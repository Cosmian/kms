use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, delete, post,
    web::{Data, Json, Path},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        extra::tagging::SYSTEM_TAG_PUBLIC_KEY,
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, PrivateKey, PublicKey, SymmetricKey},
        kmip_operations::{Destroy, Revoke},
        kmip_types::{KeyFormatType, LinkType, LinkedObjectIdentifier, UniqueIdentifier},
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, import_object_request,
            symmetric_key_create_request,
        },
    },
};
use cosmian_logger::trace;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
};
use zeroize::Zeroizing;

use super::{
    CryptoApiError, KeyCreateRequest, KeyCreateResponse,
    algorithm::{
        curve_from_crv, key_bits_from_alg, symmetric_algorithm_from_alg, usage_mask_from_alg,
    },
    b64_decode,
};
use crate::core::KMS;

/// `POST /v1/crypto/keys` — generate or import a JWK-style key.
///
/// Dispatch logic:
/// - If key material fields (`k`, `d`) are present → **import** the key into the KMS.
/// - Otherwise → **generate** a new key based on `kty`/`alg`/`crv`/`bits`.
#[post("/keys")]
pub(crate) async fn create_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<KeyCreateRequest>,
) -> Result<Json<KeyCreateResponse>, CryptoApiError> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user, "POST /v1/crypto/keys kty={}", body.kty);

    // Validate algorithm ↔ key type consistency to prevent key confusion attacks.
    if let Some(alg) = body.alg.as_deref() {
        validate_alg_kty_consistency(alg, &body.kty)?;
    }

    if body.is_import() {
        return match body.kty.as_str() {
            "oct" => import_symmetric_key(&kms, &user, &body).await.map(Json),
            "EC" => import_ec_key(&kms, &user, &body).await.map(Json),
            "RSA" => import_rsa_key(&kms, &user, &body).await.map(Json),
            #[cfg(feature = "non-fips")]
            "OKP" => import_okp_key(&kms, &user, &body).await.map(Json),
            other => Err(CryptoApiError::BadRequest(format!(
                "Unsupported key type '{other}' for import."
            ))),
        };
    }

    let alg_str = body.alg.as_deref().unwrap_or("");

    match body.kty.as_str() {
        "oct" => generate_symmetric_key(&kms, &user, &body).await.map(Json),
        "EC" => generate_ec_key_pair(&kms, &user, &body).await.map(Json),
        "RSA" => generate_rsa_key_pair(&kms, &user, &body).await.map(Json),
        #[cfg(feature = "non-fips")]
        "OKP" => generate_okp_key_pair(&kms, &user, &body).await.map(Json),
        other => Err(CryptoApiError::BadRequest(format!(
            "Unsupported key type '{other}'. Supported: oct, EC, RSA, OKP (non-FIPS). \
             alg={alg_str}"
        ))),
    }
}

/// `DELETE /v1/crypto/keys/{kid}` — destroy a key by its KMS unique identifier.
#[delete("/keys/{kid}")]
pub(crate) async fn delete_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    kid: Path<String>,
) -> Result<HttpResponse, CryptoApiError> {
    let user = kms.get_user(&req);
    let kid = kid.into_inner();

    trace!(user = user, "DELETE /v1/crypto/keys/{kid}");

    // Revoke the key first (KMIP lifecycle requires Deactivated state before Destroy)
    let revoke_req = Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::CessationOfOperation,
            revocation_message: None,
        },
        compromise_occurrence_date: None,
        cascade: true,
    };
    // Ignore revoke errors (key may already be deactivated or pre-active)
    drop(kms.revoke(revoke_req, &user).await);

    let destroy_req = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(kid)),
        remove: true,
        cascade: true,
        ..Default::default()
    };

    kms.destroy(destroy_req, &user)
        .await
        .map_err(CryptoApiError::from)?;

    Ok(HttpResponse::NoContent().finish())
}

// ─── Internal: symmetric key generation ─────────────────────────────────────

async fn generate_symmetric_key(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    let alg = body.alg.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'alg' is required for symmetric key generation (e.g. HS256, A256GCM)."
                .to_owned(),
        )
    })?;

    let key_bits = key_bits_from_alg(alg).ok_or_else(|| {
        CryptoApiError::BadRequest(format!(
            "Cannot infer key size from algorithm '{alg}'. \
             Supported symmetric algs: A128GCM, A192GCM, A256GCM, HS256, HS384, HS512."
        ))
    })?;

    let crypto_alg = symmetric_algorithm_from_alg(alg)?;

    let create_req = symmetric_key_create_request(
        kms.vendor_id(),
        None, // auto-generate UID
        key_bits,
        crypto_alg,
        Vec::<&str>::new(), // no tags
        false,              // not sensitive
        None,               // no wrapping key
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .create(create_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.unique_identifier.to_string();

    let key_ops = key_ops_from_alg(alg);

    Ok(KeyCreateResponse {
        kid,
        kid_public: None,
        kty: "oct".to_owned(),
        alg: Some(alg.to_owned()),
        crv: None,
        key_ops,
        x: None,
        y: None,
        n: None,
        e: None,
    })
}

// ─── Internal: EC key pair generation ───────────────────────────────────────

async fn generate_ec_key_pair(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    let crv = body.crv.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'crv' is required for EC key generation (e.g. P-256, P-384, P-521).".to_owned(),
        )
    })?;

    let recommended_curve = curve_from_crv(crv)?;
    let alg = body.alg.as_deref();

    let create_req = create_ec_key_pair_request(
        kms.vendor_id(),
        None,               // auto-generate UID
        Vec::<&str>::new(), // no tags
        recommended_curve,
        false, // not sensitive
        None,  // no wrapping key
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .create_key_pair(create_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.private_key_unique_identifier.to_string();
    let kid_public = resp.public_key_unique_identifier.to_string();

    let key_ops = alg.map_or_else(
        || vec!["sign".to_owned(), "verify".to_owned()],
        key_ops_from_alg,
    );

    Ok(KeyCreateResponse {
        kid,
        kid_public: Some(kid_public),
        kty: "EC".to_owned(),
        alg: alg.map(ToOwned::to_owned),
        crv: Some(crv.to_owned()),
        key_ops,
        x: None, // TODO: retrieve from public key material in a follow-up
        y: None,
        n: None,
        e: None,
    })
}

// ─── Internal: RSA key pair generation ──────────────────────────────────────

async fn generate_rsa_key_pair(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    let bits = body.bits.unwrap_or(2048);
    let alg = body.alg.as_deref();

    if bits < 2048 {
        return Err(CryptoApiError::BadRequest(format!(
            "RSA key size must be at least 2048 bits (got {bits})."
        )));
    }

    let create_req = create_rsa_key_pair_request(
        kms.vendor_id(),
        None,               // auto-generate UID
        Vec::<&str>::new(), // no tags
        bits,
        false, // not sensitive
        None,  // no wrapping key
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .create_key_pair(create_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.private_key_unique_identifier.to_string();
    let kid_public = resp.public_key_unique_identifier.to_string();

    let key_ops = alg.map_or_else(
        || vec!["sign".to_owned(), "verify".to_owned()],
        key_ops_from_alg,
    );

    Ok(KeyCreateResponse {
        kid,
        kid_public: Some(kid_public),
        kty: "RSA".to_owned(),
        alg: alg.map(ToOwned::to_owned),
        crv: None,
        key_ops,
        x: None,
        y: None,
        n: None, // TODO: retrieve from public key material in a follow-up
        e: None,
    })
}

// ─── Internal: OKP (Ed25519) key pair generation (non-FIPS) ─────────────────

#[cfg(feature = "non-fips")]
async fn generate_okp_key_pair(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    let crv = body.crv.as_deref().unwrap_or("Ed25519");
    let alg = body.alg.as_deref();

    let recommended_curve = curve_from_crv(crv)?;

    let create_req = create_ec_key_pair_request(
        kms.vendor_id(),
        None,
        Vec::<&str>::new(),
        recommended_curve,
        false,
        None,
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .create_key_pair(create_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.private_key_unique_identifier.to_string();
    let kid_public = resp.public_key_unique_identifier.to_string();

    let key_ops = alg.map_or_else(
        || vec!["sign".to_owned(), "verify".to_owned()],
        key_ops_from_alg,
    );

    Ok(KeyCreateResponse {
        kid,
        kid_public: Some(kid_public),
        kty: "OKP".to_owned(),
        alg: alg.map(ToOwned::to_owned),
        crv: Some(crv.to_owned()),
        key_ops,
        x: None, // TODO: retrieve from public key material
        y: None,
        n: None,
        e: None,
    })
}

// ─── Internal: symmetric key import ─────────────────────────────────────────

async fn import_symmetric_key(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    let k_str = body.k.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'k' (base64url-encoded key material) is required for symmetric key import."
                .to_owned(),
        )
    })?;

    let alg = body.alg.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'alg' is required for symmetric key import (e.g. HS256, A256GCM).".to_owned(),
        )
    })?;

    let key_bytes = b64_decode("k", k_str)?;

    // Validate key length against algorithm expectation.
    // For HMAC (HS*), RFC 7518 §3.2 specifies a minimum key size; for AES, exact match required.
    let expected_bits = key_bits_from_alg(alg).ok_or_else(|| {
        CryptoApiError::BadRequest(format!(
            "Cannot infer expected key size from algorithm '{alg}'."
        ))
    })?;
    let actual_bits = key_bytes.len() * 8;
    let is_hmac = alg.starts_with("HS");

    if is_hmac {
        if actual_bits < expected_bits {
            return Err(CryptoApiError::BadRequest(format!(
                "Key length too short: algorithm '{alg}' requires at least {expected_bits} bits, \
                 but 'k' contains {actual_bits} bits."
            )));
        }
        // Cap HMAC keys at 4096 bytes (32768 bits) to prevent memory-based DoS.
        // RFC 7518 §3.2 recommends keys equal to the hash output size; anything
        // beyond 4 KiB is unreasonable and likely an attack vector.
        if actual_bits > 32_768 {
            return Err(CryptoApiError::BadRequest(format!(
                "HMAC key too large: maximum 32768 bits allowed, \
                 but 'k' contains {actual_bits} bits."
            )));
        }
    } else if actual_bits != expected_bits {
        return Err(CryptoApiError::BadRequest(format!(
            "Key length mismatch: algorithm '{alg}' requires {expected_bits} bits, \
             but 'k' contains {actual_bits} bits."
        )));
    }

    let crypto_alg = symmetric_algorithm_from_alg(alg)?;
    let key_len_bits =
        i32::try_from(actual_bits).map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    // Set usage mask based on algorithm class (HMAC → MAC ops, AES → Encrypt/Decrypt)
    let usage_mask = usage_mask_from_alg(alg);

    let attributes = Attributes {
        cryptographic_algorithm: Some(crypto_alg),
        cryptographic_length: Some(key_len_bits),
        cryptographic_usage_mask: Some(usage_mask),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        ..Attributes::default()
    };

    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::from(key_bytes),
                },
                attributes: Some(attributes.clone()),
            }),
            cryptographic_algorithm: Some(crypto_alg),
            cryptographic_length: Some(key_len_bits),
            key_wrapping_data: None,
        },
    });

    let import_req = import_object_request(
        kms.vendor_id(),
        None,
        object,
        Some(attributes),
        false,
        false,
        Vec::<&str>::new(),
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .import(import_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.unique_identifier.to_string();
    let key_ops = key_ops_from_alg(alg);

    Ok(KeyCreateResponse {
        kid,
        kid_public: None,
        kty: "oct".to_owned(),
        alg: Some(alg.to_owned()),
        crv: None,
        key_ops,
        x: None,
        y: None,
        n: None,
        e: None,
    })
}

// ─── Internal: derive and import the public key for an imported private key ──

/// After importing a private key, derive its public key (SPKI DER), import it
/// as a separate `PublicKey` object with UID `{private_key_uid}_pk`, and set up
/// bidirectional links (`PublicKeyLink` on the private key, `PrivateKeyLink` on
/// the public key).
async fn import_public_key_for_private(
    kms: &Arc<KMS>,
    user: &str,
    pkey: &PKey<openssl::pkey::Private>,
    private_key_uid: &str,
    usage_mask: CryptographicUsageMask,
) -> Result<String, CryptoApiError> {
    let pub_uid = format!("{private_key_uid}{SYSTEM_TAG_PUBLIC_KEY}");

    let spki_der = pkey
        .public_key_to_der()
        .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    // Build Attributes for the public key with PrivateKeyLink
    let mut pub_attributes = Attributes {
        cryptographic_usage_mask: Some(usage_mask),
        key_format_type: Some(KeyFormatType::PKCS8),
        ..Attributes::default()
    };
    pub_attributes.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(private_key_uid.to_owned()),
    );

    let pub_object = Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS8,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(spki_der)),
                attributes: Some(pub_attributes.clone()),
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let import_req = import_object_request(
        kms.vendor_id(),
        Some(pub_uid.clone()),
        pub_object,
        Some(pub_attributes),
        false,
        false,
        Vec::<&str>::new(),
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    kms.import(import_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    Ok(pub_uid)
}

// ─── Internal: EC key import ────────────────────────────────────────────────

async fn import_ec_key(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    let d_str = body.d.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'd' (base64url-encoded private key scalar) is required for EC key import."
                .to_owned(),
        )
    })?;

    let crv = body.crv.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'crv' is required for EC key import (e.g. P-256, P-384, P-521).".to_owned(),
        )
    })?;

    // Validate the curve is also supported by the KMIP layer
    let _recommended_curve = curve_from_crv(crv)?;
    let nid = nid_from_crv(crv)?;
    let alg = body.alg.as_deref();

    let d_bytes = b64_decode("d", d_str)?;

    // Reconstruct EC private key via OpenSSL
    let group =
        EcGroup::from_curve_name(nid).map_err(|e| CryptoApiError::InternalError(e.to_string()))?;
    let d_bn =
        BigNum::from_slice(&d_bytes).map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    // Compute public point = d * G
    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;
    let mut public_point =
        EcPoint::new(&group).map_err(|e| CryptoApiError::InternalError(e.to_string()))?;
    public_point
        .mul_generator2(&group, &d_bn, &mut ctx)
        .map_err(|e| {
            CryptoApiError::BadRequest(format!(
                "Invalid EC private key scalar for curve '{crv}': {e}"
            ))
        })?;

    // If x,y coordinates are provided, validate they match the computed public point.
    // Reject on mismatch to prevent key confusion attacks (the KMS always derives
    // the public point from d, so inconsistent x,y indicates a malformed JWK).
    if body.x.is_some() || body.y.is_some() {
        let computed_uncompressed = public_point
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;
        // Uncompressed form: 0x04 || x || y, each coordinate is field_len bytes
        let field_len = (computed_uncompressed.len().saturating_sub(1)) / 2;
        let computed_x = computed_uncompressed.get(1..=field_len).ok_or_else(|| {
            CryptoApiError::InternalError(
                "EC public point encoding too short for x coordinate".to_owned(),
            )
        })?;
        let computed_y = computed_uncompressed.get(1 + field_len..).ok_or_else(|| {
            CryptoApiError::InternalError(
                "EC public point encoding too short for y coordinate".to_owned(),
            )
        })?;

        if let Some(x_str) = body.x.as_deref() {
            let x_bytes = b64_decode("x", x_str)?;
            if x_bytes != computed_x {
                return Err(CryptoApiError::BadRequest(
                    "EC key import: provided 'x' coordinate does not match public point \
                     derived from 'd'. Remove x/y or correct the key material."
                        .to_owned(),
                ));
            }
        }
        if let Some(y_str) = body.y.as_deref() {
            let y_bytes = b64_decode("y", y_str)?;
            if y_bytes != computed_y {
                return Err(CryptoApiError::BadRequest(
                    "EC key import: provided 'y' coordinate does not match public point \
                     derived from 'd'. Remove x/y or correct the key material."
                        .to_owned(),
                ));
            }
        }
    }

    let ec_key = EcKey::from_private_components(&group, &d_bn, &public_point).map_err(|e| {
        CryptoApiError::BadRequest(format!("Invalid EC key components for curve '{crv}': {e}"))
    })?;
    ec_key.check_key().map_err(|e| {
        CryptoApiError::BadRequest(format!("EC key validation failed for curve '{crv}': {e}"))
    })?;

    let pkey =
        PKey::from_ec_key(ec_key).map_err(|e| CryptoApiError::InternalError(e.to_string()))?;
    let pkcs8_der = pkey
        .private_key_to_der()
        .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    // Set usage mask and key_format_type based on the intended JOSE algorithm
    let ec_usage_mask = alg.map_or(
        CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
        usage_mask_from_alg,
    );
    let ec_attributes = Attributes {
        cryptographic_usage_mask: Some(ec_usage_mask),
        key_format_type: Some(KeyFormatType::PKCS8),
        ..Attributes::default()
    };

    let object = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS8,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(pkcs8_der)),
                attributes: Some(ec_attributes.clone()),
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let import_req = import_object_request(
        kms.vendor_id(),
        None,
        object,
        Some(ec_attributes),
        false,
        false,
        Vec::<&str>::new(),
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .import(import_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.unique_identifier.to_string();

    // Derive and import the public key alongside the private key
    let pub_usage = CryptographicUsageMask::Verify;
    let kid_public = import_public_key_for_private(kms, user, &pkey, &kid, pub_usage).await?;

    let key_ops = alg.map_or_else(
        || vec!["sign".to_owned(), "verify".to_owned()],
        key_ops_from_alg,
    );

    Ok(KeyCreateResponse {
        kid,
        kid_public: Some(kid_public),
        kty: "EC".to_owned(),
        alg: alg.map(ToOwned::to_owned),
        crv: Some(crv.to_owned()),
        key_ops,
        x: None,
        y: None,
        n: None,
        e: None,
    })
}

// ─── Internal: RSA key import ───────────────────────────────────────────────

async fn import_rsa_key(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    // All RSA CRT components are required by OpenSSL
    let n_str = body.n.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest("Field 'n' (modulus) is required for RSA key import.".to_owned())
    })?;
    let e_str = body.e.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'e' (public exponent) is required for RSA key import.".to_owned(),
        )
    })?;
    let d_str = body.d.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'd' (private exponent) is required for RSA key import.".to_owned(),
        )
    })?;
    let p_str = body.p.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'p' (first prime) is required for RSA key import.".to_owned(),
        )
    })?;
    let q_str = body.q.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'q' (second prime) is required for RSA key import.".to_owned(),
        )
    })?;
    let dp_str = body.dp.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'dp' (d mod p-1) is required for RSA key import.".to_owned(),
        )
    })?;
    let dq_str = body.dq.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'dq' (d mod q-1) is required for RSA key import.".to_owned(),
        )
    })?;
    let qi_str = body.qi.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'qi' (CRT coefficient) is required for RSA key import.".to_owned(),
        )
    })?;

    let alg = body.alg.as_deref();

    // Decode all components
    let n_bn = BigNum::from_slice(&b64_decode("n", n_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'n': {e}")))?;
    let e_bn = BigNum::from_slice(&b64_decode("e", e_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'e': {e}")))?;
    let d_bn = BigNum::from_slice(&b64_decode("d", d_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'd': {e}")))?;
    let p_bn = BigNum::from_slice(&b64_decode("p", p_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'p': {e}")))?;
    let q_bn = BigNum::from_slice(&b64_decode("q", q_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'q': {e}")))?;
    let dp_bn = BigNum::from_slice(&b64_decode("dp", dp_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'dp': {e}")))?;
    let dq_bn = BigNum::from_slice(&b64_decode("dq", dq_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'dq': {e}")))?;
    let qi_bn = BigNum::from_slice(&b64_decode("qi", qi_str)?)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid 'qi': {e}")))?;

    // Validate minimum key size
    let key_bits = n_bn.num_bits();
    if key_bits < 2048 {
        return Err(CryptoApiError::BadRequest(format!(
            "RSA key size must be at least 2048 bits (got {key_bits})."
        )));
    }

    // Validate public exponent per FIPS 186-4 §B.3.1: e must be odd and ≥ 3.
    // Common values: 3, 17, 65537. Values of 0, 1, or 2 are cryptographically broken.
    if e_bn.num_bits() < 2 {
        return Err(CryptoApiError::BadRequest(
            "RSA public exponent 'e' must be at least 3 (got value < 3).".to_owned(),
        ));
    }
    if !e_bn.is_odd() {
        return Err(CryptoApiError::BadRequest(
            "RSA public exponent 'e' must be odd.".to_owned(),
        ));
    }

    let rsa_key =
        Rsa::from_private_components(n_bn, e_bn, d_bn, p_bn, q_bn, dp_bn, dq_bn, qi_bn)
            .map_err(|e| CryptoApiError::BadRequest(format!("Invalid RSA key components: {e}")))?;

    let pkey = PKey::from_rsa(rsa_key).map_err(|e| CryptoApiError::InternalError(e.to_string()))?;
    let pkcs8_der = pkey
        .private_key_to_der()
        .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    // Set usage mask and key_format_type based on the intended JOSE algorithm
    let rsa_usage_mask = alg.map_or(
        CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
        usage_mask_from_alg,
    );
    let rsa_attributes = Attributes {
        cryptographic_usage_mask: Some(rsa_usage_mask),
        key_format_type: Some(KeyFormatType::PKCS8),
        ..Attributes::default()
    };

    let object = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS8,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(pkcs8_der)),
                attributes: Some(rsa_attributes.clone()),
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let import_req = import_object_request(
        kms.vendor_id(),
        None,
        object,
        Some(rsa_attributes),
        false,
        false,
        Vec::<&str>::new(),
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .import(import_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.unique_identifier.to_string();

    // Derive and import the public key alongside the private key
    let pub_usage = CryptographicUsageMask::Verify;
    let kid_public = import_public_key_for_private(kms, user, &pkey, &kid, pub_usage).await?;

    let key_ops = alg.map_or_else(
        || vec!["sign".to_owned(), "verify".to_owned()],
        key_ops_from_alg,
    );

    Ok(KeyCreateResponse {
        kid,
        kid_public: Some(kid_public),
        kty: "RSA".to_owned(),
        alg: alg.map(ToOwned::to_owned),
        crv: None,
        key_ops,
        x: None,
        y: None,
        n: None,
        e: None,
    })
}

// ─── Internal: OKP (Ed25519) key import (non-FIPS) ──────────────────────────

#[cfg(feature = "non-fips")]
async fn import_okp_key(
    kms: &Arc<KMS>,
    user: &str,
    body: &KeyCreateRequest,
) -> Result<KeyCreateResponse, CryptoApiError> {
    let d_str = body.d.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Field 'd' (base64url-encoded private key) is required for OKP key import.".to_owned(),
        )
    })?;

    let crv = body.crv.as_deref().unwrap_or("Ed25519");
    let alg = body.alg.as_deref();

    if crv != "Ed25519" {
        return Err(CryptoApiError::BadRequest(format!(
            "Unsupported OKP curve '{crv}' for import. Supported: Ed25519."
        )));
    }

    let d_bytes = b64_decode("d", d_str)?;
    if d_bytes.len() != 32 {
        return Err(CryptoApiError::BadRequest(format!(
            "Ed25519 private key must be exactly 32 bytes, got {}.",
            d_bytes.len()
        )));
    }

    let pkey = PKey::private_key_from_raw_bytes(&d_bytes, openssl::pkey::Id::ED25519)
        .map_err(|e| CryptoApiError::BadRequest(format!("Invalid Ed25519 private key: {e}")))?;
    let pkcs8_der = pkey
        .private_key_to_der()
        .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    // Set usage mask and key_format_type based on the intended JOSE algorithm
    let okp_usage_mask = alg.map_or(
        CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
        usage_mask_from_alg,
    );
    let okp_attributes = Attributes {
        cryptographic_usage_mask: Some(okp_usage_mask),
        key_format_type: Some(KeyFormatType::PKCS8),
        ..Attributes::default()
    };

    let object = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS8,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(pkcs8_der)),
                attributes: Some(okp_attributes.clone()),
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let import_req = import_object_request(
        kms.vendor_id(),
        None,
        object,
        Some(okp_attributes),
        false,
        false,
        Vec::<&str>::new(),
    )
    .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;

    let resp = kms
        .import(import_req, user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let kid = resp.unique_identifier.to_string();

    // Derive and import the public key alongside the private key
    let pub_usage = CryptographicUsageMask::Verify;
    let kid_public = import_public_key_for_private(kms, user, &pkey, &kid, pub_usage).await?;

    let key_ops = alg.map_or_else(
        || vec!["sign".to_owned(), "verify".to_owned()],
        key_ops_from_alg,
    );

    Ok(KeyCreateResponse {
        kid,
        kid_public: Some(kid_public),
        kty: "OKP".to_owned(),
        alg: alg.map(ToOwned::to_owned),
        crv: Some(crv.to_owned()),
        key_ops,
        x: None,
        y: None,
        n: None,
        e: None,
    })
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

/// Map a JOSE `crv` string to an OpenSSL NID.
fn nid_from_crv(crv: &str) -> Result<Nid, CryptoApiError> {
    match crv {
        "P-256" => Ok(Nid::X9_62_PRIME256V1),
        "P-384" => Ok(Nid::SECP384R1),
        "P-521" => Ok(Nid::SECP521R1),
        other => Err(CryptoApiError::BadRequest(format!(
            "Unsupported curve '{other}' for import. Supported: P-256, P-384, P-521."
        ))),
    }
}

/// Derive `key_ops` strings from a JOSE algorithm.
fn key_ops_from_alg(alg: &str) -> Vec<String> {
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "ES512"
        | "EdDSA" | "MLDSA44" | "HS256" | "HS384" | "HS512" => {
            vec!["sign".to_owned(), "verify".to_owned()]
        }
        // Encryption algorithms
        _ => vec!["encrypt".to_owned(), "decrypt".to_owned()],
    }
}

/// Validate that the JOSE `alg` is compatible with the declared `kty`.
///
/// Rejects mismatches like `kty=RSA` + `alg=ES256` which could lead to
/// algorithm confusion or key confusion attacks.
fn validate_alg_kty_consistency(alg: &str, kty: &str) -> Result<(), CryptoApiError> {
    let valid = match kty {
        "oct" => matches!(
            alg,
            "HS256" | "HS384" | "HS512" | "A128GCM" | "A192GCM" | "A256GCM" | "dir"
        ),
        "EC" => matches!(alg, "ES256" | "ES384" | "ES512"),
        "RSA" => matches!(
            alg,
            "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "RSA-OAEP" | "RSA-OAEP-256"
        ),
        "OKP" => matches!(alg, "EdDSA" | "MLDSA44"),
        _ => false, // Unknown kty will be rejected downstream
    };
    if !valid {
        return Err(CryptoApiError::BadRequest(format!(
            "Algorithm '{alg}' is not compatible with key type '{kty}'."
        )));
    }
    Ok(())
}
