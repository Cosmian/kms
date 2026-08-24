use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_2_1,
        kmip_2_1::{
            KmipOperation,
            kmip_operations::Encrypt,
            kmip_types::{LinkType, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::{
        crypto::rsa::ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_wrap,
        openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
    },
};
use cosmian_logger::{debug, trace};
use zeroize::Zeroizing;

use super::{
    CryptoApiError, CryptoResult, EncryptRequest, EncryptResponse as CryptoEncryptResponse,
    JoseAlgorithm,
    aes_gcm::{aes_gcm_encrypt, generate_cek},
    b64_decode, b64_encode, cek_cache, jose_oaep_hashes, jose_to_kmip_params,
};
use crate::{
    core::{KMS, ObjectHandle, retrieve_object_utils::retrieve_object_for_operation},
    middlewares::UserId,
};

/// `POST /v1/crypto/encrypt` — JOSE content encryption (JWE Flattened JSON).
///
/// Supports:
/// - `alg=dir`: direct AES-GCM encryption using the symmetric key referenced by `kid`
/// - `alg=RSA-OAEP` / `alg=RSA-OAEP-256`: RSA-OAEP key wrapping of an ephemeral CEK
///
/// Follows RFC 7516 §5.1 steps 14/15 for AAD construction:
/// - no `aad` field: AAD = `ASCII(protected_b64)`
/// - `aad` field present: AAD = `ASCII(protected_b64 + "." + aad_b64)`
#[post("/encrypt")]
pub(crate) async fn encrypt(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<EncryptRequest>,
) -> CryptoResult<CryptoEncryptResponse> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(
        user = user.as_str(),
        "POST /v1/crypto/encrypt kid={} alg={}", body.kid, body.alg
    );

    let plaintext = b64_decode("data", &body.data)?;

    match body.alg {
        JoseAlgorithm::RsaOaep | JoseAlgorithm::RsaOaep256 => {
            Box::pin(encrypt_rsa_oaep(
                &kms, &user, body.kid, body.alg, body.enc, &plaintext, body.aad,
            ))
            .await
        }
        JoseAlgorithm::Dir => {
            encrypt_dir(&kms, &user, body.kid, body.enc, &plaintext, body.aad).await
        }
        _ => Err(CryptoApiError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not a key-management algorithm. Supported: dir, RSA-OAEP, \
             RSA-OAEP-256.",
            body.alg
        ))),
    }
}

/// Direct AES-GCM encryption — delegates to the KMIP Encrypt pipeline.
async fn encrypt_dir(
    kms: &KMS,
    user: &UserId,
    kid: String,
    enc: super::JoseEncAlgorithm,
    plaintext: &[u8],
    aad: Option<String>,
) -> CryptoResult<CryptoEncryptResponse> {
    let kmip_params = jose_to_kmip_params(JoseAlgorithm::Dir, Some(enc))?;

    // Deterministic JSON serialization — field order is fixed (alg, enc, kid)
    let protected_json = format!(r#"{{"alg":"dir","enc":"{enc}","kid":"{kid}"}}"#);
    let protected_b64 = b64_encode(protected_json.as_bytes());

    let aad_bytes = build_jwe_aad(&protected_b64, aad.as_deref())?;

    let encrypt_req = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(kid)),
        cryptographic_parameters: Some(kmip_params),
        data: Some(Zeroizing::new(plaintext.to_vec())),
        i_v_counter_nonce: None,
        authenticated_encryption_additional_data: Some(aad_bytes),
        ..Default::default()
    };

    let resp = kms
        .encrypt(encrypt_req, user)
        .await
        .map_err(CryptoApiError::from)?;

    let ciphertext_bytes = resp.data.ok_or_else(|| {
        CryptoApiError::InternalError("Encrypt response missing ciphertext".to_owned())
    })?;
    let iv_bytes = resp.i_v_counter_nonce.ok_or_else(|| {
        CryptoApiError::InternalError(
            "Encrypt response missing IV — server did not generate one".to_owned(),
        )
    })?;
    let tag_bytes = resp.authenticated_encryption_tag.ok_or_else(|| {
        CryptoApiError::InternalError("Encrypt response missing authentication tag".to_owned())
    })?;

    Ok(Json(CryptoEncryptResponse {
        protected: protected_b64,
        encrypted_key: String::new(),
        iv: b64_encode(&iv_bytes),
        ciphertext: b64_encode(&ciphertext_bytes),
        tag: b64_encode(&tag_bytes),
        aad,
    }))
}

/// RSA-OAEP key wrapping: generate ephemeral CEK, wrap with RSA public key, AES-GCM encrypt.
///
/// Follows RFC 7516 §5.1 (JWE Encryption):
/// 1. Generate random CEK of size matching `enc`
/// 2. Wrap CEK with RSA-OAEP using the recipient's public key
/// 3. Encrypt plaintext with AES-GCM using the CEK
/// 4. Return JWE Flattened JSON with `encrypted_key` populated
#[allow(clippy::too_many_arguments)]
async fn encrypt_rsa_oaep(
    kms: &KMS,
    user: &UserId,
    kid: String,
    alg: JoseAlgorithm,
    enc: super::JoseEncAlgorithm,
    plaintext: &[u8],
    aad: Option<String>,
) -> CryptoResult<CryptoEncryptResponse> {
    // Resolve the key — accept either private or public key UID
    let owm = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(&kid),
        KmipOperation::Encrypt,
        kms,
        user,
    ))
    .await
    .map_err(CryptoApiError::from)?;

    // Determine if this is a private key (resolve to linked public key) or already a public key
    let (public_key, private_key_uid) = match owm.object() {
        kmip_2_1::kmip_objects::Object::PrivateKey { .. } => {
            // Resolve linked public key if available; otherwise extract from private key
            let pkey = if let Some(pub_key_uid) = owm.attributes().get_link(LinkType::PublicKeyLink)
            {
                let pub_owm = Box::pin(retrieve_object_for_operation(
                    ObjectHandle::from(&pub_key_uid.to_string()),
                    KmipOperation::Encrypt,
                    kms,
                    user,
                ))
                .await
                .map_err(CryptoApiError::from)?;
                kmip_public_key_to_openssl(pub_owm.object()).map_err(|e| {
                    CryptoApiError::CryptoFailure(format!(
                        "RSA-OAEP encrypt: failed to load public key: {e}"
                    ))
                })?
            } else {
                // No linked public key (e.g. imported private key) — extract from private key
                let priv_pkey = kmip_private_key_to_openssl(owm.object()).map_err(|e| {
                    CryptoApiError::CryptoFailure(format!(
                        "RSA-OAEP encrypt: failed to load private key: {e}"
                    ))
                })?;
                let pub_der = priv_pkey.public_key_to_der().map_err(|e| {
                    CryptoApiError::CryptoFailure(format!(
                        "RSA-OAEP encrypt: failed to extract public key: {e}"
                    ))
                })?;
                openssl::pkey::PKey::public_key_from_der(&pub_der).map_err(|e| {
                    CryptoApiError::CryptoFailure(format!(
                        "RSA-OAEP encrypt: failed to parse public key DER: {e}"
                    ))
                })?
            };
            (pkey, kid.clone())
        }
        kmip_2_1::kmip_objects::Object::PublicKey { .. } => {
            // Already a public key — resolve linked private key UID for the protected header
            let priv_key_uid = owm
                .attributes()
                .get_link(LinkType::PrivateKeyLink)
                .map_or_else(|| kid.clone(), |l| l.to_string());
            let pkey = kmip_public_key_to_openssl(owm.object()).map_err(|e| {
                CryptoApiError::CryptoFailure(format!(
                    "RSA-OAEP encrypt: failed to load public key: {e}"
                ))
            })?;
            (pkey, priv_key_uid)
        }
        _ => {
            return Err(CryptoApiError::CryptoFailure(format!(
                "RSA-OAEP encrypt: key '{}' is not an RSA key pair (got {:?})",
                kid,
                owm.object().object_type()
            )));
        }
    };

    // Validate RSA key type and minimum size (2048 bits)
    if public_key.id() != openssl::pkey::Id::RSA {
        return Err(CryptoApiError::CryptoFailure(format!(
            "RSA-OAEP encrypt: key '{}' is not an RSA key (got {:?})",
            kid,
            public_key.id()
        )));
    }
    if public_key.bits() < 2048 {
        return Err(CryptoApiError::CryptoFailure(format!(
            "RSA-OAEP encrypt: RSA key too small ({} bits). Minimum: 2048 bits.",
            public_key.bits()
        )));
    }

    // Get OAEP hash algorithms for this JWA variant
    let (oaep_hash, mgf1_hash) = jose_oaep_hashes(alg)?;

    // Step 1: Generate random CEK
    let cek = generate_cek(enc)?;

    // Step 2: Wrap CEK with RSA-OAEP
    let wrapped_cek = ckm_rsa_pkcs_oaep_key_wrap(&public_key, oaep_hash, mgf1_hash, None, &cek)
        .map_err(|e| CryptoApiError::InternalError(format!("RSA-OAEP key wrap failed: {e}")))?;

    // Cache the CEK keyed by the wrapped form so that subsequent /decrypt calls
    // for this JWE token can skip the RSA-OAEP unwrap entirely.
    // Uses owm.object() as fingerprint source; if the key is rotated or updated
    // the fingerprint changes and the entry will be rejected on next peek().
    cek_cache::insert_cek(kms, &wrapped_cek, owm.object(), &cek).await;

    debug!(
        "RSA-OAEP encrypt: wrapped CEK ({} bytes) with {} ({} bit key)",
        wrapped_cek.len(),
        alg,
        public_key.bits()
    );

    // Build protected header with private key UID (so decrypt handler can use it directly)
    let protected_json = format!(r#"{{"alg":"{alg}","enc":"{enc}","kid":"{private_key_uid}"}}"#);
    let protected_b64 = b64_encode(protected_json.as_bytes());

    // RFC 7516 §5.1 step 14 — AAD construction
    let aad_bytes = build_jwe_aad(&protected_b64, aad.as_deref())?;

    // Step 3: AES-GCM encrypt plaintext with the ephemeral CEK
    let output = aes_gcm_encrypt(&cek, enc, plaintext, &aad_bytes)?;

    // CEK is Zeroizing — dropped automatically here

    Ok(Json(CryptoEncryptResponse {
        protected: protected_b64,
        encrypted_key: b64_encode(&wrapped_cek),
        iv: b64_encode(&output.iv),
        ciphertext: b64_encode(&output.ciphertext),
        tag: b64_encode(&output.tag),
        aad,
    }))
}

/// Construct the JWE AAD bytes per RFC 7516 §5.1 step 14.
///
/// - No external `aad`: `ASCII(protected_b64)`
/// - With external `aad`: `ASCII(protected_b64 + "." + aad_b64)`
pub(crate) fn build_jwe_aad(
    protected_b64: &str,
    external_aad_b64: Option<&str>,
) -> Result<Vec<u8>, CryptoApiError> {
    match external_aad_b64 {
        None => Ok(protected_b64.as_bytes().to_vec()),
        Some(aad_b64) => {
            b64_decode("aad", aad_b64)?;
            let aad_string = format!("{protected_b64}.{aad_b64}");
            Ok(aad_string.into_bytes())
        }
    }
}
