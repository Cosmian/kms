use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, delete, post,
    web::{Data, Json, Path},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        kmip_operations::{Destroy, Revoke},
        kmip_types::UniqueIdentifier,
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, symmetric_key_create_request,
        },
    },
};
use cosmian_logger::trace;

use super::{
    CryptoApiError, KeyCreateRequest, KeyCreateResponse,
    algorithm::{curve_from_crv, key_bits_from_alg, symmetric_algorithm_from_alg},
};
use crate::core::KMS;

/// `POST /v1/crypto/keys` — generate or import a JWK-style key.
///
/// Dispatch logic:
/// - If key material fields (`k`, `d`) are present → **import** (not yet implemented).
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

    if body.is_import() {
        return Err(CryptoApiError::BadRequest(
            "Key import is not yet implemented. Omit key material fields (k, d) to generate a key."
                .to_owned(),
        ));
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

// ─── Shared helpers ─────────────────────────────────────────────────────────

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
