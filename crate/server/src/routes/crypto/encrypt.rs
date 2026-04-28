use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::Encrypt, kmip_types::UniqueIdentifier,
};
use cosmian_logger::trace;
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    CryptoApiError, CryptoResult, EncryptRequest, EncryptResponse as CryptoEncryptResponse,
    b64_decode, b64_encode, jose_to_kmip_params,
};
use crate::core::KMS;

/// `POST /v1/crypto/encrypt` — JOSE AES-GCM (dir) content encryption.
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

    trace!(user = user, "POST /v1/crypto/encrypt kid={}", body.kid);

    let kmip_params = jose_to_kmip_params(&body.alg, Some(&body.enc))?;
    let plaintext = b64_decode("data", &body.data)?;

    let protected_header = json!({
        "alg": body.alg,
        "enc": body.enc,
        "kid": body.kid,
    });
    let protected_json = protected_header.to_string();
    let protected_b64 = b64_encode(protected_json.as_bytes());

    // RFC 7516 §5.1 step 14
    let aad_bytes = build_jwe_aad(&protected_b64, body.aad.as_deref())?;

    // no nonce — server generates one
    let encrypt_req = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(body.kid.clone())),
        cryptographic_parameters: Some(kmip_params),
        data: Some(Zeroizing::new(plaintext)),
        i_v_counter_nonce: None, // server generates IV
        authenticated_encryption_additional_data: Some(aad_bytes),
        ..Default::default()
    };

    let resp = kms
        .encrypt(encrypt_req, &user)
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

    // For 'dir': no key material is transmitted — encrypted_key is always empty.
    // Future key-wrapping algs (RSA-OAEP, ECDH-ES) must populate encrypted_key here;
    // add a new branch rather than inheriting String::new() silently.
    debug_assert_eq!(
        body.alg, "dir",
        "encrypted_key must be populated for non-dir key management algs"
    );
    Ok(Json(CryptoEncryptResponse {
        protected: protected_b64,
        encrypted_key: String::new(),
        iv: b64_encode(&iv_bytes),
        ciphertext: b64_encode(&ciphertext_bytes),
        tag: b64_encode(&tag_bytes),
        aad: body.aad,
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
