use std::sync::Arc;

use actix_web::{HttpRequest, post, web::{Data, Json}};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::Decrypt,
    kmip_types::UniqueIdentifier,
};
use cosmian_logger::trace;

use super::{
    CryptoApiError, CryptoResult, DecryptRequest, DecryptResponse as CryptoDecryptResponse,
    b64_decode, b64_encode, jose_to_kmip_params,
};
use super::encrypt::build_jwe_aad;
use crate::core::KMS;

/// `POST /v1/crypto/decrypt` — JOSE AES-GCM (dir) content decryption.
///
/// Follows RFC 7516 §5.2 step 15 for AAD reconstruction:
/// - no `aad` field: AAD = `ASCII(protected_b64)`
/// - `aad` field present: AAD = `ASCII(protected_b64 + "." + aad_b64)`
#[post("/v1/crypto/decrypt")]
pub(crate) async fn decrypt(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<DecryptRequest>,
) -> CryptoResult<CryptoDecryptResponse> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user, "POST /v1/crypto/decrypt");

    // Validate encrypted_key: for `dir` key management there must be no wrapped key.
    if let Some(ref ek) = body.encrypted_key {
        if !ek.is_empty() {
            return Err(CryptoApiError::BadRequest(
                "'encrypted_key' must be absent or empty for 'dir' key management".to_owned(),
            ));
        }
    }

    // 1. Decode the protected header (base64url → JSON)
    let header_bytes = b64_decode("protected", &body.protected)?;
    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| {
            CryptoApiError::BadRequest(format!(
                "Field 'protected' is not valid JSON after base64url decode: {e}"
            ))
        })?;

    let kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest(
                "Protected header missing required 'kid' field".to_owned(),
            )
        })?
        .to_owned();

    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest(
                "Protected header missing required 'alg' field".to_owned(),
            )
        })?
        .to_owned();

    let enc = header_json
        .get("enc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest(
                "Protected header missing required 'enc' field".to_owned(),
            )
        })?
        .to_owned();

    // 2. Validate alg/enc and map to KMIP parameters
    let kmip_params = jose_to_kmip_params(&alg, Some(&enc))?;

    // 3. Decode iv, ciphertext, tag
    let iv_bytes = b64_decode("iv", &body.iv)?;
    let ciphertext_bytes = b64_decode("ciphertext", &body.ciphertext)?;
    let tag_bytes = b64_decode("tag", &body.tag)?;

    // 4. Build AEAD AAD per RFC 7516 §5.2 step 15 — same as encryption
    let aad_bytes = build_jwe_aad(&body.protected, body.aad.as_deref())?;

    // 5. Build KMIP Decrypt request — combine ciphertext + tag as the data field
    //    The KMS server expects ciphertext without the tag; the tag is passed separately.
    let decrypt_req = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
        cryptographic_parameters: Some(kmip_params),
        data: Some(ciphertext_bytes),
        i_v_counter_nonce: Some(iv_bytes),
        authenticated_encryption_additional_data: Some(aad_bytes),
        authenticated_encryption_tag: Some(tag_bytes),
        ..Default::default()
    };

    // 6. Call KMS
    let resp = kms
        .decrypt(decrypt_req, &user)
        .await
        .map_err(CryptoApiError::from)?;

    // 7. Return plaintext
    let plaintext_bytes = resp
        .data
        .ok_or_else(|| {
            CryptoApiError::InternalError("Decrypt response missing plaintext".to_owned())
        })?;

    Ok(Json(CryptoDecryptResponse {
        kid,
        data: b64_encode(&plaintext_bytes),
    }))
}
