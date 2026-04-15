use crate::{core::KMS, error::KmsError, result::KResult};
use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::fpe::Alphabet;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::core::retrieve_object_utils::retrieve_object_for_operation;

/// Request body for FPE tokenization encryption.
#[derive(Debug, Deserialize)]
pub struct TokenizeEncryptRequest {
    pub key_id: String,
    pub plaintext: String,
    /// The alphabet to use: a preset name or a custom character string (2 to 2^16 unique
    /// characters).
    ///
    /// Available presets: `numeric`, `hexadecimal`, `alpha_lower`, `alpha_upper`, `alpha`,
    /// `alpha_numeric`, `chinese`, `latin1sup`, `latin1sup_alphanum`, `utf`,
    /// `ascii_printable`, `base64`.
    pub alphabet: String,
    /// An optional tweak string (domain-specific context, not a secret)
    pub tweak: String,
}

/// Response body for FPE tokenization encryption.
#[derive(Debug, Serialize)]
pub struct TokenizeEncryptResponse {
    /// The FPE-encrypted string, same length and character set as the plaintext
    pub ciphertext: String,
}

/// Request body for FPE tokenization decryption.
#[derive(Debug, Deserialize)]
pub struct TokenizeDecryptRequest {
    /// KMIP Unique Identifier of the AES-256 symmetric key (32 bytes)
    pub key_id: String,
    /// The ciphertext string to decrypt
    pub ciphertext: String,
    /// The alphabet used during encryption — must be the same preset name or custom character
    /// string that was provided to the encrypt call.
    ///
    /// Available presets: `numeric`, `hexadecimal`, `alpha_lower`, `alpha_upper`, `alpha`,
    /// `alpha_numeric`, `chinese`, `latin1sup`, `latin1sup_alphanum`, `utf`,
    /// `ascii_printable`, `base64`.
    pub alphabet: String,
    /// The same tweak used during encryption
    pub tweak: String,
}

/// Response body for FPE tokenization decryption.
#[derive(Debug, Serialize)]
pub struct TokenizeDecryptResponse {
    /// The decrypted plaintext string
    pub plaintext: String,
}

/// Encrypts the given plaintext using AES-256 FF1 Format-Preserving Encryption.
/// The key referenced by `key_id` must be a 32-byte AES-256 symmetric key.
#[post("/tokenize/encrypt")]
pub(crate) async fn encrypt(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<TokenizeEncryptRequest>,
) -> KResult<Json<TokenizeEncryptResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "tokenize_encrypt");
    let _enter = span.enter();
    let user = kms.get_user(&req);

    let owm =
        retrieve_object_for_operation(&body.key_id, KmipOperation::Encrypt, &kms, &user).await?;

    let key_bytes = owm.object().key_block()?.key_bytes()?;
    if key_bytes.len() != 32 {
        return Err(KmsError::InvalidRequest(format!(
            "FPE requires a 32-byte AES-256 key, got {} bytes",
            key_bytes.len()
        )));
    }

    let body = body.into_inner();
    let alphabet = parse_alphabet(&body.alphabet)?;
    let ciphertext = alphabet
        .encrypt(&key_bytes, body.tweak.as_bytes(), &body.plaintext)
        .map_err(|e| KmsError::InvalidRequest(e.to_string()))?;

    Ok(Json(TokenizeEncryptResponse { ciphertext }))
}

/// Decrypts the given ciphertext using AES-256 FF1 Format-Preserving Encryption.
/// The key referenced by `key_id` must be a 32-byte AES-256 symmetric key.
#[post("/tokenize/decrypt")]
pub(crate) async fn decrypt(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<TokenizeDecryptRequest>,
) -> KResult<Json<TokenizeDecryptResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "tokenize_decrypt");
    let _enter = span.enter();
    let user = kms.get_user(&req);

    let owm =
        retrieve_object_for_operation(&body.key_id, KmipOperation::Decrypt, &kms, &user).await?;

    let key_bytes = owm.object().key_block()?.key_bytes()?;
    if key_bytes.len() != 32 {
        return Err(KmsError::InvalidRequest(format!(
            "FPE requires a 32-byte AES-256 key, got {} bytes",
            key_bytes.len()
        )));
    }

    let body = body.into_inner();
    let alphabet = parse_alphabet(&body.alphabet)?;
    let plaintext = alphabet
        .decrypt(&key_bytes, body.tweak.as_bytes(), &body.ciphertext)
        .map_err(|e| KmsError::InvalidRequest(e.to_string()))?;

    Ok(Json(TokenizeDecryptResponse { plaintext }))
}

fn parse_alphabet(alphabet: &str) -> KResult<Alphabet> {
    Alphabet::from_preset_or_custom(alphabet).map_err(|e| KmsError::InvalidRequest(e.to_string()))
}
