use base64::{Engine, engine::general_purpose};
use openssl::{
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};

use crate::{CryptoError, error::result::CryptoResult};

/// Attempt to sign a digest using an RSA private key and the provided algorithm name.
///
/// Supported algorithms:
/// - `SHA1withRSA`
/// - `SHA256withRSA`
/// - `SHA512withRSA`
/// - `SHA1withRSA/PSS`
/// - `SHA256withRSA/PSS`
/// - `SHA512withRSA/PSS`
pub fn sign_rsa_digest_with_algorithm(
    raw_private_key: &[u8],
    algorithm: &str,
    digest_b64: &str,
    _rsa_pss_salt_length: Option<i32>,
) -> CryptoResult<Vec<u8>> {
    // Validate the DER is a loadable private key (accept PKCS#8). If it fails, try PKCS#1.
    let private_key = match PKey::private_key_from_der(raw_private_key) {
        Ok(key) => key,
        Err(_) => {
            // For already uploaded Gmail CSE wrapped private keys, need to also handle PKCS#1 format.
            PKey::from_rsa(Rsa::<Private>::private_key_from_der(raw_private_key)?).map_err(|e| {
                CryptoError::ConversionError(format!(
                    "Neither PKCS#8 nor PKCS#1 could load RSA private key: {e}"
                ))
            })?
        }
    };

    let mut ctx = PkeyCtx::new(&private_key)?;
    ctx.sign_init()?;
    let (padding, md) = match algorithm {
        "SHA1withRSA" => (Padding::PKCS1, Md::sha1()),
        "SHA256withRSA" => (Padding::PKCS1, Md::sha256()),
        "SHA512withRSA" => (Padding::PKCS1, Md::sha512()),
        "SHA1withRSA/PSS" => (Padding::PKCS1_PSS, Md::sha1()),
        "SHA256withRSA/PSS" => (Padding::PKCS1_PSS, Md::sha256()),
        "SHA512withRSA/PSS" => (Padding::PKCS1_PSS, Md::sha512()),
        _ => {
            return Err(crate::error::CryptoError::Default(
                "Padding algorithm not handled.".to_owned(),
            ));
        }
    };
    ctx.set_rsa_padding(padding)?;
    ctx.set_signature_md(md)?;

    let digest = general_purpose::STANDARD
        .decode(digest_b64)
        .map_err(|e| crate::error::CryptoError::Default(e.to_string()))?;
    let allocation_size = ctx.sign(&digest, None)?;
    let mut signature = vec![0_u8; allocation_size];
    let signature_size = ctx.sign(&digest, Some(&mut *signature))?;
    if allocation_size != signature_size {
        return Err(crate::error::CryptoError::Default(
            "allocation_size MUST be equal to signature_size".to_owned(),
        ));
    }
    Ok(signature)
}
