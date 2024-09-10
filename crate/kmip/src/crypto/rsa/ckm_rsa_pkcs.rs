//! Implements the RSA Key Encryption Mechanism `CKM_RSA_PKCS`
//! a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40 available at
//! <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226893
//!
//! This scheme is no longer FIPS approved for wrap/unwrap encrypt/decrypt operations.
use openssl::{
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
};
use zeroize::Zeroizing;

#[cfg(feature = "fips")]
use super::FIPS_MIN_RSA_MODULUS_LENGTH;
use crate::error::KmipError;
#[cfg(feature = "fips")]
use crate::kmip_bail;

/// Key Wrap using `CKM_RSA_PKCS`
/// a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40 available at
/// <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226893
///
/// The maximum dek length is k-11 where k is the length in octets of the RSA modulus
/// The output length is the same as the modulus length.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `dek`: the data encryption key to wrap
pub fn ckm_rsa_pkcs_key_wrap(pub_key: &PKey<Public>, dek: &[u8]) -> Result<Vec<u8>, KmipError> {
    let (mut ctx, mut ciphertext) = init_ckm_rsa_pkcs_encryption_context(pub_key)?;
    ctx.encrypt_to_vec(dek, &mut ciphertext)?;
    Ok(ciphertext)
}

/// Encryption using `CKM_RSA_PKCS`
/// a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40 available at
/// <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226893
///
/// The maximum plaintext length is  k-11 where k is the length in octets of the RSA modulus
/// The output length is the same as the modulus length.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `plaintext`: the plaintext to encrypt
pub fn ckm_rsa_pkcs_encrypt(
    pub_key: &PKey<Public>,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipError> {
    let (mut ctx, mut ciphertext) = init_ckm_rsa_pkcs_encryption_context(pub_key)?;
    ctx.encrypt_to_vec(plaintext, &mut ciphertext)?;
    Ok(ciphertext)
}

fn init_ckm_rsa_pkcs_encryption_context(
    pub_key: &PKey<Public>,
) -> Result<(PkeyCtx<Public>, Vec<u8>), KmipError> {
    let rsa_pub_key = pub_key.rsa()?;

    // The ciphertext has the same length as the modulus.
    let encapsulation_bytes_len = usize::try_from(rsa_pub_key.size())?;
    let ciphertext = Vec::with_capacity(encapsulation_bytes_len);

    // Perform OAEP encryption.
    let mut ctx = PkeyCtx::new(pub_key)?;
    ctx.encrypt_init()?;
    ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
    Ok((ctx, ciphertext))
}

/// Key Unwrap using `CKM_RSA_PKCS`
/// a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40 available at
/// <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226893
///
/// The wrapped data encryption key (dek) should be of size k where k is the length in octets of the RSA modulus.
///
/// The data encryption key length is k-11.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `dek`: the `dek` of the data encryption key to unwrap
pub fn ckm_rsa_pkcs_key_unwrap(
    priv_key: &PKey<Private>,
    dek: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let (mut ctx, mut plaintext) = init_ckm_rsa_pkcs_decryption_context(priv_key)?;
    ctx.decrypt_to_vec(dek, &mut plaintext)?;
    Ok(plaintext)
}

/// Decrypt using `CKM_RSA_PKCS`
/// a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40 available at
/// <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226893
///
/// The ciphertext should be of size k where k is the length in octets of the RSA modulus.
///
/// The plaintext length is k-11.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `ciphertext`: the ciphertext to decrypt
pub fn ckm_rsa_pkcs_decrypt(
    priv_key: &PKey<Private>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let (mut ctx, mut plaintext) = init_ckm_rsa_pkcs_decryption_context(priv_key)?;
    ctx.decrypt_to_vec(ciphertext, &mut plaintext)?;
    Ok(plaintext)
}

fn init_ckm_rsa_pkcs_decryption_context(
    priv_key: &PKey<Private>,
) -> Result<(PkeyCtx<Private>, Zeroizing<Vec<u8>>), KmipError> {
    let rsa_priv_key = priv_key.rsa()?;

    // The plaintext has length equal to the modulus length - 11 bytes.
    let plaintext_bytes_len = usize::try_from(rsa_priv_key.size())? - 11;
    let plaintext = Zeroizing::from(Vec::with_capacity(plaintext_bytes_len));

    // Perform OAEP encryption.
    let mut ctx = PkeyCtx::new(priv_key)?;
    ctx.decrypt_init()?;
    ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
    Ok((ctx, plaintext))
}

#[allow(clippy::panic_in_result_fn)]
#[cfg(test)]
mod tests {
    use openssl::pkey::PKey;
    use zeroize::Zeroizing;

    use crate::{
        crypto::rsa::ckm_rsa_pkcs::{ckm_rsa_pkcs_key_unwrap, ckm_rsa_pkcs_key_wrap},
        error::KmipError,
    };

    #[test]
    fn test_ckm_rsa_pkcs_oaep() -> Result<(), KmipError> {
        let priv_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
        let pub_key = PKey::public_key_from_pem(&priv_key.public_key_to_pem()?)?;

        let dek_to_wrap = Zeroizing::from(vec![0x01; 2048 / 8 - 2 - 2 * 256 / 8]);
        let wrapped_key = ckm_rsa_pkcs_key_wrap(&pub_key, &dek_to_wrap)?;
        assert_eq!(wrapped_key.len(), 2048 / 8);
        let unwrapped_key = ckm_rsa_pkcs_key_unwrap(&priv_key, &wrapped_key)?;
        assert_eq!(unwrapped_key.len(), 2048 / 8 - 2 - 2 * 256 / 8);
        assert_eq!(unwrapped_key, dek_to_wrap);

        Ok(())
    }
}
