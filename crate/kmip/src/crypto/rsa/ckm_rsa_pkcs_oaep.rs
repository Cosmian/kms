//! Implements the RSA Key Encryption Mechanism `CKM_RSA_PKCS_OAEP`
//! a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
//! <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
//!
//! This scheme is part of the NIST 800-56B rev. 2
//!  recommendation available at section 7.2.2
//! <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf>
//!
//! As part of the NIST specification, NIST approved hash functions which can be used for the OAEP scheme are listed in
//!  - NIST FIPS 180-4: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
//!  - NIST FIPS 202: SHA3-224, SHA3-256, SHA3-384, SHA3-512 (<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>)
//!
//! The scheme can be used for both encryption and key wrapping
use openssl::{
    md::MdRef,
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
};
use zeroize::Zeroizing;

#[cfg(feature = "fips")]
use super::FIPS_MIN_RSA_MODULUS_LENGTH;
#[cfg(feature = "fips")]
use crate::kmip_bail;
use crate::{error::KmipError, kmip::kmip_types::HashingAlgorithm};

/// Key Wrap using `CKM_RSA_PKCS_OAEP`
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
///
/// The maximum dek length is  k-2-2*hLen where
///  - k is the length in octets of the RSA modulus
///  - hLen is the length in octets of the hash function output
///
/// The output length is the same as the modulus length.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `key_to_wrap`: the data encryption key to wrap
pub fn ckm_rsa_pkcs_oaep_key_wrap(
    pub_key: &PKey<Public>,
    hash_fn: HashingAlgorithm,
    key_to_wrap: &[u8],
) -> Result<Vec<u8>, KmipError> {
    let (mut ctx, mut ciphertext) = init_ckm_rsa_pkcs_oaep_encryption_context(pub_key, hash_fn)?;
    ctx.encrypt_to_vec(key_to_wrap, &mut ciphertext)?;
    Ok(ciphertext)
}

/// Encryption using `CKM_RSA_PKCS_OAEP`
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
///
/// The maximum plaintext length is  k-2-2*hLen where
///  - k is the length in octets of the RSA modulus
///  - hLen is the length in octets of the hash function output
///
/// The output length is the same as the modulus length.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `plaintext`: the plaintext to encrypt
pub fn ckm_rsa_pkcs_oaep_encrypt(
    pub_key: &PKey<Public>,
    hash_fn: HashingAlgorithm,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipError> {
    let (mut ctx, mut ciphertext) = init_ckm_rsa_pkcs_oaep_encryption_context(pub_key, hash_fn)?;
    ctx.encrypt_to_vec(plaintext, &mut ciphertext)?;
    Ok(ciphertext)
}

fn init_ckm_rsa_pkcs_oaep_encryption_context(
    pub_key: &PKey<Public>,
    hash_fn: HashingAlgorithm,
) -> Result<(PkeyCtx<Public>, Vec<u8>), KmipError> {
    let rsa_pub_key = pub_key.rsa()?;
    #[cfg(feature = "fips")]
    if pub_key.bits() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_bail!(
            "CKM_RSA_OAEP encryption error: RSA key has insufficient size: expected >= {} bits \
             and got {} bits",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            pub_key.bits()
        )
    }

    // The ciphertext has the same length as the modulus.
    let encapsulation_bytes_len = usize::try_from(rsa_pub_key.size())?;
    let ciphertext = Vec::with_capacity(encapsulation_bytes_len);

    // Perform OAEP encryption.
    let mut ctx = PkeyCtx::new(pub_key)?;
    ctx.encrypt_init()?;
    ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
    ctx.set_rsa_oaep_md(hash_fn.try_into()?)?;
    Ok((ctx, ciphertext))
}

/// Key Unwrap using `CKM_RSA_PKCS_OAEP`
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
///
/// The wrapped data encryption key (dek) should be of of size k where k is the length in octets of the RSA modulus.
///
/// The data encryption key length is  k-2-2*hLen where hLen is the length in octets of the hash function output
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `wrapped_key`: the `wrapped_key` of the key to unwrap
pub fn ckm_rsa_pkcs_oaep_key_unwrap(
    priv_key: &PKey<Private>,
    hash_fn: HashingAlgorithm,
    wrapped_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let (mut ctx, mut plaintext) = init_ckm_rsa_pkcs_oaep_decryption_context(priv_key, hash_fn)?;
    ctx.decrypt_to_vec(wrapped_key, &mut plaintext)?;
    Ok(plaintext)
}

/// Decrypt using `CKM_RSA_PKCS_OAEP`
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
///
/// The ciphertext should be of size k where k is the length in octets of the RSA modulus.
///
/// The plaintext length is  k-2-2*hLen where hLen is the length in octets of the hash function output
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `ciphertext`: the ciphertext to decrypt
pub fn ckm_rsa_pkcs_oaep_key_decrypt(
    priv_key: &PKey<Private>,
    hash_fn: HashingAlgorithm,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let (mut ctx, mut plaintext) = init_ckm_rsa_pkcs_oaep_decryption_context(priv_key, hash_fn)?;
    ctx.decrypt_to_vec(ciphertext, &mut plaintext)?;
    Ok(plaintext)
}

fn init_ckm_rsa_pkcs_oaep_decryption_context(
    priv_key: &PKey<Private>,
    hash_fn: HashingAlgorithm,
) -> Result<(PkeyCtx<Private>, Zeroizing<Vec<u8>>), KmipError> {
    let rsa_priv_key = priv_key.rsa()?;
    #[cfg(feature = "fips")]
    if priv_key.bits() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_bail!(
            "CKM_RSA_OAEP decryption error: RSA key has insufficient size: expected >= {} bits \
             and got {} bits",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            priv_key.bits()
        )
    }

    // The openssl hash function
    let hash_fn: &MdRef = hash_fn.try_into()?;

    // The ciphertext has the same length as the modulus.
    let plaintext_bytes_len = usize::try_from(rsa_priv_key.size())? - 2 - 2 * hash_fn.size();
    let plaintext = Zeroizing::from(Vec::with_capacity(plaintext_bytes_len));

    // Perform OAEP encryption.
    let mut ctx = PkeyCtx::new(priv_key)?;
    ctx.decrypt_init()?;
    ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
    ctx.set_rsa_oaep_md(hash_fn)?;
    Ok((ctx, plaintext))
}

#[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use openssl::pkey::PKey;
    use zeroize::Zeroizing;

    use crate::{
        crypto::rsa::ckm_rsa_pkcs_oaep::{
            ckm_rsa_pkcs_oaep_key_unwrap, ckm_rsa_pkcs_oaep_key_wrap,
        },
        error::KmipError,
        kmip::kmip_types::HashingAlgorithm,
    };

    #[test]
    fn test_ckm_rsa_pkcs_oaep() -> Result<(), KmipError> {
        // Load FIPS provider module from OpenSSL.
        #[cfg(feature = "fips")]
        openssl::provider::Provider::load(None, "fips").unwrap();

        let priv_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
        let pub_key = PKey::public_key_from_pem(&priv_key.public_key_to_pem()?)?;

        let dek_to_wrap = Zeroizing::from(vec![0x01; 2048 / 8 - 2 - 2 * 256 / 8]);
        let wrapped_key =
            ckm_rsa_pkcs_oaep_key_wrap(&pub_key, HashingAlgorithm::SHA256, &dek_to_wrap)?;
        assert_eq!(wrapped_key.len(), 2048 / 8);
        let unwrapped_key =
            ckm_rsa_pkcs_oaep_key_unwrap(&priv_key, HashingAlgorithm::SHA256, &wrapped_key)?;
        assert_eq!(unwrapped_key.len(), 2048 / 8 - 2 - 2 * 256 / 8);
        assert_eq!(unwrapped_key, dek_to_wrap);

        Ok(())
    }
}
