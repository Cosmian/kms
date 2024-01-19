use std::ops::Deref;

///! Implements the RSA Key Encryption Mechanism CKM_RSA_PKCS_OAEP
///! a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
///! http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226895
///!
///! This scheme is part of the NIST 800-56B rev. 2 recommendation available at section 7.2.2  
///! https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf
///!
///! As part of the NIST specification, NIST approved hash functions which can be used for the OAEP scheme are listed in
///!  - NIST FIPS 180-4: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///   - NIST FIPS 202: SHA3-224, SHA3-256, SHA3-384, SHA3-512 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
///!
///! The scheme can be used for both encryption and key wrapping
use cloudproof::reexport::crypto_core::reexport::zeroize::Zeroizing;
use openssl::{
    md::{Md, MdRef},
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
};

use crate::error::KmipUtilsError;
#[cfg(feature = "fips")]
use crate::kmip_utils_bail;

/// Approved NIST hash functions for RSA OAEP as specified in NIST 800-56B rev. 2
pub enum RsaOaepHash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl RsaOaepHash {
    fn to_md_ref(&self) -> &MdRef {
        match self {
            RsaOaepHash::Sha1 => Md::sha1(),
            RsaOaepHash::Sha224 => Md::sha224(),
            RsaOaepHash::Sha256 => Md::sha256(),
            RsaOaepHash::Sha384 => Md::sha384(),
            RsaOaepHash::Sha512 => Md::sha512(),
            RsaOaepHash::Sha3_224 => Md::sha3_224(),
            RsaOaepHash::Sha3_256 => Md::sha3_256(),
            RsaOaepHash::Sha3_384 => Md::sha3_384(),
            RsaOaepHash::Sha3_512 => Md::sha3_512(),
        }
    }
}

#[cfg(feature = "fips")]
pub const FIPS_MIN_RSA_MODULUS_LENGTH: u32 = 2048;

/// Key Wrap using CKM_RSA_PKCS_OAEP
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226895
///
/// The maximum dek length is  k-2-2*hLen where
///  - k is the length in octets of the RSA modulus
///  - hLen is the length in octets of the hash function output for EME-OAEP
/// The output length is the same as the modulus length.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `dek`: the data encryption key to wrap
pub fn ckm_rsa_pkcs_oaep_key_wrap(
    pub_key: &PKey<Public>,
    hash_fn: RsaOaepHash,
    dek: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, KmipUtilsError> {
    let (mut ctx, mut ciphertext) = init_ckm_rsa_pkcs_oaep_encryption_context(pub_key, hash_fn)?;
    ctx.encrypt_to_vec(dek.deref(), &mut ciphertext)?;
    Ok(ciphertext)
}

/// Encryption using CKM_RSA_PKCS_OAEP
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226895
///
/// The maximum plaintext length is  k-2-2*hLen where
///  - k is the length in octets of the RSA modulus
///  - hLen is the length in octets of the hash function output for EME-OAEP
/// The output length is the same as the modulus length.
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `plaintext`: the plaintext to encrypt
pub fn ckm_rsa_pkcs_oaep_encrypt(
    pub_key: &PKey<Public>,
    hash_fn: RsaOaepHash,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    let (mut ctx, mut ciphertext) = init_ckm_rsa_pkcs_oaep_encryption_context(pub_key, hash_fn)?;
    ctx.encrypt_to_vec(plaintext, &mut ciphertext)?;
    Ok(ciphertext)
}

fn init_ckm_rsa_pkcs_oaep_encryption_context(
    pub_key: &PKey<Public>,
    hash_fn: RsaOaepHash,
) -> Result<(PkeyCtx<Public>, Vec<u8>), KmipUtilsError> {
    let rsa_pub_key = pub_key.rsa()?;
    #[cfg(feature = "fips")]
    if rsa_pub_key.size() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_utils_bail!(
            "CKM_RSA_OAEP encryption error: RSA key has insufficient size: expected >= {} bytes \
             and got {} bytes",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            pub_key.bits()
        )
    }

    // The ciphertext has the same length as the modulus.
    let encapsulation_bytes_len = rsa_pub_key.size() as usize;
    let ciphertext = Vec::with_capacity(encapsulation_bytes_len);

    // Perform OAEP encryption.
    let mut ctx = PkeyCtx::new(&pub_key)?;
    ctx.set_rsa_oaep_md(hash_fn.to_md_ref())?;
    Ok((ctx, ciphertext))
}

/// Key Unwrap using CKM_RSA_PKCS_OAEP
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226895
///
/// The wrapped data encryption key (dek) should be of of size k where k is the length in octets of the RSA modulus.
///
/// The data encryption key length is  k-2-2*hLen where hLen is the length in octets of the hash function output for EME-OAEP
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `wrapped_key`: the wrapped_key of the key to unwrap
pub fn ckm_rsa_pkcs_oaep_key_unwrap(
    priv_key: &PKey<Private>,
    hash_fn: RsaOaepHash,
    wrapped_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    let (mut ctx, mut plaintext) = init_ckm_rsa_pkcs_oaep_decryption_context(priv_key, hash_fn)?;
    ctx.decrypt_to_vec(wrapped_key, &mut plaintext)?;
    Ok(Zeroizing::from(plaintext))
}

/// Decrypt using CKM_RSA_PKCS_OAEP
/// a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226895
///
/// The ciphertext should be of size k where k is the length in octets of the RSA modulus.
///
/// The plaintext length is  k-2-2*hLen where hLen is the length in octets of the hash function output for EME-OAEP
///
/// Arguments:
/// - `pubkey`: the public key used to wrap the key
/// - `hash_fn`: the hash function to use for OAEP
/// - `ciphertext`: the ciphertext to decrypt
pub fn ckm_rsa_pkcs_oaep_key_decrypt(
    priv_key: &PKey<Private>,
    hash_fn: RsaOaepHash,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    let (mut ctx, mut plaintext) = init_ckm_rsa_pkcs_oaep_decryption_context(priv_key, hash_fn)?;
    ctx.decrypt_to_vec(ciphertext, &mut plaintext)?;
    Ok(plaintext)
}

fn init_ckm_rsa_pkcs_oaep_decryption_context(
    priv_key: &PKey<Private>,
    hash_fn: RsaOaepHash,
) -> Result<(PkeyCtx<Private>, Vec<u8>), KmipUtilsError> {
    let rsa_priv_key = priv_key.rsa()?;
    #[cfg(feature = "fips")]
    if rsa_priv_key.size() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_utils_bail!(
            "CKM_RSA_OAEP encryption error: RSA key has insufficient size: expected >= {} bytes \
             and got {} bytes",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            priv_key.bits()
        )
    }

    // The openssl hash function
    let hash_fn = hash_fn.to_md_ref();

    // The ciphertext has the same length as the modulus.
    let plaintext_bytes_len = rsa_priv_key.size() as usize - 2 - 2 * hash_fn.size();
    let plaintext = Vec::with_capacity(plaintext_bytes_len);

    // Perform OAEP encryption.
    let mut ctx = PkeyCtx::new(&priv_key)?;
    ctx.set_rsa_oaep_md(hash_fn)?;
    Ok((ctx, plaintext))
}

#[test]
fn test_ckm_rsa_pkcs_oaep_unwrap() -> Result<(), KmipUtilsError> {
    // Load FIPS provider module from OpenSSL.
    #[cfg(feature = "fips")]
    openssl::provider::Provider::load(None, "fips").unwrap();

    let privkey = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let pubkey = PKey::public_key_from_pem(&privkey.public_key_to_pem()?)?;

    // Test correct key size
    let dek_to_wrap = Zeroizing::from(vec![0x01; 2048 / 8 - 2 - 2 * 256 / 8]);
    let wrapped_key =
        ckm_rsa_pkcs_oaep_key_wrap(&pubkey, RsaOaepHash::Sha256, dek_to_wrap.clone())?;
    assert_eq!(wrapped_key.len(), 2048 / 8);
    let unwrapped_key = ckm_rsa_pkcs_oaep_key_unwrap(&privkey, RsaOaepHash::Sha256, &wrapped_key)?;
    assert_eq!(unwrapped_key, dek_to_wrap);

    /*    //test incorrect size
        let dek_to_wrap = Zeroizing::from(vec![0x01; 2048 / 8 - 2 - 2 * 256 / 8 - 1]);
        let wrapped_key =
            ckm_rsa_pkcs_oaep_key_wrap(&pubkey, RsaOaepHash::Sha256, dek_to_wrap.clone())?;
        assert_eq!(wrapped_key.len(), 2048 / 8);
        let unwrapped_key = ckm_rsa_pkcs_oaep_key_unwrap(&privkey, RsaOaepHash::Sha256, &wrapped_key)?;
        assert_eq!(unwrapped_key, dek_to_wrap);
    */
    Ok(())
}
