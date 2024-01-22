use cloudproof::reexport::crypto_core::reexport::zeroize::Zeroizing;
use openssl::{
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
};

use crate::{
    crypto::{
        rsa::ckm_rsa_pkcs_oaep::{
            ckm_rsa_pkcs_oaep_key_unwrap, ckm_rsa_pkcs_oaep_key_wrap, RsaOaepHash,
        },
        symmetric::rfc5649::{rfc5649_unwrap, rfc5649_wrap, AES_KWP_KEY_SIZE},
    },
    error::KmipUtilsError,
    kmip_utils_bail,
};

#[cfg(feature = "fips")]
pub const FIPS_MIN_RSA_MODULUS_LENGTH: u32 = 256;

/// Asymmetrically wrap keys referring to PKCS#11 CKM_RSA_AES_KEY_WRAP available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908
///
/// This document describes how to wrap keys of any size using asymmetric
/// encryption and the RSA algorithm. Since old similar wrapping methods based
/// on RSA used naive RSA encryption and could present some flaws, this RFC aims
/// at a generally more secure method to wrap keys.
///
/// Let `m` be the key/message to wrap, first generate a temporary random AES
/// key `kek`. Encrypt it using RSA-OAEP; `c` is the encrypted key.
///
/// Encrypt the key/message `m` such as`wk = enc(kek, m)` using the key `kek`
/// with AES-KWP as specified in RFC5649.
///
/// Send `c|wk` where `|` is the concatenation operator.
///
/// TODO - support OAEP for different hashes.
pub fn ckm_rsa_aes_key_wrap(
    pubkey: &PKey<Public>,
    hash_fn: RsaOaepHash,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    // Generate temporary AES key.
    let mut kek = Zeroizing::from(vec![0u8; AES_KWP_KEY_SIZE]);
    rand_bytes(&mut kek)?;

    // Encapsulate it using RSA-OAEP.
    let encapsulation = ckm_rsa_pkcs_oaep_key_wrap(pubkey, hash_fn, &kek)?;

    // Wrap key according to RFC 5649 as recommended.
    let wk = rfc5649_wrap(plaintext, &kek)?;

    Ok([encapsulation, wk].concat())
}

/// Asymmetrically unwrap keys referring to PKCS#11 CKM_RSA_AES_KEY_WRAP available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908
///
/// This document describes how to unwrap keys of any size using asymmetric
/// encryption and the RSA algorithm. Since old similar wrapping methods based
/// on RSA used naive RSA encryption and could present some flaws, this RFC aims
/// at a generally more secure method to wrap keys.
///
/// Receive data of the form `c|wk` where `|` is the concatenation operator.
/// Distinguish `c` and `wk`, respectively the encrypted `kek` and the wrapped
/// key.
///
/// First decrypt the key-encryption-key `kek` using RSA-OAEP. Then proceed to
/// unwrap the key by decrypting `m = dec(wk, kek)` using AES-KWP as specified in
/// RFC5649.
///
/// TODO - support OAEP for different hashes.
pub fn ckm_rsa_aes_key_unwrap(
    p_key: &PKey<Private>,
    hash_fn: RsaOaepHash,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    let rsa_privkey = p_key.rsa()?;

    #[cfg(feature = "fips")]
    if rsa_privkey.size() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_utils_bail!(
            "CKM_RSA_OAEP decryption error: RSA key has insufficient size: expected >= {} bytes \
             and got {} bytes",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            rsa_privkey.size()
        )
    }

    let encapsulation_bytes_len = rsa_privkey.size() as usize;
    if ciphertext.len() <= encapsulation_bytes_len {
        kmip_utils_bail!(
            "CKM_RSA_OAEP decryption error: encrypted data of insufficient length: got {}",
            ciphertext.len()
        );
    }

    // Split ciphertext into encapsulation and wrapped key.
    let encapsulation = &ciphertext[..encapsulation_bytes_len];
    let wk = &ciphertext[encapsulation_bytes_len..];

    // Unwrap key-encryption-key using RSA-OAEP.
    let kek = ckm_rsa_pkcs_oaep_key_unwrap(p_key, hash_fn, encapsulation)?;

    // Unwrap key according to RFC 5649 as recommended.
    let plaintext = rfc5649_unwrap(wk, &kek)?;

    Ok(plaintext)
}

#[test]
fn test_rsa_kem_wrap_unwrap() -> Result<(), KmipUtilsError> {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let priv_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let pub_key = PKey::public_key_from_pem(&priv_key.public_key_to_pem()?)?;

    let privkey_to_wrap = Zeroizing::from(openssl::rsa::Rsa::generate(2048)?.private_key_to_pem()?);

    let wrapped_key = ckm_rsa_aes_key_wrap(&pub_key, RsaOaepHash::Sha256, &priv_key_to_wrap)?;

    let unwrapped_key = ckm_rsa_aes_key_unwrap(&priv_key, RsaOaepHash::Sha256, &wrapped_key)?;

    assert_eq!(unwrapped_key, priv_key_to_wrap);

    Ok(())
}
