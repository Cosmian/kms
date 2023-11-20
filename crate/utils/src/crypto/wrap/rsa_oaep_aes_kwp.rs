use cloudproof::reexport::crypto_core::reexport::zeroize::Zeroizing;
use openssl::{
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
    rsa::Padding,
};

use super::rfc5649::{key_unwrap, key_wrap, AES_KWP_KEY_SIZE};
use crate::{error::KmipUtilsError, kmip_utils_bail};

#[cfg(feature = "fips")]
const FIPS_MIN_RSA_MODULUS_LENGTH: u32 = 256;

/// Asymmetrically wrap keys refering to PKCS#11 available at
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
/// Encrypt they key/message `m` such as`wk = enc(kek, m)` using the key `kek`
/// with AES-KWP as specified in RFC5649.
///
/// Send `c|wk` where `|` is the concatenation operator.
///
/// TODO - support OAEP for different hashes.
pub fn ckm_rsa_aes_key_wrap(
    pubkey: PKey<Public>,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    let rsa_pubkey = pubkey.rsa()?;
    #[cfg(feature = "fips")]
    if rsa_pubkey.size() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_utils_bail!(
            "CKM_RSA_OAEP encryption error: RSA key has insufficient size: expected >= {} bytes \
             and got {} bytes",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            pubkey.bits()
        )
    }

    let encapsulation_bytes_len = rsa_pubkey.size() as usize;

    // Generate temporary AES key.
    let mut kek = Zeroizing::from(vec![0u8; AES_KWP_KEY_SIZE]);
    rand_bytes(&mut kek)?;

    let mut c = vec![0u8; encapsulation_bytes_len];
    let encrypted_len = rsa_pubkey.public_encrypt(&kek, &mut c, Padding::PKCS1_OAEP)?;
    c.truncate(encrypted_len);

    // Wrap key according to RFC 5649 as recommended.
    let wk = key_wrap(plaintext, &kek)?;

    Ok([c, wk].concat())
}

/// Asymmetrically unwrap keys refering to PKCS#11 available at
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
/// First decrypt the key-encryption-key `kek` using RSA-OAEP. then proceed to
/// unwrap the key by decrypting `m = dec(wk, kek)` using AES-KWP as specified in
/// RFC5649.
///
/// TODO - support OAEP for different hashes.
pub fn ckm_rsa_aes_key_unwrap(
    p_key: PKey<Private>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
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

    let c: &[u8] = &ciphertext[..encapsulation_bytes_len];
    let wk = &ciphertext[encapsulation_bytes_len..];

    let mut kek = Zeroizing::from(vec![0u8; encapsulation_bytes_len]);
    let decrypted_len = rsa_privkey.private_decrypt(c, &mut kek, Padding::PKCS1_OAEP)?;
    kek.truncate(decrypted_len);
    if kek.len() != AES_KWP_KEY_SIZE {
        kmip_utils_bail!(
            "CKM_RSA_OAEP decryption error: size mismatch, ciphertext may have been tweaked."
        )
    }

    // Unwrap key according to RFC 5649 as recommended.
    let plaintext = key_unwrap(wk, &kek)?;

    Ok(plaintext)
}

#[test]
#[cfg(feature = "fips")]
fn test_rsa_kem_wrap_unwrap() -> Result<(), KmipUtilsError> {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let privkey = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let pubkey = PKey::public_key_from_pem(&privkey.public_key_to_pem()?)?;

    let privkey_to_wrap = openssl::rsa::Rsa::generate(2048)?.private_key_to_pem()?;

    let wrapped_key = ckm_rsa_aes_key_wrap(pubkey, &privkey_to_wrap)?;

    let unwrapped_key = ckm_rsa_aes_key_unwrap(privkey, &wrapped_key)?;

    assert_eq!(unwrapped_key, privkey_to_wrap);

    Ok(())
}
