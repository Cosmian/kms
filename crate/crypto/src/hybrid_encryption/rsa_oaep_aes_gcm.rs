use openssl::{
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
    rsa::Padding,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use zeroize::Zeroizing;

use crate::{
    error::KmsCryptoError,
    kms_crypto_bail,
    symmetric::{AES_256_GCM_IV_LENGTH, AES_256_GCM_KEY_LENGTH, AES_256_GCM_MAC_LENGTH},
};

#[cfg(feature = "fips")]
const FIPS_MIN_RSA_MODULUS_LENGTH: u32 = 256;

/// Asymmetrically encrypt data referring to PKCS#11 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html
///
/// Let `m` be the message to encrypt, first generate a temporary random AES key
/// `kek`. Encrypt it using RSA-OAEP; `c` is the encrypted key.
///
/// Encrypt the message `m` such as`ct = enc(kek, m)` using the key `kek`
/// with AES-256-GCM with proper IV and potential additional data.
///
/// Send `c|iv|ct|tag` where `|` is the concatenation operator, `iv` the
/// initialization vector and `tag` the authentication tag.
///
/// TODO - support OAEP for different hashes.
pub fn rsa_oaep_aes_gcm_encrypt(
    pubkey: &PKey<Public>,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, KmsCryptoError> {
    let rsa_pubkey = pubkey.rsa()?;
    #[cfg(feature = "fips")]
    if rsa_pubkey.size() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kms_crypto_bail!(
            "CKM_RSA_OAEP encryption error: RSA key has insufficient size: expected >= {} bytes \
             and got {} bytes",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            pubkey.bits()
        )
    }

    let encapsulation_bytes_len = rsa_pubkey.size() as usize;

    // Generate temporary AES key.
    let mut kek = Zeroizing::from(vec![0u8; AES_256_GCM_KEY_LENGTH]);
    rand_bytes(&mut kek)?;

    let mut c = vec![0u8; encapsulation_bytes_len];
    let encrypted_len = rsa_pubkey.public_encrypt(&kek, &mut c, Padding::PKCS1_OAEP)?;
    c.truncate(encrypted_len);

    // Encrypt the key-encryption key using AES-256-GCM.
    // Random IV generation.
    let mut iv = [0; AES_256_GCM_IV_LENGTH];
    rand_bytes(&mut iv)?;

    // Create buffer for GCM tag (MAC).
    let mut tag = vec![0; AES_256_GCM_MAC_LENGTH];
    let ct: Vec<u8> = encrypt_aead(
        Cipher::aes_256_gcm(),
        &kek,
        Some(&iv),
        aad.unwrap_or_default(),
        plaintext,
        tag.as_mut(),
    )?;

    Ok([c, iv.to_vec(), ct, tag].concat())
}

/// Asymmetrically unwrap keys referring to PKCS#11 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html
///
/// Receive data of the form `c|iv|ct|tag` where `|` is the concatenation
/// operator. Distinguish `c`, `iv`, `ct` and `tag` respectively the encrypted
/// `kek`, the initialization vector, the encrypted message, and the
/// authentication tag.
///
/// First decrypt the key-encryption-key `kek` using RSA-OAEP. Then proceed to
/// decrypt the message by decrypting `m = dec(ct, kek)` using AES-256-GCM.
///
/// TODO - support OAEP for different hashes.
pub fn rsa_oaep_aes_gcm_decrypt(
    p_key: &PKey<Private>,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, KmsCryptoError> {
    let rsa_privkey = p_key.rsa()?;

    #[cfg(feature = "fips")]
    if rsa_privkey.size() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kms_crypto_bail!(
            "CKM_RSA_OAEP decryption error: RSA key has insufficient size: expected >= {} bytes \
             and got {} bytes",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            rsa_privkey.size()
        )
    }

    let encapsulation_bytes_len = rsa_privkey.size() as usize;
    if ciphertext.len() <= encapsulation_bytes_len + AES_256_GCM_IV_LENGTH + AES_256_GCM_MAC_LENGTH
    {
        kms_crypto_bail!(
            "CKM_RSA_OAEP decryption error: encrypted data of insufficient length: got {}",
            ciphertext.len()
        );
    }

    // Ciphertext received is a concatenation of `c | IV | ct | tag` with `c`
    // and `ct` of variable size and `IV` of size 96 bits and `tag` 128 bits.
    let c = &ciphertext[..encapsulation_bytes_len];

    let iv_offset = encapsulation_bytes_len + AES_256_GCM_IV_LENGTH;
    let iv = &ciphertext[encapsulation_bytes_len..iv_offset];

    let ct_offset = ciphertext.len() - AES_256_GCM_MAC_LENGTH;
    let ct = &ciphertext[iv_offset..ct_offset];

    let tag = &ciphertext[ct_offset..];

    if iv.len() != AES_256_GCM_IV_LENGTH || tag.len() != AES_256_GCM_MAC_LENGTH {
        kms_crypto_bail!(
            "Attempt at RSA_OAEP_AES_GCM_DECRYPT with bad nonce size {} or bad tag size {}.",
            iv.len(),
            tag.len()
        )
    }

    let mut kek = Zeroizing::from(vec![0u8; encapsulation_bytes_len]);
    let decrypted_len = rsa_privkey.private_decrypt(c, &mut kek, Padding::PKCS1_OAEP)?;
    kek.truncate(decrypted_len);
    if kek.len() != AES_256_GCM_KEY_LENGTH {
        kms_crypto_bail!(
            "CKM_RSA_OAEP decryption error: size mismatch, ciphertext may have been tweaked."
        )
    }

    // Decrypt data using AES-256-GCM with key-ecryption-key freshly decrypted.
    let plaintext = Zeroizing::from(decrypt_aead(
        Cipher::aes_256_gcm(),
        &kek,
        Some(iv),
        aad.unwrap_or_default(),
        ct,
        tag,
    )?);

    Ok(plaintext)
}

#[test]
fn test_rsa_oaep_encrypt_decrypt() -> Result<(), KmsCryptoError> {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let privkey = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let pubkey = PKey::public_key_from_pem(&privkey.public_key_to_pem()?)?;

    let privkey_to_wrap = Zeroizing::from(openssl::rsa::Rsa::generate(2048)?.private_key_to_pem()?);

    let ct = rsa_oaep_aes_gcm_encrypt(&pubkey, &privkey_to_wrap, None)?;

    let unwrapped_key = rsa_oaep_aes_gcm_decrypt(&privkey, &ct, None)?;

    assert_eq!(unwrapped_key, privkey_to_wrap);

    Ok(())
}
