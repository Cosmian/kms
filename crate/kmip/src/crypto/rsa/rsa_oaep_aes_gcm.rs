use openssl::pkey::{PKey, Private, Public};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        rsa::ckm_rsa_pkcs_oaep::{ckm_rsa_pkcs_oaep_key_unwrap, ckm_rsa_pkcs_oaep_key_wrap},
        symmetric::{
            aead::{aead_decrypt, aead_encrypt, random_key, random_nonce, AeadCipher},
            AES_256_GCM_MAC_LENGTH,
        },
    },
    error::KmipError,
    kmip::kmip_types::HashingAlgorithm,
    kmip_bail,
};

/// Asymmetrically encrypt data referring to PKCS#11 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html
///
/// Let `m` be the message to encrypt, first generate a temporary random AES key
/// `dek`. Encrypt it using RSA-OAEP; `c` is the encrypted key.
///
/// Encrypt the message `m` such as`ct = enc(dek, m)` using the key `dek`
/// with AES-128-GCM with proper IV and potential additional data.
///
/// Send `c|iv|ct|tag` where `|` is the concatenation operator, `iv` the
/// initialization vector and `tag` the authentication tag.
pub fn ckm_rsa_oaep_aes_key_wrap_encrypt(
    pubkey: &PKey<Public>,
    hash_fn: HashingAlgorithm,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, KmipError> {
    // Generate temporary AES key.
    let dek = random_key(AeadCipher::Aes128Gcm)?;

    // Generate IV.
    let iv = random_nonce(AeadCipher::Aes128Gcm)?;

    // Encapsulate it using RSA-OAEP.
    let c = ckm_rsa_pkcs_oaep_key_wrap(pubkey, hash_fn, &dek)?;

    let (ciphertext, tag) = aead_encrypt(
        AeadCipher::Aes128Gcm,
        &dek,
        &iv,
        aad.unwrap_or_default(),
        plaintext,
    )?;

    Ok([c, iv.clone(), ciphertext, tag].concat())
}

/// Asymmetrically unwrap keys referring to PKCS#11 available at
/// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html
///
/// Receive data of the form `c|iv|ct|tag` where `|` is the concatenation
/// operator. Distinguish `c`, `iv`, `ct` and `tag` respectively the encrypted
/// `dek`, the initialization vector, the encrypted message, and the
/// authentication tag.
///
/// First decrypt the data-encryption-key `dek` using RSA-OAEP. Then proceed to
/// decrypt the message by decrypting `m = dec(ct, dek)` using AES-128-GCM.
pub fn rsa_oaep_aes_gcm_decrypt(
    p_key: &PKey<Private>,
    hash_fn: HashingAlgorithm,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let rsa_privkey = p_key.rsa()?;

    let encapsulation_bytes_len = rsa_privkey.size() as usize;
    if ciphertext.len()
        <= encapsulation_bytes_len + AeadCipher::Aes128Gcm.nonce_size() + AES_256_GCM_MAC_LENGTH
    {
        kmip_bail!(
            "CKM_RSA_OAEP decryption error: encrypted data of insufficient length: got {}",
            ciphertext.len()
        );
    }

    // Ciphertext received is a concatenation of `c | IV | ct | tag` with `c`
    // and `ct` of variable size and `IV` of size 96 bits and `tag` 128 bits.
    let c = &ciphertext[..encapsulation_bytes_len];

    let iv_offset = encapsulation_bytes_len + AeadCipher::Aes128Gcm.nonce_size();
    let iv = &ciphertext[encapsulation_bytes_len..iv_offset];

    let ct_offset = ciphertext.len() - AeadCipher::Aes128Gcm.tag_size();
    let ct = &ciphertext[iv_offset..ct_offset];

    let tag = &ciphertext[ct_offset..];

    if iv.len() != AeadCipher::Aes128Gcm.nonce_size()
        || tag.len() != AeadCipher::Aes128Gcm.tag_size()
    {
        kmip_bail!(
            "Attempt at RSA_OAEP_AES_GCM_DECRYPT with bad nonce size {} or bad tag size {}.",
            iv.len(),
            tag.len()
        )
    }

    // recover the data-encryption-key using RSA-OAEP.
    let dek = ckm_rsa_pkcs_oaep_key_unwrap(p_key, hash_fn, c)?;
    if dek.len() != AeadCipher::Aes128Gcm.key_size() {
        kmip_bail!("RSA_OAEP_AES_GCM_DECRYPT error: wrong data encryption key size.")
    }

    // Decrypt data using AES-128-GCM with the data encryption key freshly decrypted.
    aead_decrypt(
        AeadCipher::Aes128Gcm,
        &dek,
        iv,
        aad.unwrap_or_default(),
        ct,
        tag,
    )
}

#[cfg(test)]
mod tests {
    use openssl::{pkey::PKey, rand::rand_bytes};

    use crate::{
        crypto::rsa::rsa_oaep_aes_gcm::{rsa_oaep_aes_gcm_decrypt, ckm_rsa_oaep_aes_key_wrap_encrypt},
        error::KmipError,
        kmip::kmip_types::HashingAlgorithm,
    };

    #[test]
    fn test_rsa_oaep_aes_gcm() -> Result<(), KmipError> {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let privkey = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
        let pubkey = PKey::public_key_from_pem(&privkey.public_key_to_pem()?)?;

        let mut plaintext = [0; 256];
        rand_bytes(&mut plaintext)?;

        let ct = ckm_rsa_oaep_aes_key_wrap_encrypt(
            &pubkey,
            HashingAlgorithm::SHA256,
            &plaintext,
            Some(b"asdfg"),
        )?;

        let decrytped =
            rsa_oaep_aes_gcm_decrypt(&privkey, HashingAlgorithm::SHA256, &ct, Some(b"asdfg"))?;

        // `to_vec()` conversion because of Zeroizing<>.
        assert_eq!(decrytped.to_vec(), plaintext);

        Ok(())
    }
}
