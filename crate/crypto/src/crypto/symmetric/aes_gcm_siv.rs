//! AES-GCM-SIV (RFC 8452) via OpenSSL's default provider (EVP cipher fetched by name).

use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use zeroize::Zeroizing;

use crate::{
    CryptoError,
    crypto::symmetric::symmetric_ciphers::{
        AES_128_GCM_SIV_IV_LENGTH, AES_128_GCM_SIV_KEY_LENGTH, AES_128_GCM_SIV_MAC_LENGTH,
        AES_256_GCM_SIV_KEY_LENGTH,
    },
};

fn fetch_cipher(key: &[u8]) -> Result<Cipher, CryptoError> {
    let name = match key.len() {
        AES_128_GCM_SIV_KEY_LENGTH => "AES-128-GCM-SIV",
        AES_256_GCM_SIV_KEY_LENGTH => "AES-256-GCM-SIV",
        len => {
            return Err(CryptoError::InvalidSize(format!(
                "Invalid key size: {len} for AES GCM SIV"
            )));
        }
    };
    Ok(Cipher::fetch(None, name, None)?)
}

/// `CipherCtx::*_init` panics on a short nonce, so check it first.
fn check_nonce(nonce: &[u8]) -> Result<(), CryptoError> {
    if nonce.len() == AES_128_GCM_SIV_IV_LENGTH {
        Ok(())
    } else {
        Err(CryptoError::InvalidSize(format!(
            "Invalid nonce size: {} for AES GCM SIV",
            nonce.len()
        )))
    }
}

/// Encrypt data using AES GCM SIV.
/// # Arguments
/// * `key` - The key to use for encryption.
/// * `nonce` - The nonce to use for encryption.
/// * `aad` - The additional authenticated data.
/// * `plaintext` - The data to encrypt.
/// # Returns
/// * The encrypted data and the tag.
/// # Errors
/// * If the key or the nonce is not the correct size.
/// * If there is an error encrypting the data.
pub(super) fn encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = fetch_cipher(key)?;
    check_nonce(nonce)?;
    let mut ctx = CipherCtx::new()?;
    ctx.encrypt_init(Some(&cipher), Some(key), Some(nonce))?;
    if !aad.is_empty() {
        ctx.cipher_update(aad, None)?;
    }
    // GCM-SIV takes the whole message in a single update, even when it is empty.
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
    ctx.cipher_final_vec(&mut ciphertext)?;
    let mut tag = vec![0_u8; AES_128_GCM_SIV_MAC_LENGTH];
    ctx.tag(&mut tag)?;
    Ok((ciphertext, tag))
}

/// Decrypt data using AES GCM SIV.
/// # Arguments
/// * `key` - The key to use for decryption.
/// * `nonce` - The nonce to use for decryption.
/// * `aad` - The additional authenticated data.
/// * `ciphertext` - The data to decrypt.
/// * `tag` - The tag to use for decryption.
/// # Returns
/// * The decrypted data.
/// # Errors
/// * If the key, the nonce or the tag is not the correct size.
/// * If the tag does not authenticate the data.
pub(super) fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = fetch_cipher(key)?;
    check_nonce(nonce)?;
    if tag.len() != AES_128_GCM_SIV_MAC_LENGTH {
        return Err(CryptoError::InvalidSize(format!(
            "Invalid tag size: {} for AES GCM SIV",
            tag.len()
        )));
    }
    let mut ctx = CipherCtx::new()?;
    ctx.decrypt_init(Some(&cipher), Some(key), Some(nonce))?;
    ctx.set_tag(tag)?;
    if !aad.is_empty() {
        ctx.cipher_update(aad, None)?;
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
    ctx.cipher_update_vec(ciphertext, &mut plaintext)?;
    // A wrong tag fails here.
    ctx.cipher_final_vec(&mut plaintext)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use crate::CryptoError;

    /// RFC 8452 Appendix C.1 (`AEAD_AES_128_GCM_SIV`) and a 256-bit vector.
    fn vectors() -> Vec<(
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    )> {
        let k128 = "01000000000000000000000000000000";
        let n128 = "030000000000000000000000";
        vec![
            (k128, n128, "", "", "", "dc20e2d83f25705bb49e439eca56de25"),
            (
                k128,
                n128,
                "",
                "0100000000000000",
                "b5d839330ac7b786",
                "578782fff6013b815b287c22493a364c",
            ),
            (
                k128,
                n128,
                "01",
                "0200000000000000",
                "1e6daba35669f427",
                "3b0a1a2560969cdf790d99759abd1508",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "",
                "48656C6C6F2C204145532D3235362D47434D2D53495621",
                "DC210E6F17B45F7D097AB65FA67A8422BE2575EEA92F98",
                "4FE4EE0CF4336DC842D50BC8E0251568",
            ),
        ]
    }

    #[test]
    fn test_rfc8452_vectors() {
        for (key, nonce, aad, pt, ct, tag) in vectors() {
            let (key, nonce, aad, pt) = (
                hex::decode(key).unwrap(),
                hex::decode(nonce).unwrap(),
                hex::decode(aad).unwrap(),
                hex::decode(pt).unwrap(),
            );
            let (got_ct, got_tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
            assert_eq!(hex::encode(&got_ct), ct.to_lowercase());
            assert_eq!(hex::encode(&got_tag), tag.to_lowercase());
            let got_pt = decrypt(&key, &nonce, &aad, &got_ct, &got_tag).unwrap();
            assert_eq!(*got_pt, pt);
        }
    }

    #[test]
    fn test_bad_tag_and_bad_nonce() {
        let key = hex::decode("01000000000000000000000000000000").unwrap();
        let nonce = hex::decode("030000000000000000000000").unwrap();
        let (ct, mut tag) = encrypt(&key, &nonce, b"", &[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        tag[0] ^= 1;
        decrypt(&key, &nonce, b"", &ct, &tag).unwrap_err();

        assert!(matches!(
            encrypt(&key, &nonce[..11], b"", b"x"),
            Err(CryptoError::InvalidSize(_))
        ));
    }
}
