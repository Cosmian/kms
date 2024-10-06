use openssl::{
    rand::rand_bytes,
    symm::{
        decrypt as openssl_decrypt, decrypt_aead as openssl_decrypt_aead,
        encrypt as openssl_encrypt, encrypt_aead as openssl_encrypt_aead, Cipher, Crypter,
        Mode as OpenSslMode,
    },
};
use zeroize::Zeroizing;

use super::{
    aes_gcm_siv_not_openssl, AES_128_GCM_IV_LENGTH, AES_128_GCM_KEY_LENGTH, AES_128_GCM_MAC_LENGTH,
    AES_128_GCM_SIV_IV_LENGTH, AES_128_GCM_SIV_KEY_LENGTH, AES_128_GCM_SIV_MAC_LENGTH,
    AES_128_XTS_KEY_LENGTH, AES_128_XTS_MAC_LENGTH, AES_128_XTS_TWEAK_LENGTH,
    AES_256_GCM_IV_LENGTH, AES_256_GCM_KEY_LENGTH, AES_256_GCM_MAC_LENGTH,
    AES_256_GCM_SIV_IV_LENGTH, AES_256_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_MAC_LENGTH,
    AES_256_XTS_KEY_LENGTH, AES_256_XTS_MAC_LENGTH, AES_256_XTS_TWEAK_LENGTH,
};
use crate::{
    error::KmipError,
    kmip::kmip_types::{BlockCipherMode, CryptographicAlgorithm},
    kmip_bail,
};

#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 key length in bytes.
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 iv length in bytes.
pub const CHACHA20_POLY1305_IV_LENGTH: usize = 12;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 tag/mac length in bytes.
pub const CHACHA20_POLY1305_MAC_LENGTH: usize = 16;

enum Mode {
    Encrypt,
    Decrypt,
}

impl From<Mode> for OpenSslMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Encrypt => OpenSslMode::Encrypt,
            Mode::Decrypt => OpenSslMode::Decrypt,
        }
    }
}

/// The supported AEAD ciphers.
#[derive(Debug, Clone, Copy)]
pub enum SymCipher {
    Aes256Gcm,
    Aes128Gcm,
    Aes128Xts,
    Aes256Xts,
    #[cfg(not(feature = "fips"))]
    Aes128GcmSiv,
    #[cfg(not(feature = "fips"))]
    Aes256GcmSiv,
    #[cfg(not(feature = "fips"))]
    Chacha20Poly1305,
}

impl SymCipher {
    /// Convert to the corresponding OpenSSL cipher.
    fn to_openssl_cipher(self) -> Result<Cipher, KmipError> {
        match self {
            Self::Aes128Gcm => Ok(Cipher::aes_128_gcm()),
            Self::Aes256Gcm => Ok(Cipher::aes_256_gcm()),
            Self::Aes128Xts => Ok(Cipher::aes_128_xts()),
            Self::Aes256Xts => Ok(Cipher::aes_256_xts()),
            #[cfg(not(feature = "fips"))]
            Self::Chacha20Poly1305 => Ok(Cipher::chacha20_poly1305()),
            #[cfg(not(feature = "fips"))]
            SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
                //TODO: openssl supports AES GCM SIV but the rust openssl crate does not expose it
                kmip_bail!(KmipError::NotSupported(
                    "AES GCM SIV is not supported in this version of openssl".to_owned()
                ))
            }
        }
    }

    /// Get the tag size in bytes.
    #[must_use]
    pub const fn tag_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => AES_128_GCM_MAC_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_MAC_LENGTH,
            Self::Aes128Xts => AES_128_XTS_MAC_LENGTH,
            Self::Aes256Xts => AES_256_XTS_MAC_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_MAC_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Aes128GcmSiv => AES_128_GCM_SIV_MAC_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Aes256GcmSiv => AES_256_GCM_SIV_MAC_LENGTH,
        }
    }

    /// Get the nonce size in bytes.
    #[must_use]
    pub const fn nonce_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => AES_128_GCM_IV_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_IV_LENGTH,
            Self::Aes128Xts => AES_128_XTS_TWEAK_LENGTH,
            Self::Aes256Xts => AES_256_XTS_TWEAK_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_IV_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Aes128GcmSiv => AES_128_GCM_SIV_IV_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Aes256GcmSiv => AES_256_GCM_SIV_IV_LENGTH,
        }
    }

    /// Get the key size in bytes.
    #[must_use]
    pub const fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => AES_128_GCM_KEY_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_KEY_LENGTH,
            Self::Aes128Xts => AES_128_XTS_KEY_LENGTH,
            Self::Aes256Xts => AES_256_XTS_KEY_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_KEY_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Aes128GcmSiv => AES_128_GCM_SIV_KEY_LENGTH,
            #[cfg(not(feature = "fips"))]
            Self::Aes256GcmSiv => AES_256_GCM_SIV_KEY_LENGTH,
        }
    }

    pub fn from_algorithm_and_key_size(
        algorithm: CryptographicAlgorithm,
        block_cipher_mode: Option<BlockCipherMode>,
        key_size: usize,
    ) -> Result<Self, KmipError> {
        match algorithm {
            CryptographicAlgorithm::AES => {
                let block_cipher_mode = block_cipher_mode.unwrap_or(BlockCipherMode::GCM);
                match block_cipher_mode {
                    BlockCipherMode::AEAD | BlockCipherMode::GCM => match key_size {
                        AES_128_GCM_KEY_LENGTH => Ok(Self::Aes128Gcm),
                        AES_256_GCM_KEY_LENGTH => Ok(Self::Aes256Gcm),
                        _ => kmip_bail!(KmipError::NotSupported(
                            "AES key must be 16 or 32 bytes long for AES GCM ".to_owned()
                        )),
                    },
                    BlockCipherMode::XTS => match key_size {
                        AES_128_XTS_KEY_LENGTH => Ok(Self::Aes128Xts),
                        AES_256_XTS_KEY_LENGTH => Ok(Self::Aes256Xts),
                        _ => kmip_bail!(KmipError::NotSupported(
                            "AES key must be 32 or 64 bytes long for AES XTS".to_owned()
                        )),
                    },
                    BlockCipherMode::GCMSIV => match key_size {
                        AES_128_GCM_SIV_KEY_LENGTH => Ok(Self::Aes128GcmSiv),
                        AES_256_GCM_SIV_KEY_LENGTH => Ok(Self::Aes256GcmSiv),
                        _ => kmip_bail!(KmipError::NotSupported(
                            "AES key must be 16 or 32 bytes long for AES GCM SIV".to_owned()
                        )),
                    },
                    mode => {
                        kmip_bail!(KmipError::NotSupported(format!(
                            "AES is only supported with GCM mode. Got: {mode:?}"
                        )));
                    }
                }
            }
            #[cfg(not(feature = "fips"))]
            CryptographicAlgorithm::ChaCha20 | CryptographicAlgorithm::ChaCha20Poly1305 => {
                match key_size {
                    32 => Ok(Self::Chacha20Poly1305),
                    _ => kmip_bail!(KmipError::NotSupported(
                        "ChaCha20 key must be 32 bytes long".to_owned()
                    )),
                }
            }
            other => kmip_bail!(KmipError::NotSupported(format!(
                "unsupported cryptographic algorithm: {other} for a symmetric key"
            ))),
        }
    }

    pub fn stream_cipher(
        &self,
        mode: Mode,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<StreamCipher, KmipError> {
        StreamCipher::new(*self, mode, key, nonce, aad)
    }
}

/// Generate a random nonce for the given AEAD cipher.
pub fn random_nonce(aead_cipher: SymCipher) -> Result<Vec<u8>, KmipError> {
    let mut nonce = vec![0; aead_cipher.nonce_size()];
    rand_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Generate a random key for the given AEAD cipher.
pub fn random_key(aead_cipher: SymCipher) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let mut key = Zeroizing::from(vec![0; aead_cipher.key_size()]);
    rand_bytes(&mut key)?;
    Ok(key)
}

/// Encrypt the plaintext using the given symmetric cipher.
/// Return the ciphertext and the tag.
/// For XTS mode, the nonce is the tweak, the aad is ignored, and the tag is empty.
pub fn encrypt(
    sym_cipher: SymCipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KmipError> {
    match sym_cipher {
        SymCipher::Aes128Xts | SymCipher::Aes256Xts => {
            // XTS mode does not require a tag.
            let ciphertext =
                openssl_encrypt(sym_cipher.to_openssl_cipher()?, key, Some(nonce), plaintext)?;
            Ok((ciphertext, vec![]))
        }
        SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
            aes_gcm_siv_not_openssl::encrypt(key, nonce, aad, plaintext)
        }
        _ => {
            // Create buffer for the tag
            let mut tag = vec![0; sym_cipher.tag_size()];
            // Encryption.
            let ciphertext = openssl_encrypt_aead(
                sym_cipher.to_openssl_cipher()?,
                key,
                Some(nonce),
                aad,
                plaintext,
                tag.as_mut(),
            )?;
            Ok((ciphertext, tag))
        }
    }
}

/// Decrypt the ciphertext using the given symmetric cipher.
/// Return the decrypted plaintext.
/// The tag is required for AEAD ciphers (AES GCN, ChaCha Poly1305, ...).
/// For XTS mode, the nonce is the tweak, the aad and the tag are ignored.
pub fn decrypt(
    sym_cipher: SymCipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    Ok(match sym_cipher {
        SymCipher::Aes128Xts | SymCipher::Aes256Xts => {
            // XTS mode does not require a tag.
            Zeroizing::from(openssl_decrypt(
                sym_cipher.to_openssl_cipher()?,
                key,
                Some(nonce),
                ciphertext,
            )?)
        }
        SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
            aes_gcm_siv_not_openssl::decrypt(key, nonce, aad, ciphertext, tag)?
        }
        _ => {
            // Decryption.
            Zeroizing::from(openssl_decrypt_aead(
                sym_cipher.to_openssl_cipher()?,
                key,
                Some(nonce),
                aad,
                ciphertext,
                tag,
            )?)
        }
    })
}

pub enum UnderlyingCipher {
    Openssl(Crypter),
    AesGcmSiv,
}

/// A stream cipher for encryption or decryption.
pub struct StreamCipher {
    underlying_cipher: UnderlyingCipher,
    block_size: usize,
}

impl StreamCipher {
    fn new(
        sym_cipher: SymCipher,
        mode: Mode,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Self, KmipError> {
        match sym_cipher {
            SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
                todo!()
            }
            _ => {
                let cipher = sym_cipher.to_openssl_cipher()?;
                let block_size = cipher.block_size();
                let mut crypter = Crypter::new(cipher, mode.into(), key, Some(nonce))?;
                if !aad.is_empty() {
                    crypter.aad_update(aad)?;
                }
                Ok(Self {
                    underlying_cipher: UnderlyingCipher::Openssl(crypter),
                    block_size,
                    aad: aad.to_vec(),
                })
            }
        }
    }

    pub fn update(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, KmipError> {
        match self.underlying_cipher {
            UnderlyingCipher::Openssl(ref mut c) => {
                let mut buffer = vec![0; ciphertext.len() + self.block_size];
                let len = c.update(ciphertext, &mut buffer)?;
                buffer.truncate(len);
                Ok(buffer)
            }
            UnderlyingCipher::AesGcmSiv => {
                todo!()
            }
        }
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>, KmipError> {
        match self.underlying_cipher {
            UnderlyingCipher::Openssl(ref mut c) => {
                let mut buffer = vec![0; self.block_size];
                let len = c.finalize(&mut buffer)?;
                buffer.truncate(len);
                Ok(buffer)
            }
            UnderlyingCipher::AesGcmSiv => {
                todo!()
            }
        }
    }
}
