use std::cmp::PartialEq;

use openssl::{
    rand::rand_bytes,
    symm::{
        decrypt as openssl_decrypt, decrypt_aead as openssl_decrypt_aead,
        encrypt as openssl_encrypt, encrypt_aead as openssl_encrypt_aead, Cipher, Crypter,
        Mode as OpenSslMode,
    },
};
use zeroize::Zeroizing;

#[cfg(not(feature = "fips"))]
use super::aes_gcm_siv_not_openssl;
use crate::{
    crypto::symmetric::rfc5649::{rfc5649_unwrap, rfc5649_wrap},
    error::{result::KmipResult, KmipError},
    kmip::kmip_types::{BlockCipherMode, CryptographicAlgorithm},
    kmip_bail,
};

/// AES 128 GCM key length in bytes.
pub const AES_128_GCM_KEY_LENGTH: usize = 16;
/// AES 128 GCM nonce length in bytes.
pub const AES_128_GCM_IV_LENGTH: usize = 12;
/// AES 128 GCM tag/mac length in bytes.
pub const AES_128_GCM_MAC_LENGTH: usize = 16;

/// AES 256 GCM key length in bytes.
pub const AES_256_GCM_KEY_LENGTH: usize = 32;
/// AES 256 GCM nonce length in bytes.
pub const AES_256_GCM_IV_LENGTH: usize = 12;
/// AES 256 GCM tag/mac length in bytes.
pub const AES_256_GCM_MAC_LENGTH: usize = 16;

/// AES 128 XTS key length in bytes.
pub const AES_128_XTS_KEY_LENGTH: usize = 32;
/// AES 128 XTS nonce, actually called a tweak, length in bytes.
pub const AES_128_XTS_TWEAK_LENGTH: usize = 16;
/// AES 128 XTS has no authentication.
pub const AES_128_XTS_MAC_LENGTH: usize = 0;
/// AES 256 XTS key length in bytes.
pub const AES_256_XTS_KEY_LENGTH: usize = 64;
/// AES 256 XTS nonce actually called a tweak,length in bytes.
pub const AES_256_XTS_TWEAK_LENGTH: usize = 16;
/// AES 256 XTS has no authentication.
pub const AES_256_XTS_MAC_LENGTH: usize = 0;
/// AES 128 `GCM_SIV` key length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_128_GCM_SIV_KEY_LENGTH: usize = 16;
/// AES 128 `GCM_SIV` nonce length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_128_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 128 `GCM_SIV` mac length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_128_GCM_SIV_MAC_LENGTH: usize = 16;
/// AES 256 `GCM_SIV` key length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_256_GCM_SIV_KEY_LENGTH: usize = 32;
/// AES 256 `GCM_SIV` nonce length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_256_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 256 `GCM_SIV` mac length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_256_GCM_SIV_MAC_LENGTH: usize = 16;

/// RFC 5649 with a 16-byte KEK.
pub const RFC5649_16_KEY_LENGTH: usize = 16;
// RFC 5649 IV is actually a fixed overhead
pub const RFC5649_16_IV_LENGTH: usize = 0;
/// RFC5649 has no authentication.
pub const RFC5649_16_MAC_LENGTH: usize = 0;
/// RFC 5649 with a 32-byte KEK.
pub const RFC5649_32_KEY_LENGTH: usize = 32;
// RFC 5649 IV is actually a fixed overhead
pub const RFC5649_32_IV_LENGTH: usize = 0;
/// RFC5649 has no authentication.
pub const RFC5649_32_MAC_LENGTH: usize = 0;

#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 key length in bytes.
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 iv length in bytes.
pub const CHACHA20_POLY1305_IV_LENGTH: usize = 12;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 tag/mac length in bytes.
pub const CHACHA20_POLY1305_MAC_LENGTH: usize = 16;

/// The mode of operation for the symmetric stream cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl From<Mode> for OpenSslMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Encrypt => Self::Encrypt,
            Mode::Decrypt => Self::Decrypt,
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
    Rfc5649_16,
    Rfc5649_32,
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
            Self::Rfc5649_16 | Self::Rfc5649_32 => {
                kmip_bail!(KmipError::NotSupported(
                    "RFC5649 is not supported in this version of openssl".to_owned()
                ))
            }
            #[cfg(not(feature = "fips"))]
            Self::Chacha20Poly1305 => Ok(Cipher::chacha20_poly1305()),
            #[cfg(not(feature = "fips"))]
            Self::Aes128GcmSiv | Self::Aes256GcmSiv => {
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
            Self::Rfc5649_16 => RFC5649_16_MAC_LENGTH,
            Self::Rfc5649_32 => RFC5649_32_MAC_LENGTH,
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
            Self::Rfc5649_16 => RFC5649_16_IV_LENGTH,
            Self::Rfc5649_32 => RFC5649_32_IV_LENGTH,
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
            Self::Rfc5649_16 => RFC5649_16_KEY_LENGTH,
            Self::Rfc5649_32 => RFC5649_32_KEY_LENGTH,
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
                    #[cfg(not(feature = "fips"))]
                    BlockCipherMode::GCMSIV => match key_size {
                        AES_128_GCM_SIV_KEY_LENGTH => Ok(Self::Aes128GcmSiv),
                        AES_256_GCM_SIV_KEY_LENGTH => Ok(Self::Aes256GcmSiv),
                        _ => kmip_bail!(KmipError::NotSupported(
                            "AES key must be 16 or 32 bytes long for AES GCM SIV".to_owned()
                        )),
                    },
                    BlockCipherMode::NISTKeyWrap => match key_size {
                        RFC5649_16_KEY_LENGTH => Ok(Self::Rfc5649_16),
                        RFC5649_32_KEY_LENGTH => Ok(Self::Rfc5649_32),
                        _ => kmip_bail!(KmipError::NotSupported(
                            "RFC5649 key must be 16 or 32 bytes long".to_owned()
                        )),
                    },
                    mode => {
                        kmip_bail!(KmipError::NotSupported(format!(
                            "AES is not supported with mode: {mode:?}"
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

/// Generate a random nonce for the given symmetric cipher.
pub fn random_nonce(sym_cipher: SymCipher) -> Result<Vec<u8>, KmipError> {
    let mut nonce = vec![0; sym_cipher.nonce_size()];
    rand_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Generate a random key for the given symmetric cipher.
pub fn random_key(sym_cipher: SymCipher) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let mut key = Zeroizing::from(vec![0; sym_cipher.key_size()]);
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
        #[cfg(not(feature = "fips"))]
        SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
            aes_gcm_siv_not_openssl::encrypt(key, nonce, aad, plaintext)
        }
        SymCipher::Rfc5649_16 | SymCipher::Rfc5649_32 => {
            Ok((rfc5649_wrap(plaintext, key)?, vec![]))
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
///
/// Return the decrypted plaintext.
/// The tag is required for AEAD ciphers (`AES GCN`, `ChaCha20 Poly1305`, ...).
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
        #[cfg(not(feature = "fips"))]
        SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
            aes_gcm_siv_not_openssl::decrypt(key, nonce, aad, ciphertext, tag)?
        }
        SymCipher::Rfc5649_16 | SymCipher::Rfc5649_32 => rfc5649_unwrap(ciphertext, key)?,
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

/// A stream cipher for encryption or decryption. /
pub struct StreamCipher {
    underlying_cipher: UnderlyingCipher,
    mode: Mode,
    block_size: usize,
    tag_size: usize,
    buffer: Vec<u8>,
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
            #[cfg(not(feature = "fips"))]
            SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
                //TODO: the pure Rust crate does not support streaming. When openssl id exposed, this should be fixed
                Err(KmipError::NotSupported(
                    "AES GCM SIV is not supported as a stream cipher for now".to_owned(),
                ))
            }
            _ => {
                let cipher = sym_cipher.to_openssl_cipher()?;
                let block_size = match sym_cipher {
                    // This seems to be a bug in the openssl crate. The block size for AES is 16 bytes.
                    SymCipher::Aes128Xts => 16,
                    SymCipher::Aes256Xts => 32,
                    _ => cipher.block_size(),
                };
                let mut crypter = Crypter::new(cipher, mode.into(), key, Some(nonce))?;
                if !aad.is_empty() {
                    crypter.aad_update(aad)?;
                }
                Ok(Self {
                    underlying_cipher: UnderlyingCipher::Openssl(crypter),
                    mode,
                    block_size,
                    tag_size: sym_cipher.tag_size(),
                    buffer: vec![],
                })
            }
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> KmipResult<Vec<u8>> {
        match self.underlying_cipher {
            UnderlyingCipher::Openssl(ref mut c) => {
                // prepend the remaining bytes from the buffer
                let available_bytes = [self.buffer.clone(), bytes.to_vec()].concat();
                // we only encrypt or decrypt in block sizes because XTS requires it (not GCM)
                // but we always want to keep at least one block in the buffer
                let len_to_park = available_bytes.len() % self.block_size + self.block_size;
                if available_bytes.len() <= len_to_park {
                    // all bytes are pushed to the buffer
                    self.buffer = available_bytes;
                    return Ok(vec![]);
                }
                let len_to_update = available_bytes.len() - len_to_park;
                let mut buffer = vec![0; len_to_update + self.block_size];
                let update_len = c.update(
                    available_bytes.get(..len_to_update).ok_or_else(|| {
                        KmipError::IndexingSlicing(
                            "sym_ciphers: update: ..len_to_update".to_owned(),
                        )
                    })?,
                    &mut buffer,
                )?;
                buffer.truncate(update_len);
                // store the remaining bytes in the cipher buffer
                self.buffer = available_bytes
                    .get(len_to_update..)
                    .ok_or_else(|| {
                        KmipError::IndexingSlicing(
                            "sym_ciphers: update: len_to_update..".to_owned(),
                        )
                    })?
                    .to_vec();
                Ok(buffer)
            }
            UnderlyingCipher::AesGcmSiv => Err(KmipError::NotSupported(
                "AES GCM SIV is not supported as a stream cipher for now".to_owned(),
            )),
        }
    }

    /// Finalize the encryption and return the ciphertext and the tag.
    pub fn finalize_encryption(&mut self) -> Result<(Vec<u8>, Vec<u8>), KmipError> {
        if self.mode != Mode::Encrypt {
            kmip_bail!(KmipError::Default(
                "finalize_encryption can only be called in encryption mode".to_owned()
            ));
        }
        match self.underlying_cipher {
            UnderlyingCipher::Openssl(ref mut c) => {
                // if there are remaining bytes in the buffer, we need to update once more
                // for XTS this may not be a multiple of the block size, but it must be greater than
                // the block size
                let mut final_bytes = if self.buffer.is_empty() {
                    vec![]
                } else {
                    let mut final_bytes = vec![0; 2 * self.block_size];
                    let len = c.update(&self.buffer, &mut final_bytes)?;
                    final_bytes.truncate(len);
                    final_bytes
                };
                // finalize
                let mut buffer = vec![0; self.block_size];
                let len = c.finalize(&mut buffer)?;
                buffer.truncate(len);
                final_bytes.extend(buffer);
                // Append the tag if it exists and we are encrypting.
                let tag = if self.tag_size > 0 {
                    let mut tag = vec![0; self.tag_size];
                    c.get_tag(&mut tag)?;
                    tag
                } else {
                    vec![]
                };
                Ok((final_bytes, tag))
            }
            UnderlyingCipher::AesGcmSiv => Err(KmipError::NotSupported(
                "AES GCM SIV is not supported as a stream cipher for now".to_owned(),
            )),
        }
    }

    pub fn finalize_decryption(&mut self, tag: &[u8]) -> Result<Vec<u8>, KmipError> {
        if self.mode != Mode::Decrypt {
            kmip_bail!(KmipError::Default(
                "finalize_decryption can only be called in decryption mode".to_owned()
            ));
        }
        match self.underlying_cipher {
            UnderlyingCipher::Openssl(ref mut c) => {
                // if there are remaining bytes in the buffer, we need to update once more
                let mut final_bytes = if self.buffer.is_empty() {
                    vec![]
                } else {
                    let mut final_bytes = vec![0; 2 * self.block_size];
                    let len = c.update(&self.buffer, &mut final_bytes)?;
                    final_bytes.truncate(len);
                    final_bytes
                };
                // Set the tag if it exists and we are decrypting.
                if self.tag_size > 0 {
                    if tag.len() != self.tag_size {
                        kmip_bail!(KmipError::Default(format!(
                            "tag length mismatch. Expected: {}, got: {}",
                            self.tag_size,
                            tag.len()
                        )));
                    }
                    c.set_tag(tag)?;
                }
                // finalize
                let mut buffer = vec![0; self.block_size];
                let len = c.finalize(&mut buffer)?;
                buffer.truncate(len);
                final_bytes.extend(buffer);
                Ok(final_bytes)
            }
            UnderlyingCipher::AesGcmSiv => Err(KmipError::NotSupported(
                "AES GCM SIV is not supported as a stream cipher for now".to_owned(),
            )),
        }
    }
}
