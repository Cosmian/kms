use std::cmp::PartialEq;

use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, PaddingMethod},
    kmip_2_1::kmip_types::CryptographicAlgorithm,
};
use cosmian_logger::trace;
use openssl::{
    rand::rand_bytes,
    symm::{
        Cipher, Crypter, Mode as OpenSslMode, decrypt as openssl_decrypt,
        decrypt_aead as openssl_decrypt_aead, encrypt as openssl_encrypt,
        encrypt_aead as openssl_encrypt_aead,
    },
};
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use super::aes_gcm_siv_not_openssl;
use crate::{
    crypto::symmetric::rfc5649::{rfc5649_unwrap, rfc5649_wrap},
    crypto_bail,
    error::{CryptoError, result::CryptoResult},
};

/// AES 128 CBC key length in bytes.
pub const AES_128_CBC_KEY_LENGTH: usize = 16;
/// AES 128 CBC nonce length in bytes.
pub const AES_128_CBC_IV_LENGTH: usize = 16;
/// AES 128 CBC tag/mac length in bytes.
pub const AES_128_CBC_MAC_LENGTH: usize = 0;

/// AES 256 CBC key length in bytes.
pub const AES_256_CBC_KEY_LENGTH: usize = 32;
/// AES 256 CBC nonce length in bytes.
pub const AES_256_CBC_IV_LENGTH: usize = 16;
/// AES 256 CBC tag/mac length in bytes.
pub const AES_256_CBC_MAC_LENGTH: usize = 0;

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
#[cfg(feature = "non-fips")]
pub const AES_128_GCM_SIV_KEY_LENGTH: usize = 16;
/// AES 128 `GCM_SIV` nonce length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_128_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 128 `GCM_SIV` mac length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_128_GCM_SIV_MAC_LENGTH: usize = 16;
/// AES 256 `GCM_SIV` key length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_256_GCM_SIV_KEY_LENGTH: usize = 32;
/// AES 256 `GCM_SIV` nonce length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_256_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 256 `GCM_SIV` mac length in bytes.
#[cfg(feature = "non-fips")]
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

#[cfg(feature = "non-fips")]
/// Chacha20-Poly1305 key length in bytes.
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
#[cfg(feature = "non-fips")]
/// Chacha20-Poly1305 iv length in bytes.
pub const CHACHA20_POLY1305_IV_LENGTH: usize = 12;
#[cfg(feature = "non-fips")]
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
    Aes256Cbc,
    Aes128Cbc,
    Aes256Gcm,
    Aes128Gcm,
    Aes128Xts,
    Aes256Xts,
    Rfc5649_16,
    Rfc5649_32,
    #[cfg(feature = "non-fips")]
    Aes128GcmSiv,
    #[cfg(feature = "non-fips")]
    Aes256GcmSiv,
    #[cfg(feature = "non-fips")]
    Chacha20Poly1305,
}

impl SymCipher {
    /// Convert to the corresponding OpenSSL cipher.
    fn to_openssl_cipher(self) -> Result<Cipher, CryptoError> {
        match self {
            Self::Aes128Cbc => Ok(Cipher::aes_128_cbc()),
            Self::Aes256Cbc => Ok(Cipher::aes_256_cbc()),
            Self::Aes128Gcm => Ok(Cipher::aes_128_gcm()),
            Self::Aes256Gcm => Ok(Cipher::aes_256_gcm()),
            Self::Aes128Xts => Ok(Cipher::aes_128_xts()),
            Self::Aes256Xts => Ok(Cipher::aes_256_xts()),
            Self::Rfc5649_16 | Self::Rfc5649_32 => {
                crypto_bail!(CryptoError::NotSupported(
                    "RFC5649 is not supported in this version of openssl".to_owned()
                ))
            }
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => Ok(Cipher::chacha20_poly1305()),
            #[cfg(feature = "non-fips")]
            Self::Aes128GcmSiv | Self::Aes256GcmSiv => {
                //TODO: openssl supports AES GCM SIV but the rust openssl crate does not expose it
                crypto_bail!(CryptoError::NotSupported(
                    "AES GCM SIV is not supported in this version of openssl".to_owned()
                ))
            }
        }
    }

    /// Get the tag size in bytes.
    #[must_use]
    pub const fn tag_size(&self) -> usize {
        match self {
            Self::Aes128Cbc => AES_128_CBC_MAC_LENGTH,
            Self::Aes256Cbc => AES_256_CBC_MAC_LENGTH,
            Self::Aes128Gcm => AES_128_GCM_MAC_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_MAC_LENGTH,
            Self::Aes128Xts => AES_128_XTS_MAC_LENGTH,
            Self::Aes256Xts => AES_256_XTS_MAC_LENGTH,
            Self::Rfc5649_16 => RFC5649_16_MAC_LENGTH,
            Self::Rfc5649_32 => RFC5649_32_MAC_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_MAC_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Aes128GcmSiv => AES_128_GCM_SIV_MAC_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Aes256GcmSiv => AES_256_GCM_SIV_MAC_LENGTH,
        }
    }

    /// Get the nonce size in bytes.
    #[must_use]
    pub const fn nonce_size(&self) -> usize {
        match self {
            Self::Aes128Cbc => AES_128_CBC_IV_LENGTH,
            Self::Aes256Cbc => AES_256_CBC_IV_LENGTH,
            Self::Aes128Gcm => AES_128_GCM_IV_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_IV_LENGTH,
            Self::Aes128Xts => AES_128_XTS_TWEAK_LENGTH,
            Self::Aes256Xts => AES_256_XTS_TWEAK_LENGTH,
            Self::Rfc5649_16 => RFC5649_16_IV_LENGTH,
            Self::Rfc5649_32 => RFC5649_32_IV_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_IV_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Aes128GcmSiv => AES_128_GCM_SIV_IV_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Aes256GcmSiv => AES_256_GCM_SIV_IV_LENGTH,
        }
    }

    /// Get the key size in bytes.
    #[must_use]
    pub const fn key_size(&self) -> usize {
        match self {
            Self::Aes128Cbc => AES_128_CBC_KEY_LENGTH,
            Self::Aes256Cbc => AES_256_CBC_KEY_LENGTH,
            Self::Aes128Gcm => AES_128_GCM_KEY_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_KEY_LENGTH,
            Self::Aes128Xts => AES_128_XTS_KEY_LENGTH,
            Self::Aes256Xts => AES_256_XTS_KEY_LENGTH,
            Self::Rfc5649_16 => RFC5649_16_KEY_LENGTH,
            Self::Rfc5649_32 => RFC5649_32_KEY_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_KEY_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Aes128GcmSiv => AES_128_GCM_SIV_KEY_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Aes256GcmSiv => AES_256_GCM_SIV_KEY_LENGTH,
        }
    }

    pub fn from_algorithm_and_key_size(
        algorithm: CryptographicAlgorithm,
        block_cipher_mode: Option<BlockCipherMode>,
        key_size: usize,
    ) -> Result<Self, CryptoError> {
        trace!(
            "algorithm: {algorithm:?}, block_cipher_mode: {block_cipher_mode:?}, key_size: \
             {key_size}"
        );
        match algorithm {
            CryptographicAlgorithm::AES => {
                let block_cipher_mode = block_cipher_mode.unwrap_or(BlockCipherMode::GCM);
                match block_cipher_mode {
                    BlockCipherMode::AEAD | BlockCipherMode::GCM => match key_size {
                        AES_128_GCM_KEY_LENGTH => Ok(Self::Aes128Gcm),
                        AES_256_GCM_KEY_LENGTH => Ok(Self::Aes256Gcm),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "AES key must be 16 or 32 bytes long for AES GCM. Found {key_size} \
                             bytes",
                        ))),
                    },
                    BlockCipherMode::CBC => match key_size {
                        AES_128_CBC_KEY_LENGTH => Ok(Self::Aes128Cbc),
                        AES_256_CBC_KEY_LENGTH => Ok(Self::Aes256Cbc),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "AES key must be 16 or 32 bytes long for AES CBC. Found {key_size} \
                             bytes",
                        ))),
                    },
                    BlockCipherMode::XTS => match key_size {
                        AES_128_XTS_KEY_LENGTH => Ok(Self::Aes128Xts),
                        AES_256_XTS_KEY_LENGTH => Ok(Self::Aes256Xts),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "AES key must be 32 or 64 bytes long for AES XTS. Found {key_size} \
                             bytes",
                        ))),
                    },
                    #[cfg(feature = "non-fips")]
                    BlockCipherMode::GCMSIV => match key_size {
                        AES_128_GCM_SIV_KEY_LENGTH => Ok(Self::Aes128GcmSiv),
                        AES_256_GCM_SIV_KEY_LENGTH => Ok(Self::Aes256GcmSiv),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "AES key must be 16 or 32 bytes long for AES GCM SIV. Found \
                             {key_size} bytes",
                        ))),
                    },
                    BlockCipherMode::NISTKeyWrap => match key_size {
                        RFC5649_16_KEY_LENGTH => Ok(Self::Rfc5649_16),
                        RFC5649_32_KEY_LENGTH => Ok(Self::Rfc5649_32),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "RFC5649 key must be 16 or 32 bytes long. Found {key_size} bytes",
                        ))),
                    },
                    mode => {
                        crypto_bail!(CryptoError::NotSupported(format!(
                            "AES is not supported with mode: {mode:?}"
                        )));
                    }
                }
            }
            #[cfg(feature = "non-fips")]
            CryptographicAlgorithm::ChaCha20 | CryptographicAlgorithm::ChaCha20Poly1305 => {
                match key_size {
                    32 => Ok(Self::Chacha20Poly1305),
                    _ => crypto_bail!(CryptoError::NotSupported(
                        "ChaCha20 key must be 32 bytes long".to_owned()
                    )),
                }
            }
            other => crypto_bail!(CryptoError::NotSupported(format!(
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
    ) -> Result<StreamCipher, CryptoError> {
        StreamCipher::new(*self, mode, key, nonce, aad)
    }
}

/// Generate a random nonce for the given symmetric cipher.
pub fn random_nonce(sym_cipher: SymCipher) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = vec![0; sym_cipher.nonce_size()];
    rand_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Generate a random key for the given symmetric cipher.
pub fn random_key(sym_cipher: SymCipher) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
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
    padding_method: Option<PaddingMethod>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    match sym_cipher {
        SymCipher::Aes128Xts | SymCipher::Aes256Xts => {
            //  XTS mode does not require a tag.
            if plaintext.len() < 16
                && matches!(sym_cipher, SymCipher::Aes128Xts | SymCipher::Aes256Xts)
            {
                return Err(CryptoError::InvalidSize(
                    "Plaintext is too short for XTS block encryption".to_owned(),
                ));
            }
            let ciphertext =
                openssl_encrypt(sym_cipher.to_openssl_cipher()?, key, Some(nonce), plaintext)?;
            Ok((ciphertext, vec![]))
        }
        SymCipher::Aes128Cbc | SymCipher::Aes256Cbc => {
            let padding = padding_method.unwrap_or(PaddingMethod::PKCS5);
            let ciphertext = match padding {
                PaddingMethod::None => {
                    let cipher = sym_cipher.to_openssl_cipher()?;
                    if !plaintext.len().is_multiple_of(cipher.block_size()) {
                        return Err(CryptoError::InvalidSize(
                            "Plaintext must be a multiple of the block size when no padding is \
                             used"
                                .to_owned(),
                        ));
                    }
                    let mut c =
                        Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, Some(nonce))?;
                    c.pad(false);
                    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
                    let count = c.update(plaintext, &mut ciphertext)?;
                    let rest = c.finalize(ciphertext.get_mut(count..).ok_or_else(|| {
                        CryptoError::IndexingSlicing(
                            "sym_ciphers::encrypt: finalize: count..".to_owned(),
                        )
                    })?)?;
                    ciphertext.truncate(count + rest);
                    ciphertext
                }
                PaddingMethod::PKCS5 => {
                    openssl_encrypt(sym_cipher.to_openssl_cipher()?, key, Some(nonce), plaintext)?
                }
                not_supported => {
                    return Err(CryptoError::NotSupported(format!(
                        "Padding method {not_supported:?} is not currently supported"
                    )));
                }
            };
            Ok((ciphertext, vec![]))
        }
        #[cfg(feature = "non-fips")]
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
    padding_method: Option<PaddingMethod>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
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
        SymCipher::Aes128Cbc | SymCipher::Aes256Cbc => {
            let padding = padding_method.unwrap_or(PaddingMethod::PKCS5);
            // CBC mode does not require a tag.
            match padding {
                PaddingMethod::PKCS5 => Zeroizing::from(openssl_decrypt(
                    sym_cipher.to_openssl_cipher()?,
                    key,
                    Some(nonce),
                    ciphertext,
                )?),
                PaddingMethod::None => {
                    let cipher = sym_cipher.to_openssl_cipher()?;
                    if !ciphertext.len().is_multiple_of(cipher.block_size()) {
                        return Err(CryptoError::InvalidSize(
                            "Ciphertext must be a multiple of the block size when no padding is \
                             used"
                                .to_owned(),
                        ));
                    }
                    let mut c =
                        Crypter::new(cipher, openssl::symm::Mode::Decrypt, key, Some(nonce))?;
                    c.pad(false);
                    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
                    let count = c.update(ciphertext, &mut plaintext)?;
                    let rest = c.finalize(plaintext.get_mut(count..).ok_or_else(|| {
                        CryptoError::IndexingSlicing(
                            "sym_ciphers::decrypt: finalize: count..".to_owned(),
                        )
                    })?)?;
                    plaintext.truncate(count + rest);
                    Zeroizing::new(plaintext)
                }
                _ => {
                    return Err(CryptoError::NotSupported(format!(
                        "Padding method {padding:?} is not currently supported"
                    )));
                }
            }
        }
        #[cfg(feature = "non-fips")]
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
    ) -> Result<Self, CryptoError> {
        match sym_cipher {
            #[cfg(feature = "non-fips")]
            SymCipher::Aes128GcmSiv | SymCipher::Aes256GcmSiv => {
                //TODO: the pure Rust crate does not support streaming. When openssl id exposed, this should be fixed
                Err(CryptoError::NotSupported(
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

    pub fn update(&mut self, bytes: &[u8]) -> CryptoResult<Vec<u8>> {
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
                        CryptoError::IndexingSlicing(
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
                        CryptoError::IndexingSlicing(
                            "sym_ciphers: update: len_to_update..".to_owned(),
                        )
                    })?
                    .to_vec();
                Ok(buffer)
            }
            UnderlyingCipher::AesGcmSiv => Err(CryptoError::NotSupported(
                "AES GCM SIV is not supported as a stream cipher for now".to_owned(),
            )),
        }
    }

    /// Finalize the encryption and return the ciphertext and the tag.
    pub fn finalize_encryption(&mut self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if self.mode != Mode::Encrypt {
            crypto_bail!(CryptoError::Default(
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
            UnderlyingCipher::AesGcmSiv => Err(CryptoError::NotSupported(
                "AES GCM SIV is not supported as a stream cipher for now".to_owned(),
            )),
        }
    }

    pub fn finalize_decryption(&mut self, tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.mode != Mode::Decrypt {
            crypto_bail!(CryptoError::Default(
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
                        crypto_bail!(CryptoError::Default(format!(
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
            UnderlyingCipher::AesGcmSiv => Err(CryptoError::NotSupported(
                "AES GCM SIV is not supported as a stream cipher for now".to_owned(),
            )),
        }
    }
}
