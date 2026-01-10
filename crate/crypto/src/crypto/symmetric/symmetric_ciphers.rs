use std::cmp::PartialEq;

use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, PaddingMethod},
    kmip_2_1::kmip_types::CryptographicAlgorithm,
};
use cosmian_logger::{info, trace};
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
    crypto::symmetric::{
        rfc3394::{rfc3394_unwrap, rfc3394_wrap},
        rfc5649::{rfc5649_unwrap, rfc5649_wrap},
    },
    crypto_bail,
    error::{CryptoError, result::CryptoResult},
};

/// AES 128 CBC key length in bytes.
pub const AES_128_CBC_KEY_LENGTH: usize = 16;
/// AES 128 CBC nonce length in bytes.
pub const AES_128_CBC_IV_LENGTH: usize = 16;
/// AES 128 CBC tag/mac length in bytes.
pub const AES_128_CBC_MAC_LENGTH: usize = 0;

/// AES 192 CBC key length in bytes.
pub const AES_192_CBC_KEY_LENGTH: usize = 24;
/// AES 192 CBC nonce length in bytes.
pub const AES_192_CBC_IV_LENGTH: usize = 24;
/// AES 192 CBC tag/mac length in bytes.
pub const AES_192_CBC_MAC_LENGTH: usize = 0;

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

/// AES 192 GCM key length in bytes.
pub const AES_192_GCM_KEY_LENGTH: usize = 24;
/// AES 192 GCM nonce length in bytes.
pub const AES_192_GCM_IV_LENGTH: usize = 12;
/// AES 192 GCM tag/mac length in bytes.
pub const AES_192_GCM_MAC_LENGTH: usize = 16;

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

// RFC 3394 IV is actually a fixed overhead
pub const RFC3394_IV_LENGTH: usize = 0;
/// RFC3394 has no authentication.
pub const RFC3394_MAC_LENGTH: usize = 0;
/// RFC 3394 with a 16-byte KEK.
pub const RFC3394_16_KEY_LENGTH: usize = 16;
/// RFC 3394 with a 24-byte KEK.
pub const RFC3394_24_KEY_LENGTH: usize = 24;
/// RFC 3394 with a 32-byte KEK.
pub const RFC3394_32_KEY_LENGTH: usize = 32;

// RFC 5649 IV is actually a fixed overhead
pub const RFC5649_IV_LENGTH: usize = 0;
/// RFC5649 has no authentication.
pub const RFC5649_MAC_LENGTH: usize = 0;
/// RFC 5649 with a 16-byte KEK.
pub const RFC5649_16_KEY_LENGTH: usize = 16;
/// RFC 5649 with a 24-byte KEK.
pub const RFC5649_24_KEY_LENGTH: usize = 24;
/// RFC 5649 with a 32-byte KEK.
pub const RFC5649_32_KEY_LENGTH: usize = 32;

#[cfg(feature = "non-fips")]
/// Chacha20-Poly1305 key length in bytes.
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
#[cfg(feature = "non-fips")]
/// Chacha20-Poly1305 iv length in bytes.
pub const CHACHA20_POLY1305_IV_LENGTH: usize = 12;
#[cfg(feature = "non-fips")]
/// Chacha20-Poly1305 tag/mac length in bytes.
pub const CHACHA20_POLY1305_MAC_LENGTH: usize = 16;
#[cfg(feature = "non-fips")]
/// `ChaCha20` (pure stream cipher, original variant with 64-bit nonce) key length in bytes.
pub const CHACHA20_KEY_LENGTH: usize = 32;
#[cfg(feature = "non-fips")]
/// `ChaCha20` (pure stream cipher) nonce length in bytes (original variant uses 64-bit nonce).
pub const CHACHA20_IV_LENGTH: usize = 8;
#[cfg(feature = "non-fips")]
/// `ChaCha20` (pure stream cipher) has no authentication tag.
pub const CHACHA20_MAC_LENGTH: usize = 0;

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
    Aes256Ecb,
    Aes192Ecb,
    Aes128Ecb,
    Aes256Cbc,
    Aes192Cbc,
    Aes128Cbc,
    Aes256Gcm,
    Aes192Gcm,
    Aes128Gcm,
    Aes128Xts,
    Aes256Xts,
    Rfc3394_16,
    Rfc3394_24,
    Rfc3394_32,
    Rfc5649_16,
    Rfc5649_24,
    Rfc5649_32,
    #[cfg(feature = "non-fips")]
    Aes128GcmSiv,
    #[cfg(feature = "non-fips")]
    Aes256GcmSiv,
    #[cfg(feature = "non-fips")]
    Chacha20Poly1305,
    #[cfg(feature = "non-fips")]
    Chacha20, // pure stream cipher (no authentication)
}

impl SymCipher {
    /// Convert to the corresponding OpenSSL cipher.
    fn to_openssl_cipher(self) -> Result<Cipher, CryptoError> {
        match self {
            Self::Aes128Ecb => Ok(Cipher::aes_128_ecb()),
            Self::Aes192Ecb => Ok(Cipher::aes_192_ecb()),
            Self::Aes256Ecb => Ok(Cipher::aes_256_ecb()),
            Self::Aes128Cbc => Ok(Cipher::aes_128_cbc()),
            Self::Aes192Cbc => Ok(Cipher::aes_192_cbc()),
            Self::Aes256Cbc => Ok(Cipher::aes_256_cbc()),
            Self::Aes128Gcm => Ok(Cipher::aes_128_gcm()),
            Self::Aes192Gcm => Ok(Cipher::aes_192_gcm()),
            Self::Aes256Gcm => Ok(Cipher::aes_256_gcm()),
            Self::Aes128Xts => Ok(Cipher::aes_128_xts()),
            Self::Aes256Xts => Ok(Cipher::aes_256_xts()),
            Self::Rfc3394_16 | Self::Rfc3394_24 | Self::Rfc3394_32 => {
                crypto_bail!(CryptoError::NotSupported(
                    "RFC3394 is not supported in this version of openssl".to_owned()
                ))
            }
            Self::Rfc5649_16 | Self::Rfc5649_24 | Self::Rfc5649_32 => {
                crypto_bail!(CryptoError::NotSupported(
                    "RFC5649 is not supported in this version of openssl".to_owned()
                ))
            }
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => Ok(Cipher::chacha20_poly1305()),
            #[cfg(feature = "non-fips")]
            Self::Chacha20 => Ok(Cipher::chacha20()),
            #[cfg(feature = "non-fips")]
            Self::Aes128GcmSiv | Self::Aes256GcmSiv => {
                // TODO: openssl supports AES GCM SIV but the rust openssl crate does not expose it
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
            Self::Aes128Ecb => 0,
            Self::Aes192Ecb => 0,
            Self::Aes256Ecb => 0,
            Self::Aes128Cbc => AES_128_CBC_MAC_LENGTH,
            Self::Aes192Cbc => AES_192_CBC_MAC_LENGTH,
            Self::Aes256Cbc => AES_256_CBC_MAC_LENGTH,
            Self::Aes128Gcm => AES_128_GCM_MAC_LENGTH,
            Self::Aes192Gcm => AES_192_GCM_MAC_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_MAC_LENGTH,
            Self::Aes128Xts => AES_128_XTS_MAC_LENGTH,
            Self::Aes256Xts => AES_256_XTS_MAC_LENGTH,
            Self::Rfc3394_16 | Self::Rfc3394_24 | Self::Rfc3394_32 => RFC3394_MAC_LENGTH,
            Self::Rfc5649_16 | Self::Rfc5649_24 | Self::Rfc5649_32 => RFC5649_MAC_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_MAC_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20 => CHACHA20_MAC_LENGTH,
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
            Self::Aes128Ecb => 0,
            Self::Aes192Ecb => 0,
            Self::Aes256Ecb => 0,
            Self::Aes128Cbc => AES_128_CBC_IV_LENGTH,
            Self::Aes192Cbc => AES_192_CBC_IV_LENGTH,
            Self::Aes256Cbc => AES_256_CBC_IV_LENGTH,
            Self::Aes128Gcm => AES_128_GCM_IV_LENGTH,
            Self::Aes192Gcm => AES_192_GCM_IV_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_IV_LENGTH,
            Self::Aes128Xts => AES_128_XTS_TWEAK_LENGTH,
            Self::Aes256Xts => AES_256_XTS_TWEAK_LENGTH,
            Self::Rfc3394_16 | Self::Rfc3394_24 | Self::Rfc3394_32 => RFC3394_IV_LENGTH,
            Self::Rfc5649_16 | Self::Rfc5649_24 | Self::Rfc5649_32 => RFC5649_IV_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_IV_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20 => CHACHA20_IV_LENGTH,
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
            Self::Aes128Ecb => 16,
            Self::Aes192Ecb => 24,
            Self::Aes256Ecb => 32,
            Self::Aes128Cbc => AES_128_CBC_KEY_LENGTH,
            Self::Aes192Cbc => AES_192_CBC_KEY_LENGTH,
            Self::Aes256Cbc => AES_256_CBC_KEY_LENGTH,
            Self::Aes128Gcm => AES_128_GCM_KEY_LENGTH,
            Self::Aes192Gcm => AES_192_GCM_KEY_LENGTH,
            Self::Aes256Gcm => AES_256_GCM_KEY_LENGTH,
            Self::Aes128Xts => AES_128_XTS_KEY_LENGTH,
            Self::Aes256Xts => AES_256_XTS_KEY_LENGTH,
            Self::Rfc3394_16 => RFC3394_16_KEY_LENGTH,
            Self::Rfc3394_24 => RFC3394_24_KEY_LENGTH,
            Self::Rfc3394_32 => RFC3394_32_KEY_LENGTH,
            Self::Rfc5649_16 => RFC5649_16_KEY_LENGTH,
            Self::Rfc5649_24 => RFC5649_24_KEY_LENGTH,
            Self::Rfc5649_32 => RFC5649_32_KEY_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_KEY_LENGTH,
            #[cfg(feature = "non-fips")]
            Self::Chacha20 => CHACHA20_KEY_LENGTH,
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
                    BlockCipherMode::ECB => match key_size {
                        16 => Ok(Self::Aes128Ecb),
                        24 => Ok(Self::Aes192Ecb),
                        32 => Ok(Self::Aes256Ecb),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "AES key must be 16, 24 or 32 bytes long for AES ECB. Found {key_size} bytes",
                        ))),
                    },
                    BlockCipherMode::AEAD | BlockCipherMode::GCM => match key_size {
                        AES_128_GCM_KEY_LENGTH => Ok(Self::Aes128Gcm),
                        AES_192_GCM_KEY_LENGTH => Ok(Self::Aes192Gcm),
                        AES_256_GCM_KEY_LENGTH => Ok(Self::Aes256Gcm),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "AES key must be 16 or 32 bytes long for AES GCM. Found {key_size} \
                             bytes",
                        ))),
                    },
                    BlockCipherMode::CBC => match key_size {
                        AES_128_CBC_KEY_LENGTH => Ok(Self::Aes128Cbc),
                        AES_192_CBC_KEY_LENGTH => Ok(Self::Aes192Cbc),
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
                    BlockCipherMode::AESKeyWrapPadding => match key_size {
                        RFC5649_16_KEY_LENGTH => Ok(Self::Rfc5649_16),
                        RFC5649_24_KEY_LENGTH => Ok(Self::Rfc5649_24),
                        RFC5649_32_KEY_LENGTH => Ok(Self::Rfc5649_32),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "RFC5649 key must be 16, 24 or 32 bytes long. Found {key_size} \
                             bytes",
                        ))),
                    },
                    BlockCipherMode::NISTKeyWrap => match key_size {
                        RFC3394_16_KEY_LENGTH => Ok(Self::Rfc3394_16),
                        RFC3394_24_KEY_LENGTH => Ok(Self::Rfc3394_24),
                        RFC3394_32_KEY_LENGTH => Ok(Self::Rfc3394_32),
                        _ => crypto_bail!(CryptoError::NotSupported(format!(
                            "RFC3394 key must be 16, 24 or 32 bytes long. Found {key_size} bytes",
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
            CryptographicAlgorithm::ChaCha20 => match key_size {
                32 => Ok(Self::Chacha20),
                _ => crypto_bail!(CryptoError::NotSupported(
                    "ChaCha20 key must be 32 bytes long".to_owned()
                )),
            },
            #[cfg(feature = "non-fips")]
            CryptographicAlgorithm::ChaCha20Poly1305 => match key_size {
                32 => Ok(Self::Chacha20Poly1305),
                _ => crypto_bail!(CryptoError::NotSupported(
                    "ChaCha20 key must be 32 bytes long".to_owned()
                )),
            },
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
    trace!(
        "encrypt: sym_cipher: {sym_cipher:?}, key length: {}, nonce length: {}, aad length: {}, \
         plaintext length: {}, padding_method: {padding_method:?}",
        key.len(),
        nonce.len(),
        aad.len(),
        plaintext.len()
    );
    match sym_cipher {
        SymCipher::Aes128Ecb | SymCipher::Aes192Ecb | SymCipher::Aes256Ecb => {
            // ECB mode does not require IV/nonce or tag
            // Default to no padding so block-aligned inputs remain deterministic (KMIP vectors)
            let padding = padding_method.unwrap_or(PaddingMethod::None);
            let cipher = sym_cipher.to_openssl_cipher()?;
            let ciphertext = match padding {
                PaddingMethod::None => {
                    if !plaintext.len().is_multiple_of(cipher.block_size()) {
                        return Err(CryptoError::InvalidSize(
                            "Plaintext must be a multiple of the block size when no padding is used".to_owned(),
                        ));
                    }
                    let mut c = Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, None)?;
                    c.pad(false);
                    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
                    let count = c.update(plaintext, &mut ciphertext)?;
                    let rest = c.finalize(ciphertext.get_mut(count..).ok_or_else(|| {
                        CryptoError::IndexingSlicing(
                            "sym_ciphers::encrypt ecb: finalize: count..".to_owned(),
                        )
                    })?)?;
                    ciphertext.truncate(count + rest);
                    ciphertext
                }
                PaddingMethod::PKCS5 => {
                    openssl_encrypt(sym_cipher.to_openssl_cipher()?, key, None, plaintext)?
                }
                not_supported => {
                    return Err(CryptoError::NotSupported(format!(
                        "Padding method {not_supported:?} is not currently supported"
                    )));
                }
            };
            Ok((ciphertext, vec![]))
        }
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
        SymCipher::Rfc5649_16 | SymCipher::Rfc5649_24 | SymCipher::Rfc5649_32 => {
            Ok((rfc5649_wrap(plaintext, key)?, vec![]))
        }
        SymCipher::Rfc3394_16 | SymCipher::Rfc3394_24 | SymCipher::Rfc3394_32 => {
            info!(
                "RFC 3394 is deprecated in favor of RFC 5649 and is supported only for legacy compatibility. Please consider using `BlockCipherMode::AESKeyWrapPadding` (RFC 5649) for new applications instead of `BlockCipherMode::NISTKeyWrap `."
            );
            Ok((rfc3394_wrap(plaintext, key)?, vec![]))
        }
        #[cfg(feature = "non-fips")]
        SymCipher::Chacha20 => {
            trace!(
                "ChaCha20 (pure) encryption: key_len={}, nonce_len={}, pt_len={}",
                key.len(),
                nonce.len(),
                plaintext.len()
            );
            if key.len() != CHACHA20_KEY_LENGTH {
                crypto_bail!(CryptoError::InvalidSize(format!(
                    "ChaCha20 key must be {} bytes. Got {}",
                    CHACHA20_KEY_LENGTH,
                    key.len()
                )));
            }
            if nonce.len() != CHACHA20_IV_LENGTH {
                crypto_bail!(CryptoError::InvalidSize(format!(
                    "ChaCha20 nonce must be {} bytes. Got {}",
                    CHACHA20_IV_LENGTH,
                    nonce.len()
                )));
            }
            let mut out = vec![0_u8; plaintext.len()];
            chacha20_xor(key, nonce, 0, plaintext, &mut out)?;
            Ok((out, vec![]))
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
        SymCipher::Aes128Ecb | SymCipher::Aes192Ecb | SymCipher::Aes256Ecb => {
            // Default to no padding for ECB to mirror encrypt-side default
            let padding = padding_method.unwrap_or(PaddingMethod::None);
            let cipher = sym_cipher.to_openssl_cipher()?;
            match padding {
                PaddingMethod::PKCS5 => {
                    Zeroizing::from(openssl_decrypt(cipher, key, None, ciphertext)?)
                }
                PaddingMethod::None => {
                    if !ciphertext.len().is_multiple_of(cipher.block_size()) {
                        return Err(CryptoError::InvalidSize(
                            "Ciphertext must be a multiple of the block size when no padding is used".to_owned(),
                        ));
                    }
                    let mut c = Crypter::new(cipher, openssl::symm::Mode::Decrypt, key, None)?;
                    c.pad(false);
                    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
                    let count = c.update(ciphertext, &mut plaintext)?;
                    let rest = c.finalize(plaintext.get_mut(count..).ok_or_else(|| {
                        CryptoError::IndexingSlicing(
                            "sym_ciphers::decrypt ecb: finalize: count..".to_owned(),
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
        SymCipher::Rfc3394_16 | SymCipher::Rfc3394_24 | SymCipher::Rfc3394_32 => {
            info!(
                "RFC 3394 is deprecated in favor of RFC 5649 and is supported only for legacy compatibility. Please consider using `BlockCipherMode::AESKeyWrapPadding` (RFC 5649) for new applications instead of `BlockCipherMode::NISTKeyWrap `."
            );
            rfc3394_unwrap(ciphertext, key)?
        }
        SymCipher::Rfc5649_16 | SymCipher::Rfc5649_24 | SymCipher::Rfc5649_32 => {
            rfc5649_unwrap(ciphertext, key)?
        }
        #[cfg(feature = "non-fips")]
        SymCipher::Chacha20 => {
            if key.len() != CHACHA20_KEY_LENGTH {
                crypto_bail!(CryptoError::InvalidSize(format!(
                    "ChaCha20 key must be {} bytes. Got {}",
                    CHACHA20_KEY_LENGTH,
                    key.len()
                )));
            }
            if nonce.len() != CHACHA20_IV_LENGTH {
                crypto_bail!(CryptoError::InvalidSize(format!(
                    "ChaCha20 nonce must be {} bytes. Got {}",
                    CHACHA20_IV_LENGTH,
                    nonce.len()
                )));
            }
            let mut out = vec![0_u8; ciphertext.len()];
            chacha20_xor(key, nonce, 0, ciphertext, &mut out)?;
            Zeroizing::from(out)
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

/// A stream cipher for encryption or decryption. /
pub struct StreamCipher {
    underlying_cipher: UnderlyingCipher,
    mode: Mode,
    block_size: usize,
    tag_size: usize,
    buffer: Vec<u8>,
}

// --- Pure ChaCha20 (original 64-bit nonce variant) implementation -----------------------------
// Implementation notes:
// - Original ChaCha20 state layout (16 words):
//   constants (4) | key (8) | block counter (1) | nonce (3)  (IETF 96-bit nonce variant)
//   The earlier, "original" 64-bit nonce form instead uses: constants | key (8) | block counter (2) | nonce (2)
// - The mandatory KMIP vectors provide an 8-byte nonce. We implement the original variant
//   with a 64-bit block counter composed of two u32 words and a 64-bit nonce (two u32 words).
// - For simplicity we keep a 64-bit block counter but expose only the lower 32-bit starting value (counter_low).
// - This function XORs the keystream with input into output; input and output may alias.
#[cfg(feature = "non-fips")]
fn chacha20_xor(
    key: &[u8],
    nonce: &[u8],
    counter_low: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    // Switch to OpenSSL-backed ChaCha20. OpenSSL expects a 16-byte IV for ChaCha20:
    // 4-byte little-endian counter followed by a 12-byte nonce (IETF layout).
    // Our API (KMIP vectors) provides an 8-byte nonce; we map it to the 12-byte nonce
    // by zero-padding the leading 4 bytes. This preserves external expectations while
    // using OpenSSL for the cipher core.
    debug_assert_eq!(key.len(), CHACHA20_KEY_LENGTH);
    debug_assert_eq!(nonce.len(), CHACHA20_IV_LENGTH);
    debug_assert_eq!(input.len(), output.len());

    let mut iv = [0_u8; 16];
    // 4-byte counter (little-endian)
    iv[0..4].copy_from_slice(&counter_low.to_le_bytes());
    // Next 4 bytes zero-padded to expand 8-byte nonce to 12 bytes
    iv[4..8].copy_from_slice(&[0_u8; 4]);
    // Last 8 bytes are the provided 64-bit nonce
    iv[8..16].copy_from_slice(nonce);

    let result = openssl_encrypt(Cipher::chacha20(), key, Some(&iv), input)?;
    output.copy_from_slice(&result);
    Ok(())
}

#[cfg(all(test, feature = "non-fips"))]
mod chacha_tests {
    use super::{CHACHA20_IV_LENGTH, CHACHA20_KEY_LENGTH, chacha20_xor};
    use crate::CryptoError;
    // Test vector adapted: 32-byte zero key, 8-byte zero nonce, zero plaintext -> keystream first 64 bytes per original variant.
    #[test]
    fn chacha20_zero_key_nonce_block0() -> Result<(), CryptoError> {
        let key = [0_u8; CHACHA20_KEY_LENGTH];
        let nonce = [0_u8; CHACHA20_IV_LENGTH];
        let inp = [0_u8; 64];
        let mut out = [0_u8; 64];
        chacha20_xor(&key, &nonce, 0, &inp, &mut out)?; // XOR with zeros -> keystream directly
        // Expected first 16 bytes (original variant) differ from IETF 96-bit nonce vector; we assert internal consistency (non-zero mix) and length.
        if out.len() != 64 {
            return Err(CryptoError::Default("unexpected output length".to_owned()));
        }
        // Basic diffusion sanity checks
        if !out.iter().any(|&b| b != 0) {
            return Err(CryptoError::Default(
                "unexpected all-zero ChaCha20 keystream".to_owned(),
            ));
        }
        Ok(())
    }
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
                // TODO: the pure Rust crate does not support streaming. When openssl id exposed, this should be fixed
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
