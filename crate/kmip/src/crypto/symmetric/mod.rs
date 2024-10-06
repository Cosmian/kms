mod symmetric_key;
pub use symmetric_key::{create_symmetric_key_kmip_object, symmetric_key_create_request};

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

/// AES KEY WRAP with padding key length in bytes.
pub const AES_KWP_KEY_LENGTH: usize = 0x20;

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

/// AES 128 GCM_SIV key length in bytes.
pub const AES_128_GCM_SIV_KEY_LENGTH: usize = 16;
/// AES 128 GCM_SIV nonce length in bytes.
pub const AES_128_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 128 GCM_SIV has no authentication.
pub const AES_128_GCM_SIV_MAC_LENGTH: usize = 16;
/// AES 256 GCM_SIV key length in bytes.
pub const AES_256_GCM_SIV_KEY_LENGTH: usize = 32;
/// AES 256 GCM_SIV nonce length in bytes.
pub const AES_256_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 256 GCM_SIV has no authentication.
pub const AES_256_GCM_SIV_MAC_LENGTH: usize = 16;

pub mod symmetric_ciphers;

pub mod rfc5649;

#[cfg(not(feature = "fips"))]
mod aes_gcm_siv_not_openssl;
#[cfg(test)]
mod tests;
