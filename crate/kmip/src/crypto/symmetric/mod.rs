mod symmetric_key;
pub use symmetric_key::{create_symmetric_key_kmip_object, symmetric_key_create_request};
mod aes_256_gcm;
pub use aes_256_gcm::AesGcmSystem;

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

pub mod aead;
pub mod rfc5649;
#[cfg(test)]
mod tests;
