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
