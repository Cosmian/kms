#[cfg(feature = "non-fips")]
pub mod ecies;
pub mod operation;
pub mod sign;
pub mod verify;

// Montgomery curves key length.
pub const X25519_PRIVATE_KEY_LENGTH: usize = 0x20;
pub const X25519_PUBLIC_KEY_LENGTH: usize = 0x20;
pub const X448_PRIVATE_KEY_LENGTH: usize = 0x38;
pub const X448_PUBLIC_KEY_LENGTH: usize = 0x38;

// Edwards curves key length.
pub const ED25519_PRIVATE_KEY_LENGTH: usize = 0x20;
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 0x20;
pub const ED448_PRIVATE_KEY_LENGTH: usize = 0x39;
pub const ED448_PUBLIC_KEY_LENGTH: usize = 0x39;

pub const CURVE_25519_Q_LENGTH_BITS: i32 = 253;
