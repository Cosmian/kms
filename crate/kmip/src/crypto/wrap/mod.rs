mod common;
#[cfg(test)]
mod tests;
#[cfg(feature = "openssl")]
mod unwrap_key;
#[cfg(feature = "openssl")]
mod wrap_key;

const WRAPPING_SECRET_LENGTH: usize = 32;

#[cfg(feature = "openssl")]
pub use unwrap_key::{unwrap_key_block, unwrap_key_bytes};
#[cfg(feature = "openssl")]
pub use wrap_key::{wrap_key_block, wrap_key_bytes};
