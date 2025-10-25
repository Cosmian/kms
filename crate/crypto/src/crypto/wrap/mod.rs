mod common;
#[allow(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    clippy::unwrap_in_result,
    clippy::expect_used
)]
#[cfg(test)]
mod tests;
mod unwrap_key;
mod wrap_key;

const WRAPPING_SECRET_LENGTH: usize = 32;

pub use unwrap_key::{aes_gcm_decrypt, decode_unwrapped_key, unwrap_key_block, unwrap_key_bytes};
pub use wrap_key::{key_data_to_wrap, wrap_key_bytes, wrap_object_with_key};
