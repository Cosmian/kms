mod common;
#[allow(clippy::unwrap_used, clippy::panic_in_result_fn)]
#[cfg(test)]
mod tests;
mod unwrap_key;
mod wrap_key;

const WRAPPING_SECRET_LENGTH: usize = 32;

pub use unwrap_key::{
    recover_wrapped_key, unwrap_key_block, unwrap_key_bytes, update_key_block_with_unwrapped_key,
};
pub use wrap_key::{
    key_data_to_wrap, update_key_block_with_wrapped_key, wrap_key_block, wrap_key_bytes,
};
