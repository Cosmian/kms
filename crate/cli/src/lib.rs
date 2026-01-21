pub mod actions;
pub mod error;

pub mod reexport {
    pub use cosmian_kmip;
    pub use cosmian_kms_client;
    pub use cosmian_kms_crypto;
}

// Clippy lints that are allowed in tests
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::implicit_clone,
    clippy::str_to_string,
    clippy::large_stack_frames,
    clippy::ignore_without_reason,
    dead_code,
    clippy::unwrap_in_result,
    clippy::as_conversions
)]
mod tests;
