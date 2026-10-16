// Test fixtures draw throw-away data from non-`KmsRng` generators; production code stays under
// the `clippy.toml` bans (see ADR 2026-10-10).
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        clippy::disallowed_types,
        reason = "test fixtures only; production code must use KmsRng"
    )
)]

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
    clippy::unwrap_in_result,
    clippy::as_conversions
)]
mod tests;
