// Test fixtures draw throw-away data from non-`KmsRng` generators; production code stays under
// the `clippy.toml` bans (see ADR 2026-10-10).
#![cfg_attr(
    test,
    expect(
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

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests;
