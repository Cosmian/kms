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
