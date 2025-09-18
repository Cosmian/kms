pub mod actions;
pub mod error;

pub mod reexport {
    pub use cosmian_kmip;
    pub use cosmian_kms_client;
    pub use cosmian_kms_crypto;
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::implicit_clone,
    clippy::str_to_string,
    clippy::unwrap_in_result
)]
mod tests;
