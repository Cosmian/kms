pub mod config;
pub mod error;
pub mod service;

#[cfg(all(test, unix))]
pub mod integration_tests;

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::empty_structs_with_brackets,
    clippy::missing_const_for_fn,
    clippy::default_trait_access,
    clippy::as_conversions,
    clippy::doc_markdown,
    reason = "prost/tonic-generated code (src/*.proto)"
)]
pub mod kmsv2 {
    include!("v2.rs");
}
