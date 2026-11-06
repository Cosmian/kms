pub mod config;
pub mod error;
pub mod service;

// result_large_err is a false positive here: tonic::Status (176 bytes) is the fixed error type
// of every generated gRPC method, and generated code cannot box it.
#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::empty_structs_with_brackets,
    clippy::missing_const_for_fn,
    clippy::default_trait_access,
    clippy::as_conversions,
    clippy::doc_markdown,
    clippy::result_large_err,
    reason = "prost/tonic-generated code (src/*.proto)"
)]
pub mod v1alpha1 {
    include!("provider.rs");
}
