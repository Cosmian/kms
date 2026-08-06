pub mod config;
pub mod error;
pub mod service;

#[allow(
    unreachable_pub,
    clippy::derive_partial_eq_without_eq,
    clippy::empty_structs_with_brackets,
    clippy::missing_const_for_fn,
    clippy::default_trait_access,
    clippy::as_conversions,
    clippy::use_self,
    clippy::doc_markdown
)]
pub mod v1alpha1 {
    include!("provider.rs");
}
