#![deny(
    nonstandard_style,
    refining_impl_trait,
    future_incompatible,
    keyword_idents,
    let_underscore,
    // rust_2024_compatibility,
    unreachable_pub,
    unused,
    clippy::all,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::pedantic,
    clippy::cargo,
    clippy::nursery,

    // restriction lints
    clippy::map_err_ignore,
    clippy::print_stdout,
    clippy::redundant_clone
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::too_many_lines,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate
)]
pub mod actions;
pub mod commands;
pub mod error;

pub use commands::{ckms_main, KmsActions, KmsOptions};

pub mod reexport {
    pub use cosmian_kms_client;
}

#[cfg(test)]
mod tests;
