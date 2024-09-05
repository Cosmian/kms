//! The lib is mostly useful for the CLI tests but
//! since it is declared, all the modules in other Files
//! will be resolved against the lib. So everything is exported

#![deny(
    nonstandard_style,
    refining_impl_trait,
    future_incompatible,
    keyword_idents,
    let_underscore,
    rust_2024_compatibility,
    unreachable_pub,
    unused,
    clippy::all,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::pedantic,
    clippy::cargo,

    // restriction lints
    clippy::unwrap_used,
    clippy::get_unwrap,
    clippy::renamed_function_params,
    clippy::verbose_file_reads,
    clippy::str_to_string,
    clippy::string_to_string,
    clippy::unreachable,

)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions
)]

pub mod config;
pub mod core;
pub mod database;
pub mod error;
pub mod kms_server;
pub mod middlewares;
pub mod result;
pub mod routes;
pub mod telemetry;

pub use database::KMSServer;

#[cfg(test)]
mod tests;
