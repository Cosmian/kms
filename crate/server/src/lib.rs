//! The lib is mostly useful for the CLI tests but
//! since it is declared, all the modules in other Files
//! will be resolved against the lib. So everything is exported

pub mod config;
pub mod core;
pub mod error;
pub mod middlewares;
pub mod result;
pub mod routes;
pub mod socket_server;
pub mod start_kms_server;
#[allow(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::expect_used,
    unsafe_code,
    clippy::indexing_slicing
)]
#[cfg(test)]
mod tests;
pub mod tls_config;
