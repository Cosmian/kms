//! The lib is mostly useful for the CLI tests but
//! since it is declared, all the modules in other Files
//! will be resolved against the lib. So everything is exported

pub mod config;
pub mod core;
pub mod cron;
pub mod error;
pub mod middlewares;
pub mod openssl_providers;
pub mod result;
pub mod routes;
pub mod socket_server;
pub mod start_kms_server;
pub mod tls_config;

#[expect(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    clippy::cognitive_complexity,
    unsafe_code,
    clippy::indexing_slicing,
    dead_code
)]
#[cfg(test)]
pub mod tests;
