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
#[cfg(windows)]
pub mod windows_service;

#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
#[cfg(test)]
pub mod tests;

#[cfg(test)]
mod lint_cleanup_core_characterization_tests;
#[cfg(test)]
mod lint_cleanup_routes_characterization_tests;
