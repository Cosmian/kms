//! The lib is mostly useful for the CLI tests but
//! since it is declared, all the modules in other Files
//! will be resolved against the lib. So everything is exported

pub mod bootstrap_server;
pub mod config;
pub mod core;
pub mod database;
pub mod error;
pub mod kms_server;
pub mod log_utils;
pub mod middlewares;
pub mod result;
pub mod routes;
pub use database::KMSServer;

#[cfg(test)]
mod tests;
