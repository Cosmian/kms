#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::str_to_string))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(clippy::unwrap_in_result))]
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]
#![cfg_attr(test, allow(clippy::panic_in_result_fn))]
#![cfg_attr(test, allow(clippy::unseparated_literal_suffix))]

pub mod actions;
pub mod commands;
pub mod config;
pub mod error;
pub mod proxy_config;

pub use commands::{Cli, CliCommands, cosmian_main};

pub mod reexport {
    pub use cosmian_kms_cli;
}

#[cfg(all(test, feature = "non-fips"))]
mod tests;
