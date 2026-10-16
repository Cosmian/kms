// Test fixtures draw throw-away data from non-`KmsRng` generators; production code stays under
// the `clippy.toml` bans (see ADR 2026-10-10).
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        clippy::disallowed_types,
        reason = "test fixtures only; production code must use KmsRng"
    )
)]

pub mod actions;
pub mod commands;
pub mod config;
pub mod error;
pub mod headers_config;
pub mod proxy_config;

pub use commands::{Cli, CliCommands, ckms_main};

pub mod reexport {
    pub use cosmian_kms_cli_actions;
}

#[cfg(all(test, feature = "non-fips"))]
mod tests;
