#![allow(deprecated)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::str_to_string)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_in_result)]
#![allow(clippy::assertions_on_result_states)]
#![allow(clippy::panic_in_result_fn)]

use std::{env, path::Path};

use cosmian_config_utils::ConfigUtils;
use test_kms_server::TestsContext;

use crate::config::ClientConfig;

mod ensure_binary;
pub(crate) mod kms;

// Re-export the ensure function for all tests to use
pub(crate) use ensure_binary::ensure_ckms_binary;

// Ensure ckms binary is built when test module loads
// This runs once before any tests in this module execute
#[allow(dead_code)]
static ENSURE_BINARY_ON_LOAD: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
    ensure_ckms_binary();
});

/// Force initialization of binary builder on module load
/// This test runs automatically and ensures other tests have the binary available
#[test]
fn ensure_binary_built() {
    // Access the lazy lock to trigger binary build
    *ENSURE_BINARY_ON_LOAD;
}

pub(crate) const PROG_NAME: &str = "ckms";

/// Create a Command for the ckms binary, ensuring it's built first
/// Use this instead of `Command::cargo_bin()` directly in tests
#[allow(dead_code)]
pub(crate) fn ckms_command() -> std::process::Command {
    use assert_cmd::cargo::CommandCargoExt;

    // Access the lazy lock to ensure binary is built
    *ENSURE_BINARY_ON_LOAD;

    std::process::Command::cargo_bin(PROG_NAME).expect("Failed to find ckms binary")
}

pub(crate) fn save_kms_cli_config(kms_ctx: &TestsContext) -> (String, String) {
    // Ensure binary is built before any test that uses it
    ensure_ckms_binary();

    let owner_file_path = env::temp_dir()
        .join(format!("owner_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    if !Path::new(&owner_file_path).exists() {
        let conf = ClientConfig {
            kms_config: kms_ctx.owner_client_config.clone(),
        };
        conf.to_toml(&owner_file_path)
            .expect("Failed to save owner test config");
    }

    let user_file_path = env::temp_dir()
        .join(format!("user_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    if !Path::new(&user_file_path).exists() {
        let conf = ClientConfig {
            kms_config: kms_ctx.user_client_config.clone(),
        };
        conf.to_toml(&user_file_path)
            .expect("Failed to save user test config");
    }

    (owner_file_path, user_file_path)
}

#[allow(dead_code)]
pub(crate) fn force_save_kms_cli_config(kms_ctx: &TestsContext) -> (String, String) {
    // Ensure binary is built before any test that uses it
    ensure_ckms_binary();

    let owner_file_path = env::temp_dir()
        .join(format!("owner_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: kms_ctx.owner_client_config.clone(),
    };
    conf.to_toml(&owner_file_path)
        .expect("Failed to save owner test config");

    let user_file_path = env::temp_dir()
        .join(format!("user_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: kms_ctx.user_client_config.clone(),
    };
    conf.to_toml(&user_file_path)
        .expect("Failed to save user test config");

    (owner_file_path, user_file_path)
}
