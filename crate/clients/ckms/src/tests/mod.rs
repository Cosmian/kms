#![allow(deprecated)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::str_to_string)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_in_result)]
#![allow(clippy::assertions_on_result_states)]
#![allow(clippy::panic_in_result_fn)]

use std::{env, path::Path, sync::Mutex};

use cosmian_config_utils::ConfigUtils;
use test_kms_server::TestsContext;

use crate::config::ClientConfig;

/// Protects the check-then-write sequence in `save_kms_cli_config` from TOCTOU
/// races when multiple test threads call it concurrently for the same server port.
static SAVE_CONFIG_LOCK: Mutex<()> = Mutex::new(());

mod ensure_binary;

#[cfg(feature = "non-fips")]
mod access;
mod attributes;
#[cfg(not(target_os = "windows"))]
#[cfg(feature = "non-fips")]
mod auth_tests;
mod certificates;
#[cfg(feature = "non-fips")]
mod cover_crypt;
mod custom_headers_tests;
mod derive_key;
mod elliptic_curve;
mod forward_proxy_tests;
mod google_cmd;
mod hash;
mod hsm;
mod login_tests;
mod mac;
#[cfg(feature = "non-fips")]
mod pqc;
mod rest_crypto;
mod rsa;
mod secret_data;
mod shared;
mod symmetric;
pub(crate) mod utils;
mod vendor_id;

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

    // Serialize writes within this process to prevent TOCTOU races when
    // multiple test threads concurrently call this function for the same port.
    // The process ID is embedded in the filename to prevent cross-process
    // conflicts when `cargo test --workspace --lib` runs multiple test binaries
    // concurrently (e.g., ckms + cosmian_kms_cli_actions both using port 9999).
    let _guard = SAVE_CONFIG_LOCK.lock().expect("SAVE_CONFIG_LOCK poisoned");
    let pid = std::process::id();

    let owner_file_path = env::temp_dir()
        .join(format!("owner_{}_{}.toml", kms_ctx.server_port, pid))
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
        .join(format!("user_{}_{}.toml", kms_ctx.server_port, pid))
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
    let pid = std::process::id();

    let owner_file_path = env::temp_dir()
        .join(format!("owner_{}_{}.toml", kms_ctx.server_port, pid))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: kms_ctx.owner_client_config.clone(),
    };
    conf.to_toml(&owner_file_path)
        .expect("Failed to save owner test config");

    let user_file_path = env::temp_dir()
        .join(format!("user_{}_{}.toml", kms_ctx.server_port, pid))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: kms_ctx.user_client_config.clone(),
    };
    conf.to_toml(&user_file_path)
        .expect("Failed to save user test config");

    (owner_file_path, user_file_path)
}
