#![allow(deprecated)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::str_to_string)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_in_result)]
#![allow(clippy::assertions_on_result_states)]
#![allow(clippy::panic_in_result_fn)]

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
mod discover_versions;
mod elliptic_curve;
mod error_messages;
mod forward_proxy_tests;
#[cfg(feature = "non-fips")]
mod fpe;
mod google_cmd;
mod hash;
mod hsm;
mod login_tests;
mod mac;
mod opaque_object;
#[cfg(feature = "non-fips")]
mod pqc;
mod query;
mod rng;
mod rsa;
mod secret_data;
mod security;
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
