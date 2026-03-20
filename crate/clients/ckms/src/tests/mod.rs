#![allow(deprecated)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::str_to_string)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_in_result)]
#![allow(clippy::assertions_on_result_states)]
#![allow(clippy::panic_in_result_fn)]

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

fn ckms_binary_path() -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .expect("Failed to find workspace root");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    workspace_root
        .join("target")
        .join(profile)
        .join(format!("{PROG_NAME}{}", std::env::consts::EXE_SUFFIX))
}

/// Create a Command for the ckms binary, ensuring it's built first
/// Use this instead of `Command::cargo_bin()` directly in tests.
#[allow(dead_code)]
pub(crate) fn ckms_command() -> std::process::Command {
    // Access the lazy lock to ensure binary is built
    *ENSURE_BINARY_ON_LOAD;

    let binary_path = ckms_binary_path();
    assert!(
        binary_path.exists(),
        "Failed to find ckms binary at {}",
        binary_path.display()
    );
    std::process::Command::new(binary_path)
}
