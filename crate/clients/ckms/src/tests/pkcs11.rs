//! Integration tests for `ckms pkcs11 verify`.
//!
//! These tests exercise the PKCS#11 shared-library verification command against
//! a real KMS server with JWT authentication enabled.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::Once,
};

use test_kms_server::{AUTH0_TOKEN, start_default_test_kms_server_with_jwt_auth};

use crate::tests::utils::{ckms_bin, load_client_config, recover_cmd_logs};

// ---------------------------------------------------------------------------
// Ensure the PKCS#11 cdylib is built before tests run
// ---------------------------------------------------------------------------

static BUILD_PKCS11: Once = Once::new();

/// Ensures the `libcosmian_pkcs11` shared library (cdylib) is built.
/// Mirrors the pattern from `ensure_binary.rs`.
#[allow(clippy::print_stdout)]
fn ensure_pkcs11_lib() {
    BUILD_PKCS11.call_once(|| {
        build_pkcs11_lib();
    });
}

#[allow(clippy::print_stdout)]
fn build_pkcs11_lib() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("Failed to find workspace root");

    println!("Building libcosmian_pkcs11 for PKCS#11 tests...");

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("cosmian_pkcs11")
        .current_dir(workspace_root);

    if !cfg!(debug_assertions) {
        cmd.arg("--release");
    }

    #[cfg(feature = "non-fips")]
    {
        cmd.arg("--features").arg("non-fips");
    }

    let output = cmd
        .output()
        .expect("Failed to execute cargo build for cosmian_pkcs11");

    if !output.status.success() {
        eprintln!("Failed to build libcosmian_pkcs11:");
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("libcosmian_pkcs11 build failed");
    }

    let lib_path = pkcs11_lib_path();
    assert!(
        lib_path.exists(),
        "libcosmian_pkcs11 was not created at {}",
        lib_path.display()
    );

    println!(
        "✓ libcosmian_pkcs11 built successfully at {}",
        lib_path.display()
    );
}

/// Returns the expected path to the built PKCS#11 shared library.
fn pkcs11_lib_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("Failed to find workspace root");

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    let lib_name = if cfg!(target_os = "macos") {
        "libcosmian_pkcs11.dylib"
    } else if cfg!(target_os = "windows") {
        "cosmian_pkcs11.dll"
    } else {
        "libcosmian_pkcs11.so"
    };

    workspace_root.join("target").join(profile).join(lib_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `ckms pkcs11 verify` succeeds against a JWT-authenticated server
/// when a valid token is provided.
#[tokio::test]
async fn test_pkcs11_verify_with_jwt_auth() {
    ensure_pkcs11_lib();

    let ctx = start_default_test_kms_server_with_jwt_auth().await;
    let dll_path = pkcs11_lib_path();
    let conf_path = load_client_config("pkcs11_oidc.toml", ctx);

    let mut cmd = ckms_bin();
    cmd.args([
        "pkcs11",
        "verify",
        "--dll",
        dll_path.to_str().expect("dll path is UTF-8"),
        "--conf",
        &conf_path,
        "--token",
        AUTH0_TOKEN,
    ]);

    let output = recover_cmd_logs(&mut cmd);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "ckms pkcs11 verify failed.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("All checks passed"),
        "Expected 'All checks passed' in stdout.\nstdout: {stdout}"
    );
}

/// Verify that `ckms pkcs11 verify` FAILS when no KMS server is reachable.
/// This guards against false positives if the server is down.
#[tokio::test]
async fn test_pkcs11_verify_fails_without_server() {
    ensure_pkcs11_lib();

    let dll_path = pkcs11_lib_path();
    // Use a temp config pointing at a port where no server is listening
    let pid = std::process::id();
    let conf_path = env::temp_dir().join(format!("pkcs11_no_server_{pid}.toml"));
    std::fs::write(
        &conf_path,
        "pkcs11_use_pin_as_access_token = true\n\n[http_config]\nserver_url = \"http://localhost:19999\"\n",
    )
    .expect("Failed to write temp config");

    let mut cmd = ckms_bin();
    cmd.args([
        "pkcs11",
        "verify",
        "--dll",
        dll_path.to_str().expect("dll path is UTF-8"),
        "--conf",
        conf_path.to_str().expect("conf path is UTF-8"),
        "--token",
        "fake-token",
    ]);

    let output = recover_cmd_logs(&mut cmd);

    assert!(
        !output.status.success(),
        "ckms pkcs11 verify should FAIL when no KMS server is running, but it succeeded.\n\
         stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
