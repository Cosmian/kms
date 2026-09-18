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

use crate::tests::utils::{
    ckms_bin, force_save_kms_cli_config, load_client_config, recover_cmd_logs,
};

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

/// Function names whose function-coverage shallow probe is expected to fail
/// every run, because the probe deliberately does not engineer the full
/// precondition sequence for that function (`plan.md` Decision 5/"dynamic"
/// philosophy: report the real `CK_RV` rather than perfectly staging state).
#[cfg(not(target_os = "windows"))]
const KNOWN_FAILING_SHALLOW_PROBES: &[&str] = &[
    // Rejected: the minimal template omitted mandatory attributes.
    "C_CreateObject",
    // `CKR_OPERATION_NOT_INITIALIZED`: no matching `C_SignInit`/`C_VerifyInit`
    // precedes this shallow probe (that pairing is only exercised inside the
    // deep mechanism checks, which use one-shot `C_Sign`/`C_Verify`, not the
    // streaming `*Update`/`*Final` variants).
    "C_SignUpdate",
    "C_SignFinal",
    "C_VerifyUpdate",
    "C_VerifyFinal",
    // `cosmian_pkcs11` does not support application-seeded randomness.
    "C_SeedRandom",
];

/// Verify that `ckms pkcs11 capabilities` runs every FIPS-eligible mechanism
/// (AES/RSA/ECDSA) end to end against a JWT-authenticated server and reports
/// them all as passing.
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_pkcs11_capabilities_with_jwt_auth() {
    ensure_pkcs11_lib();

    let ctx = start_default_test_kms_server_with_jwt_auth().await;
    let dll_path = pkcs11_lib_path();
    // The PKCS#11 provider authenticates via `C_Login`/`--token` (bearer token
    // supplied at keystore-open time); the KMS client used to *provision* the
    // RSA/EC/Ed25519 test keys over the REST API is a separate, conventionally
    // authenticated client (owner config), independent of that PKCS#11 flow.
    let conf_path = load_client_config("pkcs11_oidc.toml", ctx);
    let (owner_conf_path, _) = force_save_kms_cli_config(ctx);

    let mut cmd = ckms_bin();
    cmd.env("CKMS_CONF_PATH", &owner_conf_path);
    cmd.args([
        "pkcs11",
        "capabilities",
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
        "ckms pkcs11 capabilities exited non-zero.\nstdout: {stdout}\nstderr: {stderr}"
    );
    for mechanism in [
        "CKM_AES_KEY_GEN",
        "CKM_AES_CBC",
        "CKM_AES_CBC_PAD",
        "CKM_AES_GCM",
        "CKM_RSA_PKCS",
        "CKM_SHA256_RSA_PKCS",
        "CKM_RSA_PKCS_PSS",
        "CKM_ECDSA",
    ] {
        assert!(
            stdout.contains(mechanism),
            "Expected a report row for {mechanism}.\nstdout: {stdout}"
        );
    }
    // `CKM_SHA1_RSA_PKCS` is expected to fail: the KMS server's algorithm policy
    // (`crate/server/src/core/operations/algorithm_policy.rs`) unconditionally denies
    // the deprecated `SHA1WithRSAEncryption` signature algorithm, independent of the
    // FIPS/non-FIPS build. A ❌ row that is genuinely "not implemented" (the vast
    // majority of the 430 mechanisms `cosmian_pkcs11` does not advertise) is
    // expected and excluded from this check; any other failing (\u{274c}) row —
    // i.e. a real attempted operation that did not behave as expected — is a
    // genuine regression.
    let mechanism_section_start = stdout
        .find("PKCS#11 mechanism coverage")
        .expect("mechanism coverage section not found");
    for line in stdout[mechanism_section_start..].lines() {
        if line.contains('\u{274c}') && !line.contains("(not implemented:") {
            assert!(
                line.contains("CKM_SHA1_RSA_PKCS"),
                "Unexpected failing mechanism row: {line}\nstdout: {stdout}"
            );
        }
    }
    // The function section's shallow probes deliberately do not engineer every
    // operation's full precondition sequence (`plan.md` Decision 5/"dynamic"
    // philosophy: report the real `CK_RV` rather than perfectly staging state).
    // These specific functions are therefore expected to fail with a
    // precondition-related error every run. A ❌ row that is genuinely "not
    // implemented" (`CKR_FUNCTION_NOT_SUPPORTED`-stubbed functions) is expected
    // and excluded from this check; any other failing (\u{274c}) row in this
    // section is a genuine regression.
    let function_section_end = mechanism_section_start;
    for line in stdout[..function_section_end].lines() {
        if line.contains('\u{274c}') && !line.contains("(not implemented:") {
            assert!(
                KNOWN_FAILING_SHALLOW_PROBES
                    .iter()
                    .any(|name| line.contains(name)),
                "Unexpected failing function row: {line}\nstdout: {stdout}"
            );
        }
    }

    #[cfg(feature = "non-fips")]
    {
        assert!(
            stdout.contains("CKM_EDDSA"),
            "Expected a report row for CKM_EDDSA in a non-fips build.\nstdout: {stdout}"
        );
    }

    // All 92 C_* functions must be accounted for exactly once each (passed +
    // failed + skipped + not-implemented + excluded == 92): no function may be
    // silently dropped by the coverage pass.
    assert_section_total(&stdout, "PKCS#11 API function coverage", 92);
    // The mechanism section has more *rows* than 442 whenever a mechanism is
    // deep-tested across several curves (e.g. CKM_ECDSA: P-256/P-384/P-521/
    // secp256k1), since each curve is a genuinely distinct code path (Decision
    // 7). The invariant that must hold is therefore on *distinct* CKM_* names
    // covered, not on the raw row count.
    assert_mechanism_names_covered(&stdout, 442);
}

/// Parses one report section's trailing summary line (`"N passed, N failed, N
/// skipped, N not implemented, N excluded (N total)."`) and asserts the
/// reported total matches the known universe size for that section, per
/// `plan.md` Decision 10's count-reconciliation invariant.
#[cfg(not(target_os = "windows"))]
fn assert_section_total(stdout: &str, section_title: &str, expected_total: usize) {
    let section_start = stdout
        .find(section_title)
        .unwrap_or_else(|| panic!("section '{section_title}' not found.\nstdout: {stdout}"));
    let summary_line = stdout[section_start..]
        .lines()
        .find(|line| line.contains("total)."))
        .unwrap_or_else(|| {
            panic!("no summary line found for section '{section_title}'.\nstdout: {stdout}")
        });
    let total_str = summary_line
        .rsplit('(')
        .next()
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or_else(|| panic!("cannot parse summary line: {summary_line}"));
    let total: usize = total_str
        .parse()
        .unwrap_or_else(|e| panic!("cannot parse total '{total_str}' in '{summary_line}': {e}"));
    assert_eq!(
        total, expected_total,
        "section '{section_title}' reported {total} total rows, expected {expected_total} \
         (some entries were silently dropped or double-counted).\nsummary line: {summary_line}"
    );
}

/// Counts the number of *distinct* `CKM_*` mechanism names appearing as report
/// rows in the "PKCS#11 mechanism coverage" section and asserts it matches the
/// known 442-mechanism universe (`ALL_MECHANISMS` in `pkcs11_capabilities.rs`).
#[cfg(not(target_os = "windows"))]
fn assert_mechanism_names_covered(stdout: &str, expected_names: usize) {
    let section_start = stdout
        .find("PKCS#11 mechanism coverage")
        .expect("mechanism coverage section not found");
    let section_end = stdout[section_start..]
        .find("total).")
        .map_or(stdout.len(), |offset| section_start + offset);
    let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for line in stdout[section_start..section_end].lines() {
        if let Some(rest) = line.split(' ').nth(1) {
            if rest.starts_with("CKM_") {
                names.insert(rest);
            }
        }
    }
    assert_eq!(
        names.len(),
        expected_names,
        "expected {expected_names} distinct CKM_* mechanism names in the report, found {}",
        names.len()
    );
}
