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

/// Path of an already-built provider library to test instead of building one.
const PREBUILT_PKCS11_ENV: &str = "COSMIAN_PKCS11_LIB";

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
    // A prebuilt artifact under test must not be overwritten by a rebuild.
    if env::var_os(PREBUILT_PKCS11_ENV).is_some() {
        return;
    }
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
        cmd.arg("--profile").arg("pkcs11-provider");
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
    if let Some(path) = env::var_os(PREBUILT_PKCS11_ENV) {
        return PathBuf::from(path);
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("Failed to find workspace root");

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "pkcs11-provider"
    };

    let lib_name = if cfg!(target_os = "macos") {
        "libcosmian_pkcs11.dylib"
    } else if cfg!(target_os = "windows") {
        "cosmian_pkcs11.dll"
    } else {
        "libcosmian_pkcs11.so"
    };

    let target_dir = env::var_os("CARGO_TARGET_DIR").map_or_else(
        || workspace_root.join("target"),
        |dir| workspace_root.join(dir),
    );
    target_dir.join(profile).join(lib_name)
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

    // Every C_* function is reported exactly once, split between the legacy
    // v2.40 ABI and v3.x extension tables.
    assert_section_total(&stdout, "PKCS#11 v2.40 API function coverage", 68);
    assert_section_total(&stdout, "PKCS#11 v3.x API extension coverage", 24);
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

// ---------------------------------------------------------------------------
// Real-library panic containment (fresh child process)
// ---------------------------------------------------------------------------

const FAULT_CHILD_ENV: &str = "COSMIAN_PKCS11_FAULT_CHILD";
/// Raw-pointer host for the cdylib under test; `libloading` has no safe API.
mod fault_host {
    #![expect(unsafe_code)] // tracked in #925: dlopen of the shipped library

    use super::pkcs11_lib_path;

    // PKCS#11 v2.40 values.
    const CKR_OK: std::ffi::c_ulong = 0;
    const CKR_GENERAL_ERROR: std::ffi::c_ulong = 5;
    const CKF_SERIAL_SESSION: std::ffi::c_ulong = 4;

    type InitFn = unsafe extern "C" fn(*mut std::ffi::c_void) -> std::ffi::c_ulong;
    type OpenSessionFn = unsafe extern "C" fn(
        std::ffi::c_ulong,
        std::ffi::c_ulong,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut std::ffi::c_ulong,
    ) -> std::ffi::c_ulong;
    type RandomFn =
        unsafe extern "C" fn(std::ffi::c_ulong, *mut u8, std::ffi::c_ulong) -> std::ffi::c_ulong;
    type StatusFn = unsafe extern "C" fn(std::ffi::c_ulong) -> std::ffi::c_ulong;
    type DiscoverFn = unsafe extern "C" fn(*mut *const usize) -> std::ffi::c_ulong;

    /// Resolves `name` through its slot in the PKCS#11 function list, checking that the slot
    /// holds the exported symbol.
    ///
    /// # Safety
    /// `T` must be the exact signature of the exported function and `table` the list it returned.
    unsafe fn resolve<T: Copy>(
        lib: &libloading::Library,
        table: *const usize,
        name: &[u8],
        slot: usize,
    ) -> T {
        // SAFETY: a data-pointer view of the symbol yields its address.
        let address = unsafe {
            *lib.get::<*const std::ffi::c_void>(name)
                .expect("symbol not exported")
        };
        // SAFETY: the 2.40 list is a version header word followed by one pointer per function.
        let entry = unsafe { table.add(1 + slot) };
        // SAFETY: `entry` is inside the list returned by the library.
        assert_eq!(
            unsafe { *entry },
            address.addr(),
            "slot {slot} is not {name:?}"
        );
        // SAFETY: the slot holds the verified exported function.
        unsafe { entry.cast::<T>().read() }
    }

    pub(super) fn run_fault_child() {
        // CK_ULONG must be able to exceed isize::MAX to force a capacity overflow, not a real allocation.
        let oversized = std::ffi::c_ulong::MAX;
        if usize::try_from(oversized).map_or(true, |size| size <= isize::MAX.unsigned_abs()) {
            return;
        }
        // SAFETY: loads the library under test; its initializers only set up statics.
        let lib = unsafe { libloading::Library::new(pkcs11_lib_path()) }.expect("load provider");
        // SAFETY: `C_GetFunctionList` has this signature.
        let discover: DiscoverFn = unsafe {
            *lib.get::<DiscoverFn>(b"C_GetFunctionList\0")
                .expect("discovery")
        };
        let mut table: *const usize = std::ptr::null();
        // SAFETY: `table` is a valid out-pointer.
        assert_eq!(unsafe { discover(&raw mut table) }, CKR_OK);

        // SAFETY: each type is the PKCS#11 signature of the named function and slot (v2.40 order).
        let (init, finalize, open_session, random, status) = unsafe {
            (
                resolve::<InitFn>(&lib, table, b"C_Initialize\0", 0),
                resolve::<InitFn>(&lib, table, b"C_Finalize\0", 1),
                resolve::<OpenSessionFn>(&lib, table, b"C_OpenSession\0", 12),
                resolve::<RandomFn>(&lib, table, b"C_GenerateRandom\0", 64),
                resolve::<StatusFn>(&lib, table, b"C_GetFunctionStatus\0", 65),
            )
        };
        let mut session: std::ffi::c_ulong = 0;
        let mut bytes = [0_u8; 16];
        // SAFETY: valid pointers and lengths for the calls below.
        unsafe {
            assert_eq!(init(std::ptr::null_mut()), CKR_OK);
            assert_eq!(
                open_session(
                    1,
                    CKF_SERIAL_SESSION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &raw mut session
                ),
                CKR_OK
            );
            assert_eq!(
                random(session, bytes.as_mut_ptr(), 16),
                CKR_OK,
                "healthy call failed"
            );
            // The length overflows Vec capacity before the buffer is touched.
            assert_eq!(
                random(session, bytes.as_mut_ptr(), oversized),
                CKR_GENERAL_ERROR
            );
            assert_eq!(
                random(session, bytes.as_mut_ptr(), 16),
                CKR_GENERAL_ERROR,
                "work after fault"
            );
            assert_eq!(status(session), CKR_GENERAL_ERROR, "stub after fault");
            assert_eq!(
                finalize(std::ptr::null_mut()),
                CKR_GENERAL_ERROR,
                "finalize after fault"
            );
            assert_eq!(
                init(std::ptr::null_mut()),
                CKR_GENERAL_ERROR,
                "re-init after fault"
            );
            assert_eq!(
                discover(&raw mut table),
                CKR_GENERAL_ERROR,
                "discovery after fault"
            );
        }
    }
}

/// A panic inside the shipped-profile library is contained and the library stays refused.
#[test]
fn test_pkcs11_real_library_contains_panic() {
    if env::var_os(FAULT_CHILD_ENV).is_some() {
        fault_host::run_fault_child();
        return;
    }
    ensure_pkcs11_lib();
    let conf = env::temp_dir().join(format!("pkcs11_fault_{}.toml", std::process::id()));
    std::fs::write(
        &conf,
        "[http_config]\nserver_url = \"http://127.0.0.1:1\"\n",
    )
    .expect("Failed to write temp config");
    let output = Command::new(env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "tests::pkcs11::test_pkcs11_real_library_contains_panic",
            "--nocapture",
        ])
        .env(FAULT_CHILD_ENV, "1")
        .env("CKMS_CONF", &conf)
        .output()
        .expect("spawn fault child");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
