//! Helpers shared by the tests that drive `Session` against C fixture libraries
//! compiled from `tests/fixtures/*.c`.

use std::{
    path::PathBuf,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    HError, HResult, ObjectHandlesCache, Session, hsm_capabilities::HsmCapabilities,
    hsm_lib::HsmLib, session::message_context::MessageMechanismSupport,
};

/// Monotonic counter giving each `compile_fixture()` invocation a
/// unique output filename. Required because the tests using the helper run
/// concurrently (the default `cargo test` runner parallelises tests within a
/// binary): a shared, fixed output path let one test's (re)compilation
/// truncate/replace the file out from under another test's concurrent `dlopen`,
/// causing sporadic "no such file" failures.
static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

/// Serializes invocations of the C compiler across the concurrently-running
/// tests. Unlike GCC/Clang (`-o <unique>.{so,dylib}`, no
/// leftover intermediate file), MSVC's `cl.exe` does not honor `-o` as an
/// object-output path (only accepts it as a deprecated legacy alias — see the
/// `D9035` compiler warning) and always writes an intermediate
/// `<source>.obj` at a fixed location relative to the current
/// directory, regardless of the requested (unique) `.dll` output path.
/// Concurrent `cargo test` threads invoking `cl.exe` at the same time
/// therefore race on that single shared `.obj` file (`C1083: Cannot open
/// compiler generated file ... Permission denied`, then a
/// corrupted/partially-linked `.dll` causing a later access violation on
/// load) — observed only on Windows CI. Serializing the compiler invocation
/// itself (not just the final output filename) avoids the race on every
/// platform, at the cost of a little test time.
static COMPILE_LOCK: Mutex<()> = Mutex::new(());

/// Returns the current Rust host target triple (e.g.
/// `aarch64-apple-darwin`), needed because `cc::Build` requires `TARGET`/`HOST`
/// to be set (normally supplied by Cargo to build scripts, but absent in a plain
/// `#[test]` context).
fn host_target_triple() -> HResult<String> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|e| HError::Default(format!("failed to invoke rustc: {e}")))?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| {
            HError::Default("rustc -vV output did not contain a \"host: \" line".to_owned())
        })
}

/// Compiles `tests/fixtures/<source_file>` into a uniquely named shared library.
/// `extra_args` are passed to the compiler verbatim (e.g. `-DWITH_MESSAGE_SIGNATURE`, `-ldl`).
///
/// `minimal_pkcs11.c` is a strictly spec-conformant PKCS#11 v3.0 shim that exports *only*
/// `C_GetFunctionList`/`C_GetInterface` (no individual `C_XXX` symbols), mirroring how Kryoptic
/// and other strictly conformant libraries behave. Returns an error with a descriptive message
/// on any compiler failure so a broken fixture never silently skips a regression test.
pub(crate) fn compile_fixture(source_file: &str, extra_args: &[&str]) -> HResult<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let source = PathBuf::from(manifest_dir)
        .join("tests/fixtures")
        .join(source_file);
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join("cosmian_kms_base_hsm_test_fixtures")
            .to_string_lossy()
            .into_owned()
    }));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| HError::Default(format!("failed to create test fixture output dir: {e}")))?;

    let extension = if cfg!(target_os = "windows") {
        "dll"
    } else if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    let stem = source
        .file_stem()
        .map_or_else(|| "fixture".into(), |s| s.to_string_lossy());
    let output = out_dir.join(format!(
        "{stem}_{}_{}.{extension}",
        std::process::id(),
        NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));

    // `cc::Build` targets static libs/object files, not shared libraries, so the
    // shared-library flag is invoked manually via the resolved compiler. `target`
    // and `host` must be set explicitly since we are not running inside a Cargo
    // build script (where Cargo would set the `TARGET`/`HOST` env vars for us).
    let triple = host_target_triple()?;
    let compiler = cc::Build::new()
        .opt_level(0)
        .target(&triple)
        .host(&triple)
        .cargo_metadata(false) // this is a plain test, not a build script
        .get_compiler();
    let mut cmd = Command::new(compiler.path());
    cmd.envs(compiler.get_envs());
    cmd.args(compiler.args());
    if !cfg!(target_os = "windows") {
        // Silence the intentional generic-function-pointer-cast warning below:
        // this is a throwaway test fixture standing in for a real vendor PKCS#11
        // library, not shipped code subject to the workspace's zero-warnings rule.
        cmd.arg("-w");
    }
    if cfg!(target_os = "macos") {
        cmd.arg("-dynamiclib");
    } else if cfg!(target_os = "windows") {
        cmd.arg("/LD");
    } else {
        cmd.arg("-shared");
    }
    if !cfg!(target_os = "windows") {
        cmd.arg("-fPIC");
    }
    cmd.arg(&source);
    cmd.args(extra_args);
    cmd.arg("-o").arg(&output);

    // See `COMPILE_LOCK`'s doc comment: on Windows, `cl.exe` writes a
    // fixed-name intermediate `.obj` shared by every concurrent invocation,
    // so the compiler must be invoked one test at a time. `PoisonError` is
    // ignored (`unwrap_or_else`) so a prior test panicking while holding the
    // lock cannot spuriously fail every subsequent test.
    let _guard = COMPILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let status = cmd.status().map_err(|e| {
        HError::Default(format!(
            "failed to invoke the C compiler for the test fixture: {e}"
        ))
    })?;
    if !status.success() {
        return Err(HError::Default(format!(
            "failed to compile the PKCS#11 test fixture {source:?}: compiler exited with \
             {status}"
        )));
    }
    Ok(output)
}

/// Builds a `Session` directly against a fixture library, bypassing
/// `SlotManager` (which the fixtures do not implement enough of `C_GetSlotList`
/// et al. to support) — sufficient for exercising `Session` methods that only
/// need an `HsmLib` and an opaque session handle.
pub(crate) fn fixture_session(hsm_lib: HsmLib, capabilities: HsmCapabilities) -> Session {
    Session::new(
        Arc::new(hsm_lib),
        1, // opaque session handle; every fixture stub ignores it
        Arc::new(ObjectHandlesCache::new()),
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(MessageMechanismSupport::default())),
        false,
        capabilities,
    )
}
