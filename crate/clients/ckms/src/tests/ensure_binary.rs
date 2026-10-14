use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::Once,
    thread,
    time::{Duration, Instant},
};

static INIT: Once = Once::new();

/// Ensures the ckms binary is built before any test runs
/// Call this function at the start of every test that needs the ckms binary
pub(crate) fn ensure_ckms_binary() {
    INIT.call_once(|| {
        build_ckms_binary();
    });
}

/// Releases the cross-process build lock (see `build_ckms_binary`) when
/// dropped, including on panic, so a failed build never leaves other
/// processes waiting forever for a binary that will never appear.
struct BuildLockGuard(PathBuf);

impl Drop for BuildLockGuard {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.0));
    }
}

/// Waits until the builder process releases `lock_path` and `marker_path`
/// vouches for `binary_path`, polling at a short interval. Bails out after
/// `timeout` so a stuck/crashed builder process cannot hang the waiting test
/// forever.
fn wait_for_binary(binary_path: &Path, lock_path: &Path, marker_path: &Path, timeout: Duration) {
    let start = Instant::now();
    while lock_path.exists() {
        assert!(
            start.elapsed() < timeout,
            "Timed out after {timeout:?} waiting for another test process to finish building \
             the ckms binary at {}",
            binary_path.display()
        );
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        is_fresh(binary_path, marker_path),
        "another test process finished building but the ckms binary at {} is not ready",
        binary_path.display()
    );
}

/// Modification time of `path` as a string, used to identify one exact build
/// of the binary.
fn mtime_stamp(path: &Path) -> Option<String> {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| format!("{t:?}"))
}

/// The binary is usable when the marker was written by our own build of this
/// variant (it stores the binary's mtime, so any later `cargo build` of the
/// other variant invalidates it) and after the current test executable was
/// compiled (so ckms source changes trigger a rebuild).
fn is_fresh(binary_path: &Path, marker_path: &Path) -> bool {
    let Some(stamp) = mtime_stamp(binary_path) else {
        return false;
    };
    let marker_newer_than_test_exe = std::env::current_exe()
        .and_then(fs::metadata)
        .and_then(|m| m.modified())
        .ok()
        .zip(fs::metadata(marker_path).and_then(|m| m.modified()).ok())
        .is_some_and(|(exe, marker)| marker >= exe);
    marker_newer_than_test_exe && fs::read_to_string(marker_path).is_ok_and(|s| s == stamp)
}

#[allow(clippy::print_stdout)]
fn build_ckms_binary() {
    // Get the path where the binary should be
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("Failed to find workspace root");

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let variant = if cfg!(feature = "non-fips") {
        "non-fips"
    } else {
        "fips"
    };

    let binary_path = workspace_root
        .join("target")
        .join(profile)
        .join(format!("ckms{}", std::env::consts::EXE_SUFFIX));
    let lock_path = workspace_root
        .join("target")
        .join(format!(".ckms-build-{profile}-{variant}.lock"));
    let marker_path = workspace_root
        .join("target")
        .join(format!(".ckms-build-{profile}-{variant}.ready"));

    // Reuse the binary only if it is exactly the one our last build of this
    // variant produced; a plain `cargo build` (FIPS) overwrites the same path.
    if is_fresh(&binary_path, &marker_path) {
        return;
    }

    // `INIT` above only de-duplicates within a single OS process. Under
    // `cargo nextest`, every test runs in its own process, so dozens of
    // `ckms` tests would otherwise race to invoke `cargo build --bin ckms`
    // concurrently — which was observed to intermittently fail test command
    // spawns with ENOENT while another process was mid-relink of the binary,
    // and wastefully spawned one redundant `cargo build` subprocess per test
    // process. Use an atomically-created lock file so only the first process
    // across the whole test run actually builds; everyone else just waits
    // for the binary to appear.
    let wait_timeout: Duration = Duration::from_secs(300);

    // If an orphaned lock file exists from a crashed or killed process, check
    // its age and clear it if it exceeds the timeout.
    if let Ok(metadata) = fs::metadata(&lock_path) {
        if let Ok(age) = metadata
            .modified()
            .and_then(|m| m.elapsed().map_err(std::io::Error::other))
        {
            if age > wait_timeout {
                drop(fs::remove_file(&lock_path));
            }
        }
    }

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_lock_file) => {
            let _guard = BuildLockGuard(lock_path);
            drop(fs::remove_file(&marker_path));
            run_cargo_build(workspace_root, &binary_path);
            // Write marker to signal completion before dropping guard
            if let Some(stamp) = mtime_stamp(&binary_path) {
                drop(fs::write(&marker_path, stamp));
            }
        }
        Err(_) => {
            // Another process already holds the lock (or just finished and
            // hasn't been able to remove it yet) — wait for the binary
            // rather than racing our own `cargo build`.
            wait_for_binary(&binary_path, &lock_path, &marker_path, wait_timeout);
        }
    }
}
fn run_cargo_build(workspace_root: &Path, binary_path: &Path) {
    use std::process::Command;

    // Build the binary
    println!("Building ckms binary for tests...");

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("ckms")
        .arg("--bin")
        .arg("ckms")
        .current_dir(workspace_root);

    // Add release flag if needed
    if !cfg!(debug_assertions) {
        cmd.arg("--release");
    }

    // Add features based on what's enabled
    #[cfg(feature = "non-fips")]
    {
        cmd.arg("--features").arg("non-fips");
    }

    let output = cmd.output().expect("Failed to execute cargo build");

    if !output.status.success() {
        eprintln!("Failed to build ckms binary:");
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("ckms binary build failed");
    }

    assert!(
        binary_path.exists(),
        "ckms binary was not created at {}",
        binary_path.display()
    );

    println!(
        "✓ ckms binary built successfully at {}",
        binary_path.display()
    );
}
