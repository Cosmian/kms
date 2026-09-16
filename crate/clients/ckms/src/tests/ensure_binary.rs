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
#[allow(clippy::print_stdout)]
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

/// Waits until `marker_path` (indicating build completion) or `binary_path`
/// exists and the lock file is released, polling at a short interval. Bails
/// out after `timeout` so a stuck/crashed builder process cannot hang the
/// waiting test forever.
fn wait_for_binary(binary_path: &Path, lock_path: &Path, marker_path: &Path, timeout: Duration) {
    let start = Instant::now();
    while !marker_path.exists() {
        // If the lock file disappeared and the binary exists, the builder finished.
        if !lock_path.exists() && binary_path.exists() {
            break;
        }
        assert!(
            start.elapsed() < timeout,
            "Timed out after {timeout:?} waiting for another test process to finish building \
             the ckms binary at {}",
            binary_path.display()
        );
        thread::sleep(Duration::from_millis(100));
    }

    assert!(
        binary_path.exists(),
        "ckms binary was reported ready but does not exist at {}",
        binary_path.display()
    );
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

    let binary_path = workspace_root
        .join("target")
        .join(profile)
        .join(format!("ckms{}", std::env::consts::EXE_SUFFIX));

    if binary_path.exists() {
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
    let lock_path = workspace_root
        .join("target")
        .join(format!(".ckms-build-{profile}.lock"));
    let marker_path = workspace_root
        .join("target")
        .join(format!(".ckms-build-{profile}.ready"));

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
            drop(fs::write(&marker_path, b"ready"));
        }
        Err(_) => {
            // Another process already holds the lock (or just finished and
            // hasn't been able to remove it yet) — wait for the binary
            // rather than racing our own `cargo build`.
            wait_for_binary(&binary_path, &lock_path, &marker_path, wait_timeout);
        }
    }
}

#[allow(clippy::print_stdout)]
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
