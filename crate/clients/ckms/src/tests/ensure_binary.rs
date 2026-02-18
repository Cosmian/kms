use std::sync::Once;

static INIT: Once = Once::new();

/// Ensures the ckms binary is built before any test runs
/// Call this function at the start of every test that needs the ckms binary
#[allow(clippy::print_stdout)]
pub(crate) fn ensure_ckms_binary() {
    INIT.call_once(|| {
        build_ckms_binary();
    });
}

#[allow(clippy::print_stdout)]
fn build_ckms_binary() {
    use std::process::Command;

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

    // Check if binary already exists
    if binary_path.exists() {
        println!("✓ ckms binary already exists at {}", binary_path.display());
        return;
    }

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
