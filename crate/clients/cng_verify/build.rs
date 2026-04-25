/// Build script for `cosmian_kms_cng_ksp_verify`.
///
/// Checks that the `cosmian_kms_cng_ksp` DLL exists in the target directory.
/// The DLL must be built separately (via `cargo build -p cosmian_kms_cng_ksp`)
/// because nested `cargo build` calls from build scripts deadlock on the target
/// directory lock.
fn main() {
    // Only relevant on Windows — the DLL is a Windows-only artifact.
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }

    println!("cargo::rerun-if-changed=../cng/src/");
    println!("cargo::rerun-if-changed=../cng/Cargo.toml");

    // Determine the profile: if OPT_LEVEL > 0 we assume release, otherwise debug.
    let profile = if std::env::var("OPT_LEVEL").unwrap_or_default() == "0" {
        "debug"
    } else {
        "release"
    };

    // Look for the DLL in the target directory.
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let Some(ws_root) = std::path::Path::new(&manifest_dir)
        .parent() // clients/
        .and_then(|p| p.parent()) // crate/
        .and_then(|p| p.parent())
    // workspace root
    else {
        return;
    };
    let dll_path = ws_root
        .join("target")
        .join(profile)
        .join("cosmian_kms_cng_ksp.dll");

    if !dll_path.exists() {
        println!(
            "cargo::warning=cosmian_kms_cng_ksp.dll not found at {}. \
             Build it first with: cargo build -p cosmian_kms_cng_ksp",
            dll_path.display()
        );
    }
}
