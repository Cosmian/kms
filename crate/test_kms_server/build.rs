#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::manual_assert,
    clippy::uninlined_format_args,
    clippy::verbose_file_reads
)]

use std::{env, path::Path};

/// The `test_kms_server` crate depends on `cosmian_kms_server` which already
/// builds OpenSSL via its build.rs script. However, when tests link against
/// `test_kms_server`, they need the OpenSSL environment variables to be set
/// at link time.
///
/// This build script ensures that:
/// 1. The OpenSSL built by `cosmian_kms_server` is used
/// 2. Link paths are correctly set for test binaries
/// 3. Runtime environment variables are propagated for test execution
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let fips_mode = is_fips_mode();
    let in_nix = in_nix_env();

    if in_nix {
        // In Nix environment, OpenSSL is provided by the derivation
        println!(
            "cargo:warning=test_kms_server: Detected Nix environment; using Nix-provided OpenSSL"
        );
        return;
    }

    // If OPENSSL_DIR is already set in the environment, check if it's valid
    if let Ok(dir) = env::var("OPENSSL_DIR") {
        let dir_path = Path::new(&dir);
        if dir_path.join("include").exists() {
            if fips_mode {
                if fips_artifacts_present(dir_path) {
                    println!(
                        "cargo:warning=test_kms_server: Using existing OPENSSL_DIR={dir} (FIPS artifacts detected)"
                    );
                    emit_link_env(dir_path);
                    return;
                }
            } else {
                println!(
                    "cargo:warning=test_kms_server: Using existing OPENSSL_DIR={dir} in non-FIPS mode"
                );
                emit_link_env(dir_path);
                return;
            }
        }
    }

    // Resolve workspace root from CARGO_MANIFEST_DIR (crate/test_kms_server -> crate -> repo root)
    let Some(manifest_dir_os) = env::var_os("CARGO_MANIFEST_DIR") else {
        println!(
            "cargo:warning=test_kms_server: Missing CARGO_MANIFEST_DIR; cannot locate OpenSSL build"
        );
        return;
    };
    let manifest_dir = Path::new(&manifest_dir_os);
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| Path::new("."));

    // Allow respect of CARGO_TARGET_DIR if set; fallback to <workspace>/target
    #[allow(clippy::map_unwrap_or)]
    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(|s| Path::new(&s).to_path_buf())
        .unwrap_or_else(|| workspace_root.join("target"));

    // Determine the OpenSSL installation path (must match server/build.rs logic)
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown-arch".into());
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown-os".into());
    let mode_suffix = if fips_mode { "fips" } else { "legacy" };

    let openssl_dir = target_dir.join(format!("openssl-{}-3.1.2-{}-{}", mode_suffix, os, arch));

    // Check if OpenSSL has been built by the server crate
    if !openssl_dir.join("lib/libcrypto.a").exists() {
        println!(
            "cargo:warning=test_kms_server: {} OpenSSL not found at {}",
            if fips_mode { "FIPS" } else { "legacy" },
            openssl_dir.display()
        );
        println!(
            "cargo:warning=test_kms_server: OpenSSL will be built by cosmian_kms_server dependency"
        );
        // The server crate's build.rs will run and build OpenSSL, but we can't
        // emit link directives here since the build hasn't happened yet.
        // Tests may fail if OpenSSL isn't available at link time.
        return;
    }

    if fips_mode && !fips_artifacts_present(&openssl_dir) {
        println!(
            "cargo:warning=test_kms_server: FIPS mode requested but FIPS artifacts not found at {}",
            openssl_dir.display()
        );
        return;
    }

    println!(
        "cargo:warning=test_kms_server: Using {} OpenSSL from {}",
        if fips_mode { "FIPS" } else { "legacy" },
        openssl_dir.display()
    );

    emit_link_env(&openssl_dir);
}

fn is_fips_mode() -> bool {
    env::var("CARGO_FEATURE_NON_FIPS").is_err()
}

fn in_nix_env() -> bool {
    env::var("NIX_BUILD_TOP").is_ok() || env::var("IN_NIX_SHELL").is_ok()
}

fn fips_artifacts_present(prefix: &Path) -> bool {
    let mod_ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    let provider = prefix.join(format!("lib/ossl-modules/fips.{mod_ext}"));
    let cnf = prefix.join("ssl/fipsmodule.cnf");
    provider.exists() && cnf.exists()
}

fn emit_link_env(install_prefix: &Path) {
    // Note: We don't emit rustc-link directives here because the openssl crate
    // (via openssl-sys) handles linking. We only need to ensure OPENSSL_DIR is set.
    println!("cargo:rustc-env=OPENSSL_DIR={}", install_prefix.display());

    // Set runtime environment variables so tests can find FIPS provider and config
    println!(
        "cargo:rustc-env=OPENSSL_CONF={}/ssl/openssl.cnf",
        install_prefix.display()
    );
    println!(
        "cargo:rustc-env=OPENSSL_MODULES={}/lib/ossl-modules",
        install_prefix.display()
    );
}
