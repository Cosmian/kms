#![allow(
    clippy::expect_used, // build scripts may panic on misconfigured build environments
    clippy::panic
)]
//! Build script for `cosmian_pkcs11_verify`.
//!
//! Determines the workspace `target/{profile}/` directory from `OUT_DIR` and
//! emits it as the compile-time environment variable `COSMIAN_PKCS11_LIB_DIR`.
//! The integration test in `src/tests.rs` reads this variable to locate the
//! `libcosmian_pkcs11.{dylib,so,dll}` cdylib that must have been built before
//! running the tests (e.g. via `cargo test-non-fips`, which builds all workspace
//! members including `cosmian_pkcs11`).
//!
//! The `cargo:rerun-if-changed` directives tell Cargo to re-run this script —
//! and therefore re-emit `COSMIAN_PKCS11_LIB_DIR` — whenever the provider
//! sources or its manifest change.

fn main() {
    // OUT_DIR is always set by Cargo before invoking build scripts:
    //   .../target/{profile}/build/{crate_name}-{hash}/out
    // Ascending three levels gives .../target/{profile}/.
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by Cargo");
    let target_profile_dir = std::path::Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .expect("OUT_DIR does not have at least 3 ancestor components");

    println!(
        "cargo:rustc-env=COSMIAN_PKCS11_LIB_DIR={}",
        target_profile_dir.display()
    );

    // Rebuild this script (and re-emit the env var) when provider sources change.
    println!("cargo:rerun-if-changed=../provider/src");
    println!("cargo:rerun-if-changed=../provider/Cargo.toml");
}
