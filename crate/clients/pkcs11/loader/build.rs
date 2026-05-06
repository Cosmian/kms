#![allow(
    clippy::expect_used, // build scripts may panic on misconfigured build environments
    clippy::panic
)]
//! Build script for `cosmian_pkcs11_verify`.
//!
//! Emits the compile-time env var `COSMIAN_PKCS11_LIB_DIR` pointing to the
//! `target/{profile}/` directory where the `cosmian_pkcs11` cdylib is expected.
//!
//! The cdylib itself is built on-demand by the test helper `ensure_cdylib()`
//! in `src/tests.rs`.  `cargo test --lib` only produces rlib artifacts and does
//! NOT write the `.dylib`/`.so`/`.dll` to `target/{profile}/`, so the tests
//! invoke `cargo build -p cosmian_pkcs11` themselves before loading the library.
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

    // Rebuild when provider sources change.
    println!("cargo:rerun-if-changed=../provider/src");
    println!("cargo:rerun-if-changed=../provider/Cargo.toml");
}
