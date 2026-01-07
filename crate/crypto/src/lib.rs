#![allow(let_underscore_drop)]
pub use error::{CryptoError, result::CryptoResultHelper};

pub mod crypto;
mod error;
pub mod openssl;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() < size {
        bytes.insert(0, 0);
    }
}

// Initialize OpenSSL environment from values provided by build.rs (tests only).
// Keep ctor usage limited to dev/test builds as requested.
#[cfg(test)]
#[allow(unsafe_code)]
#[ctor::ctor]
fn initialize_openssl_env_from_build() {
    let conf_is_set = std::env::var_os("OPENSSL_CONF").is_some();
    let modules_is_set = std::env::var_os("OPENSSL_MODULES").is_some();
    let _ = conf_is_set; // reserved for future use; avoid overriding OPENSSL_CONF here

    if !modules_is_set {
        if let Some(mods) = option_env!("OPENSSL_MODULES") {
            if !mods.is_empty() {
                unsafe {
                    std::env::set_var("OPENSSL_MODULES", mods);
                }
            }
        }
    }

    // Diagnostics to help understand which OpenSSL is loaded under Nix.
    #[allow(unused)]
    {
        let ver_num = ::openssl::version::number();
        let ver_str = ::openssl::version::version();
        eprintln!("[cosmian_kms_crypto:test-init] OpenSSL loaded: {ver_str} (0x{ver_num:x})");
        if let Some(conf) = std::env::var_os("OPENSSL_CONF") {
            eprintln!(
                "[cosmian_kms_crypto:test-init] OPENSSL_CONF={}",
                conf.to_string_lossy()
            );
        }
        if let Some(ct_conf) = option_env!("OPENSSL_CONF") {
            eprintln!("[cosmian_kms_crypto:test-init] COMPILETIME_OPENSSL_CONF={ct_conf}");
        }
        if let Some(mods) = std::env::var_os("OPENSSL_MODULES") {
            eprintln!(
                "[cosmian_kms_crypto:test-init] OPENSSL_MODULES={}",
                mods.to_string_lossy()
            );
        }
        if let Some(ct_mods) = option_env!("OPENSSL_MODULES") {
            eprintln!("[cosmian_kms_crypto:test-init] COMPILETIME_OPENSSL_MODULES={ct_mods}");
        }
    }
}

pub mod reexport {
    #[cfg(feature = "non-fips")]
    pub use cosmian_cover_crypt;
    pub use cosmian_crypto_core;
    pub use cosmian_kmip;
}

#[cfg(test)]
mod tests {
    use std::{env, path::PathBuf, sync::Once};

    static INIT: Once = Once::new();

    /// Ensure OpenSSL environment variables are set for tests (both FIPS and non-FIPS).
    /// Called automatically before any test runs.
    #[allow(unsafe_code)]
    fn ensure_openssl_env() {
        let conf_is_set = env::var_os("OPENSSL_CONF").is_some();
        let modules_is_set = env::var_os("OPENSSL_MODULES").is_some();
        if conf_is_set && modules_is_set {
            return;
        }

        #[cfg(feature = "non-fips")]
        {
            // Non-FIPS mode: prefer OPENSSL_DIR if provided
            if let Ok(dir) = env::var("OPENSSL_DIR") {
                let openssl_dir = PathBuf::from(&dir);
                let conf_path = openssl_dir.join("ssl").join("openssl.cnf");
                let modules_dir = openssl_dir.join("lib").join("ossl-modules");
                if conf_path.exists() {
                    if !conf_is_set {
                        unsafe { env::set_var("OPENSSL_CONF", &conf_path) }
                    }
                    if !modules_is_set && modules_dir.exists() {
                        unsafe { env::set_var("OPENSSL_MODULES", &modules_dir) }
                    }
                    return;
                }
            }

            // Fallback to cargo-built non-fips prefix under target/openssl-non-fips-3.6.0-<os>-<arch>
            let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let workspace_root = crate_dir
                .parent()
                .and_then(|p| p.parent())
                .unwrap_or(&crate_dir)
                .to_path_buf();
            let os = std::env::consts::OS;
            let arch = std::env::consts::ARCH;
            let main_prefix = workspace_root
                .join("target")
                .join(format!("openssl-non-fips-3.6.0-{os}-{arch}"));
            let conf_path = main_prefix.join("ssl").join("openssl.cnf");
            let modules_dir = main_prefix.join("lib").join("ossl-modules");
            if conf_path.exists() && modules_dir.exists() {
                if !conf_is_set {
                    unsafe { env::set_var("OPENSSL_CONF", &conf_path) }
                }
                if !modules_is_set {
                    unsafe { env::set_var("OPENSSL_MODULES", &modules_dir) }
                }
            }
        }

        #[cfg(not(feature = "non-fips"))]
        {
            // Compute workspace root from the current crate path
            // `lib.rs` lives under `crate/crypto`, so go up two levels
            let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let workspace_root = crate_dir
                .parent()
                .and_then(|p| p.parent())
                .unwrap_or(&crate_dir)
                .to_path_buf();

            // FIPS mode: prefer an existing OPENSSL_DIR (e.g. provided by Nix shell) if it contains
            // FIPS artifacts. This avoids falling back to a locally built OpenSSL that
            // may have been compiled against an incompatible glibc version.
            if let Ok(dir) = env::var("OPENSSL_DIR") {
                let openssl_dir = PathBuf::from(&dir);
                let conf_path = openssl_dir.join("ssl").join("openssl.cnf");
                let modules_dir = openssl_dir.join("lib").join("ossl-modules");
                // Detect fips module (Linux .so / macOS .dylib)
                let fips_so = modules_dir.join("fips.so");
                let fips_dylib = modules_dir.join("fips.dylib");
                if conf_path.exists() && (fips_so.exists() || fips_dylib.exists()) {
                    // If under Nix (/nix/store), do not override OPENSSL_CONF.
                    let in_nix = dir.starts_with("/nix/store/");
                    unsafe {
                        if !in_nix && !conf_is_set {
                            env::set_var("OPENSSL_CONF", &conf_path);
                        }
                        if !modules_is_set {
                            env::set_var("OPENSSL_MODULES", &modules_dir);
                        }
                    }
                } else {
                    // Fall back to cargo-built FIPS main prefix under target/openssl-3.6.0-<os>-<arch>
                    let os = std::env::consts::OS;
                    let arch = std::env::consts::ARCH;
                    let main_prefix = workspace_root
                        .join("target")
                        .join(format!("openssl-3.6.0-{os}-{arch}"));
                    let openssl_conf = main_prefix.join("ssl").join("openssl.cnf");
                    let modules_dir = main_prefix.join("lib").join("ossl-modules");
                    if !conf_is_set {
                        unsafe { env::set_var("OPENSSL_CONF", &openssl_conf) }
                    }
                    if !modules_is_set {
                        unsafe { env::set_var("OPENSSL_MODULES", &modules_dir) }
                    }
                }
            } else {
                // No OPENSSL_DIR set, prefer cargo-built FIPS main prefix
                let os = std::env::consts::OS;
                let arch = std::env::consts::ARCH;
                let main_prefix = workspace_root
                    .join("target")
                    .join(format!("openssl-3.6.0-{os}-{arch}"));
                let openssl_conf = main_prefix.join("ssl").join("openssl.cnf");
                let modules_dir = main_prefix.join("lib").join("ossl-modules");
                if !conf_is_set {
                    unsafe { env::set_var("OPENSSL_CONF", &openssl_conf) }
                }
                if !modules_is_set {
                    unsafe { env::set_var("OPENSSL_MODULES", &modules_dir) }
                }
            }
        }
    }

    /// Initialize test environment once before any tests run
    pub(crate) fn init() {
        INIT.call_once(|| {
            ensure_openssl_env();
        });
    }

    #[ctor::ctor]
    fn initialize() {
        init();
        // Initialize OpenSSL after env variables are ensured, so configuration
        // like OPENSSL_CONF/OPENSSL_MODULES is honored (especially under Nix).
        ::openssl::init();
    }
}
