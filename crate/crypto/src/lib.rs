pub use error::{CryptoError, result::CryptoResultHelper};

pub mod crypto;
mod error;
pub mod openssl;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() < size {
        bytes.insert(0, 0);
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
            // Non-FIPS mode: Check for custom OpenSSL provided via OPENSSL_DIR (e.g., from Nix)
            if let Ok(dir) = env::var("OPENSSL_DIR") {
                let openssl_dir = PathBuf::from(&dir);
                let conf_path = openssl_dir.join("ssl").join("openssl.cnf");
                let modules_dir = openssl_dir.join("lib").join("ossl-modules");

                if conf_path.exists() {
                    if !conf_is_set {
                        unsafe {
                            env::set_var("OPENSSL_CONF", &conf_path);
                        }
                    }
                    if !modules_is_set && modules_dir.exists() {
                        unsafe {
                            env::set_var("OPENSSL_MODULES", &modules_dir);
                        }
                    }
                }
            }

            // Fall back to system OpenSSL for non-FIPS builds (no custom config needed)
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
                    unsafe {
                        if !conf_is_set {
                            env::set_var("OPENSSL_CONF", &conf_path);
                        }
                        if !modules_is_set {
                            env::set_var("OPENSSL_MODULES", &modules_dir);
                        }
                    }
                } else {
                    // Fall back to locally built FIPS OpenSSL (built by build.rs in crate/server)
                    // The build folder already contains everything needed:
                    // - target/openssl-fips-3.1.2-{os}-{arch}/ssl/openssl.cnf
                    // - target/openssl-fips-3.1.2-{os}-{arch}/ssl/fipsmodule.cnf
                    // - target/openssl-fips-3.1.2-{os}-{arch}/lib/ossl-modules/fips.so (or .dylib on macOS)
                    let os = std::env::consts::OS;
                    let arch = std::env::consts::ARCH;

                    let target_dir = workspace_root
                        .join("target")
                        .join(format!("openssl-fips-3.1.2-{os}-{arch}"));
                    let openssl_conf = target_dir.join("ssl").join("openssl.cnf");
                    let modules_dir = target_dir.join("lib").join("ossl-modules");

                    if !conf_is_set {
                        unsafe {
                            env::set_var("OPENSSL_CONF", &openssl_conf);
                        }
                    }
                    if !modules_is_set {
                        unsafe {
                            env::set_var("OPENSSL_MODULES", &modules_dir);
                        }
                    }
                }
            } else {
                // No OPENSSL_DIR set, use locally built FIPS OpenSSL
                let os = std::env::consts::OS;
                let arch = std::env::consts::ARCH;

                let target_dir = workspace_root
                    .join("target")
                    .join(format!("openssl-fips-3.1.2-{os}-{arch}"));
                let openssl_conf = target_dir.join("ssl").join("openssl.cnf");
                let modules_dir = target_dir.join("lib").join("ossl-modules");

                if !conf_is_set {
                    unsafe {
                        env::set_var("OPENSSL_CONF", &openssl_conf);
                    }
                }
                if !modules_is_set {
                    unsafe {
                        env::set_var("OPENSSL_MODULES", &modules_dir);
                    }
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
    }
}
