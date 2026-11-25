pub use error::{CryptoError, result::CryptoResultHelper};

pub mod crypto;
mod error;
pub mod kat_vectors;
pub mod openssl;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() < size {
        bytes.insert(0, 0);
    }
}

// Argon2id and AES-GCM-SIV are fetched from OpenSSL's default provider. Tests that explicitly
// load (and later drop) a provider disable the implicit default fallback and unload the
// provider under concurrently running tests, so pin it for the whole test process.
#[cfg(all(test, feature = "non-fips"))]
fn pin_default_provider() {
    static DEFAULT_PROVIDER: std::sync::LazyLock<Option<::openssl::provider::Provider>> =
        std::sync::LazyLock::new(|| {
            ::openssl::provider::Provider::try_load(None, "default", true).ok()
        });
    std::sync::LazyLock::force(&DEFAULT_PROVIDER);
}

#[cfg(all(test, not(feature = "non-fips")))]
const fn pin_default_provider() {}

// Initialize OpenSSL environment from values provided by build.rs (tests only).
// Keep ctor usage limited to dev/test builds as requested.
#[cfg(test)]
#[expect(unsafe_code, reason = "std::env::set_var is unsafe in edition 2024")]
#[ctor::ctor]
fn initialize_openssl_env_from_build() {
    let modules_is_set = std::env::var_os("OPENSSL_MODULES").is_some();

    if !modules_is_set
        && let Some(mods) = option_env!("OPENSSL_MODULES")
        && !mods.is_empty()
    {
        unsafe {
            std::env::set_var("OPENSSL_MODULES", mods);
        }
    }

    pin_default_provider();

    // Diagnostics to help understand which OpenSSL is loaded under Nix.
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

    /// `true` when `modules` holds the provider this build needs: the FIPS provider in FIPS mode.
    #[cfg(not(feature = "non-fips"))]
    fn has_required_provider(modules: &std::path::Path) -> bool {
        modules.join("fips.so").exists() || modules.join("fips.dylib").exists()
    }

    /// `true` when `modules` holds the provider this build needs: any module in non-FIPS mode.
    #[cfg(feature = "non-fips")]
    fn has_required_provider(modules: &std::path::Path) -> bool {
        modules.exists()
    }

    /// `(conf, modules)` of an `OPENSSL_DIR` tree (e.g. provided by the Nix shell) holding what
    /// this build needs, so a locally built OpenSSL compiled against an incompatible glibc is not
    /// used instead. Under Nix, `OPENSSL_CONF` is left untouched.
    fn openssl_dir_paths(dir: &str) -> Option<(Option<PathBuf>, PathBuf)> {
        let root = PathBuf::from(dir);
        let conf = root.join("ssl").join("openssl.cnf");
        let modules = root.join("lib").join("ossl-modules");
        (conf.exists() && has_required_provider(&modules))
            .then(|| ((!dir.starts_with("/nix/store/")).then_some(conf), modules))
    }

    /// Ensure OpenSSL environment variables are set for tests (both FIPS and non-FIPS).
    /// Called automatically before any test runs.
    #[expect(unsafe_code, reason = "std::env::set_var is unsafe in edition 2024")]
    fn ensure_openssl_env() {
        let conf_is_set = env::var_os("OPENSSL_CONF").is_some();
        let modules_is_set = env::var_os("OPENSSL_MODULES").is_some();
        if conf_is_set && modules_is_set {
            return;
        }

        // Otherwise use the prefix `build.rs` built and exported at compile time.
        let Some((conf, modules)) = env::var("OPENSSL_DIR")
            .ok()
            .and_then(|dir| openssl_dir_paths(&dir))
            .or_else(|| {
                Some((
                    Some(PathBuf::from(option_env!("OPENSSL_CONF")?)),
                    PathBuf::from(option_env!("OPENSSL_MODULES")?),
                ))
            })
        else {
            return;
        };
        if !conf_is_set && let Some(conf) = conf {
            unsafe { env::set_var("OPENSSL_CONF", conf) }
        }
        if !modules_is_set {
            unsafe { env::set_var("OPENSSL_MODULES", modules) }
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
#[cfg(test)]
mod lint_cleanup_characterization_tests;
