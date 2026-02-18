use std::ffi::CStr;

#[cfg(feature = "non-fips")]
use cosmian_logger::info;

/// Safely retrieve OpenSSL version information without risking a segmentation
/// fault.  In some edge-case environments (missing OpenSSL shared library,
/// incomplete installation, restricted container, …) the underlying
/// `OpenSSL_version` C function may return a NULL pointer or call through an
/// uninitialised function-pointer table, both of which cause a SIGSEGV.
///
/// This helper calls the raw `openssl-sys` FFI directly so it can check for a
/// NULL return *before* converting to a Rust `&str`.
///
/// # Returns
///
/// Returns a tuple of `(version_string, dir_string, version_number)` where:
/// - `version_string` is the OpenSSL version text (e.g., "OpenSSL 3.6.0")
/// - `dir_string` is the OpenSSL installation directory
/// - `version_number` is the numeric version (e.g., 0x30600000 for version 3.6.0)
///
/// If OpenSSL is not available, returns `("<unavailable>", "<unavailable>", 0)`.
#[allow(unsafe_code)]
#[must_use]
pub fn safe_openssl_version_info() -> (String, String, u64) {
    // SAFETY: `OpenSSL_version_num` returns a plain integer and never
    // dereferences any pointer, so it is safe to call even when OpenSSL is not
    // fully initialised.  We call it first as a cheap liveness check.
    // Note: Returns `c_ulong` which is u32 on Windows and u64 on Unix.
    // We need `as u64` for cross-platform compatibility (widening is safe).
    #[allow(clippy::as_conversions)]
    let num = unsafe { openssl_sys::OpenSSL_version_num() } as u64;
    if num == 0 {
        return ("<unavailable>".to_owned(), "<unavailable>".to_owned(), 0);
    }

    // SAFETY: `OpenSSL_version` returns a `*const c_char` pointing to a static
    // string.  We check for NULL before creating a `CStr`.
    let version = unsafe {
        let ptr = openssl_sys::OpenSSL_version(openssl_sys::OPENSSL_VERSION);
        if ptr.is_null() {
            "<unavailable>".to_owned()
        } else {
            CStr::from_ptr(ptr)
                .to_str()
                .unwrap_or("<invalid utf-8>")
                .to_owned()
        }
    };

    let dir = unsafe {
        let ptr = openssl_sys::OpenSSL_version(openssl_sys::OPENSSL_DIR);
        if ptr.is_null() {
            "<unavailable>".to_owned()
        } else {
            CStr::from_ptr(ptr)
                .to_str()
                .unwrap_or("<invalid utf-8>")
                .to_owned()
        }
    };

    (version, dir, num)
}

/// Initialize OpenSSL providers for test environments.
///
/// In non-FIPS mode with OpenSSL >= 3.0: loads the legacy provider for old PKCS#12 formats.
/// In non-FIPS mode with OpenSSL < 3.0: loads the default provider.
/// In FIPS mode: no-op (FIPS provider is loaded via openssl.cnf).
///
/// Note: The default provider is already active via openssl.cnf configuration.
/// This function only adds the legacy provider on top of it.
#[cfg(feature = "non-fips")]
#[allow(
    unsafe_code,
    clippy::as_conversions,
    clippy::missing_panics_doc,
    clippy::expect_used
)]
pub fn init_openssl_providers_for_tests() {
    use std::sync::OnceLock;

    use openssl::provider::Provider;

    // Keep provider alive for program lifetime — it must not be dropped
    static PROVIDER: OnceLock<Provider> = OnceLock::new();

    PROVIDER.get_or_init(|| {
        let ossl_number = unsafe { openssl_sys::OpenSSL_version_num() as u64 };
        if ossl_number >= 0x3000_0000 {
            // OpenSSL 3.x: load the legacy provider for old PKCS#12 formats
            Provider::try_load(None, "legacy", true).expect("Failed to load legacy provider")
        } else {
            // OpenSSL < 3.0: load the default provider
            Provider::load(None, "default").expect("Failed to load default provider")
        }
    });
}

/// No-op for FIPS builds
#[cfg(not(feature = "non-fips"))]
pub const fn init_openssl_providers_for_tests() {
    // No-op in FIPS mode
}

/// Initialize OpenSSL providers for production KMS server.
///
/// For FIPS mode: loads the FIPS provider.
/// For non-FIPS mode with OpenSSL >= 3.0: loads the legacy provider for old PKCS#12 formats.
/// For non-FIPS mode with OpenSSL < 3.0: loads the default provider.
///
/// Note: In non-FIPS mode, the default provider is already active via openssl.cnf.
/// This function only adds the legacy provider on top of it.
///
/// This function uses `OnceLock` to ensure providers are loaded only once and kept alive
/// for the lifetime of the program.
///
/// # Errors
///
/// Returns an error if the provider fails to load.
#[allow(unsafe_code, clippy::as_conversions)]
pub fn init_openssl_providers() -> Result<(), openssl::error::ErrorStack> {
    use std::sync::OnceLock;

    use openssl::provider::Provider;

    #[cfg(not(feature = "non-fips"))]
    {
        static PROVIDER: OnceLock<Provider> = OnceLock::new();
        if PROVIDER.get().is_none() {
            let provider = Provider::load(None, "fips")?;
            drop(PROVIDER.set(provider));
        }
        Ok(())
    }

    #[cfg(feature = "non-fips")]
    {
        static PROVIDER: OnceLock<Provider> = OnceLock::new();

        if PROVIDER.get().is_none() {
            let ossl_number = unsafe { openssl_sys::OpenSSL_version_num() as u64 };
            let provider = if ossl_number >= 0x3000_0000 {
                // OpenSSL 3.x: load the legacy provider for old PKCS#12 formats
                info!("Load legacy provider");
                Provider::try_load(None, "legacy", true)?
            } else {
                // OpenSSL < 3.0: load the default provider
                info!("Load default provider");
                Provider::load(None, "default")?
            };
            drop(PROVIDER.set(provider));
        }
        Ok(())
    }
}
