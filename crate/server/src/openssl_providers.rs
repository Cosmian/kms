use std::ffi::{CStr, c_int};
#[cfg(not(feature = "non-fips"))]
use std::ffi::{c_char, c_void};
#[cfg(not(feature = "non-fips"))]
use std::ptr;

use cosmian_logger::info;

#[cfg(not(feature = "non-fips"))]
use crate::error::KmsError;
use crate::result::KResult;

/// Minimum `OpenSSL_version_num()` value that indicates OpenSSL 3.x.
/// Encoding: `MNNFFPPS` where M=major, NN=minor, etc.
#[cfg(feature = "non-fips")]
const OPENSSL_3_0_VERSION_NUMBER: u64 = 0x3000_0000;

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
/// - `version_string` is the OpenSSL version text (e.g., "OpenSSL 3.6.5")
/// - `dir_string` is the OpenSSL installation directory
/// - `version_number` is the numeric version (e.g., 0x30600000 for version 3.6.0)
///
/// If OpenSSL is not available, returns `("<unavailable>", "<unavailable>", 0)`.
#[must_use]
#[expect(
    unsafe_code,
    reason = "raw openssl-sys FFI, NULL-checked before dereferencing"
)]
pub fn safe_openssl_version_info() -> (String, String, u64) {
    // `version::number()` returns a `c_ulong` (u32 on Windows, u64 on Unix); a value that
    // does not fit u64 or is 0 means OpenSSL is unavailable.
    let num = u64::try_from(openssl::version::number()).unwrap_or(0);
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

/// Retrieve human-readable OpenSSL CPU hardware-acceleration feature flags detected
/// at runtime.
///
/// `OpenSSL_version(OPENSSL_CPU_INFO)` (constant `9`, not yet exposed by `openssl-sys`)
/// returns the raw capability bitmask string that OpenSSL assembled during its own
/// `OPENSSL_cpuid_setup` call.  This function decodes that bitmask for the known
/// architectures and falls back to the raw string for unknown ones.
///
/// Supported architectures:
/// - **`x86_64`**: five packed `u64` words (`OPENSSL_ia32cap_P[0..10]`) covering
///   CPUID leaves 1, 7.0, 7.1, and 24.  Each bit is mapped to a well-known flag name.
/// - **`AArch64`**: a single `u32` word (`OPENSSL_armcap_P`) with ARMv7/v8 extension flags.
/// - **`PowerPC`**: a single `u32` word (`OPENSSL_ppccap_P`) with `AltiVec` / VSX flags.
/// - **s390x, RISC-V, other**: the raw OpenSSL string is returned verbatim.
///
/// # Returns
///
/// A `String` such as:
/// ```text
/// OpenSSL CPU features (x86_64): AES-NI, PCLMULQDQ, AVX, AVX2, SHA, RDRAND
/// ```
#[must_use]
#[expect(
    unsafe_code,
    reason = "raw openssl-sys FFI, NULL-checked before dereferencing"
)]
pub fn cpu_features_info() -> String {
    // OPENSSL_CPU_INFO = 9; this constant is not yet exposed by openssl-sys.
    const OPENSSL_CPU_INFO_QUERY: c_int = 9;

    // Liveness check: if OpenSSL is not initialised at all, bail out early
    // rather than risking a crash from `OpenSSL_version`.  This mirrors the
    // guard in `safe_openssl_version_info()`.
    if openssl::version::number() == 0 {
        return "OpenSSL CPU features: <unavailable>".to_owned();
    }

    // SAFETY: `OpenSSL_version` returns a `*const c_char` pointing to a static
    // string owned by the library.  We verified above that OpenSSL is alive
    // (version_num != 0), and we check for NULL before dereferencing via
    // `CStr::from_ptr`.  The returned pointer remains valid for the lifetime of
    // the process.
    let raw = unsafe {
        let ptr = openssl_sys::OpenSSL_version(OPENSSL_CPU_INFO_QUERY);
        if ptr.is_null() {
            return "OpenSSL CPU features: <unavailable>".to_owned();
        }
        match CStr::from_ptr(ptr).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return "OpenSSL CPU features: <invalid utf-8>".to_owned(),
        }
    };

    // Strip optional " env:..." suffix that OpenSSL may append when the
    // OPENSSL_ia32cap / OPENSSL_armcap env vars override capabilities.
    // Also strip the leading "CPUINFO: " prefix that OpenSSL_version(9) includes.
    let raw = raw
        .split_once(" env:")
        .map_or(raw.as_str(), |(head, _)| head)
        .trim_start_matches("CPUINFO: ")
        .trim()
        .to_owned();

    if let Some(hex) = raw.strip_prefix("OPENSSL_ia32cap=") {
        return format!("OpenSSL CPU features (x86_64): {}", decode_ia32cap(hex));
    }
    if let Some(hex) = raw.strip_prefix("OPENSSL_armcap=") {
        return format!("OpenSSL CPU features (aarch64): {}", decode_armcap(hex));
    }
    if let Some(hex) = raw.strip_prefix("OPENSSL_ppccap=") {
        return format!("OpenSSL CPU features (powerpc): {}", decode_ppccap(hex));
    }

    // s390x, RISC-V, or any future architecture: log the raw string verbatim.
    format!("OpenSSL CPU features: {raw}")
}

/// Decode the `x86_64` `OPENSSL_ia32cap` five-word hex string into named flags.
///
/// Format: `0xW0:0xW1:0xW2:0xW3:0xW4` — five packed `u64` where each word packs
/// two 32-bit CPUID output registers (low = first register, high = second register):
///
/// | Word | Low 32 bits     | High 32 bits    |
/// |------|-----------------|-----------------|
/// | 0    | CPUID.1.EDX     | CPUID.1.ECX     |
/// | 1    | CPUID.7.0.EBX   | CPUID.7.0.ECX   |
/// | 2    | CPUID.7.0.EDX   | CPUID.7.1.EAX   |
/// | 3    | CPUID.7.1.EDX   | CPUID.7.1.EBX   |
/// | 4    | CPUID.7.1.ECX   | CPUID.24.0.EBX  |
fn decode_ia32cap(hex: &str) -> String {
    // (word_index, bit_position_within_word, display_name)
    // Bits 0-31 map to the low u32 register; bits 32-63 to the high u32 register.
    #[rustfmt::skip]
    const FLAGS: &[(usize, u32, &str)] = &[
        // Word 0 — CPUID leaf 1, EDX (bits 0-31) + ECX (bits 32-63)
        (0, 23, "MMX"),
        (0, 25, "SSE"),
        (0, 26, "SSE2"),
        (0, 32, "SSE3"),
        (0, 33, "PCLMULQDQ"),
        (0, 41, "SSSE3"),
        (0, 44, "FMA"),
        (0, 51, "SSE4.1"),
        (0, 52, "SSE4.2"),
        (0, 54, "MOVBE"),
        (0, 55, "POPCNT"),
        (0, 57, "AES-NI"),
        (0, 58, "XSAVE"),
        (0, 60, "AVX"),
        (0, 62, "RDRAND"),
        // Word 1 — CPUID leaf 7 subleaf 0, EBX (bits 0-31) + ECX (bits 32-63)
        (1,  3, "BMI1"),
        (1,  5, "AVX2"),
        (1,  8, "BMI2"),
        (1, 16, "AVX512F"),
        (1, 17, "AVX512DQ"),
        (1, 18, "RDSEED"),
        (1, 19, "ADX"),
        (1, 21, "AVX512IFMA"),
        (1, 28, "AVX512CD"),
        (1, 29, "SHA"),
        (1, 30, "AVX512BW"),
        (1, 31, "AVX512VL"),
        (1, 33, "AVX512VBMI"),
        (1, 38, "AVX512VBMI2"),
        (1, 40, "GFNI"),
        (1, 41, "VAES"),
        (1, 42, "VPCLMULQDQ"),
        (1, 43, "AVX512VNNI"),
        (1, 44, "AVX512BITALG"),
        (1, 46, "AVX512VPOPCNTDQ"),
        // Word 2 — CPUID.7.0.EDX (bits 0-31) + CPUID.7.1.EAX (bits 32-63)
        (2,  2, "AVX512-4VNNIW"),
        (2,  3, "AVX512-4FMAPS"),
        (2,  8, "AVX512VP2INTERSECT"),
        (2, 36, "AVX-VNNI"),
        (2, 37, "AVX512-BF16"),
        // Word 3 — CPUID.7.1.EDX (bits 0-31) + CPUID.7.1.EBX (bits 32-63)
        (3, 32, "SHA512"),
        (3, 33, "SM3"),
        (3, 34, "SM4"),
        // Word 4 — CPUID.7.1.ECX (bits 0-31) + CPUID.24.0.EBX (bits 32-63, AVX10)
        (4,  4, "AVX-NE-CONVERT"),
        (4,  5, "AVX-VNNI-INT8"),
    ];

    let words: Vec<u64> = hex
        .split(':')
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .collect();

    if words.len() < 5 {
        return format!("<parse error: {hex}>");
    }

    let enabled: Vec<&str> = FLAGS
        .iter()
        .filter(|&&(w, bit, _)| words.get(w).is_some_and(|word| (word >> bit) & 1 == 1))
        .map(|&(_, _, name)| name)
        .collect();

    if enabled.is_empty() {
        "<none>".to_owned()
    } else {
        enabled.join(", ")
    }
}

/// Decode the `AArch64` `OPENSSL_armcap` single-word hex string into named flags.
///
/// The value is a 32-bit bitmask (`OPENSSL_armcap_P`) populated by the kernel
/// auxiliary vector (`AT_HWCAP` / `AT_HWCAP2`) during `OPENSSL_cpuid_setup`.
fn decode_armcap(hex: &str) -> String {
    #[rustfmt::skip]
    const FLAGS: &[(u32, &str)] = &[
        (1 <<  0, "NEON"),
        (1 <<  2, "ARMV8_AES"),
        (1 <<  3, "ARMV8_SHA1"),
        (1 <<  4, "ARMV8_SHA256"),
        (1 <<  5, "ARMV8_PMULL"),
        (1 <<  6, "ARMV8_SHA512"),
        (1 <<  8, "ARMV8_RNG"),
        (1 <<  9, "ARMV8_SM3"),
        (1 << 10, "ARMV8_SM4"),
        (1 << 11, "ARMV8_SHA3"),
        (1 << 12, "ARMV8_UNROLL8_EOR3"),
        (1 << 13, "ARMV8_SVE"),
        (1 << 14, "ARMV8_SVE2"),
        (1 << 16, "ARMV8_UNROLL12_EOR3"),
    ];

    let cap = u32::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);

    let enabled: Vec<&str> = FLAGS
        .iter()
        .filter(|&&(mask, _)| cap & mask != 0)
        .map(|&(_, name)| name)
        .collect();

    if enabled.is_empty() {
        "<none>".to_owned()
    } else {
        enabled.join(", ")
    }
}

/// Decode the PowerPC `OPENSSL_ppccap` single-word hex string into named flags.
///
/// The value is a 32-bit bitmask (`OPENSSL_ppccap_P`) populated during
/// `OPENSSL_cpuid_setup` from the Linux auxiliary vector.
fn decode_ppccap(hex: &str) -> String {
    #[rustfmt::skip]
    const FLAGS: &[(u32, &str)] = &[
        (1 << 0, "PPC_FPU64"),
        (1 << 1, "PPC_ALTIVEC"),
        (1 << 2, "PPC_CRYPTO207"),
        (1 << 3, "PPC_FPU"),
        (1 << 4, "PPC_MADD300"),
        (1 << 5, "PPC_MFTB"),
    ];

    let cap = u32::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);

    let enabled: Vec<&str> = FLAGS
        .iter()
        .filter(|&&(mask, _)| cap & mask != 0)
        .map(|&(_, name)| name)
        .collect();

    if enabled.is_empty() {
        "<none>".to_owned()
    } else {
        enabled.join(", ")
    }
}

/// Initialize OpenSSL providers for test environments.
///
/// In non-FIPS mode: loads the legacy provider for old PKCS#12 formats
/// (falls back to a warning if it can't be loaded — see [`init_openssl_providers`]).
/// In FIPS mode: no-op (FIPS provider is loaded via openssl.cnf).
///
/// Note: The default provider is already active via openssl.cnf configuration.
/// This function only adds the legacy provider on top of it.
#[cfg(feature = "non-fips")]
pub fn init_openssl_providers_for_tests() {
    use std::sync::OnceLock;

    use cosmian_logger::warn;
    use openssl::provider::Provider;

    // Keep provider alive for program lifetime — it must not be dropped. `None` means
    // the legacy provider could not be loaded (see init_openssl_providers) rather than
    // "not yet initialized".
    static PROVIDER: OnceLock<Option<Provider>> = OnceLock::new();

    PROVIDER.get_or_init(|| {
        // `openssl::provider::Provider` only exists for OpenSSL >= 3: load the legacy
        // provider for old PKCS#12 formats.
        match Provider::try_load(None, "legacy", true) {
            Ok(provider) => Some(provider),
            Err(e) => {
                warn!(
                    "Legacy OpenSSL provider unavailable ({e}); old PKCS#12/RC2 formats \
                     are unsupported in this test run. All other algorithms are unaffected."
                );
                None
            }
        }
    });
}

/// No-op for FIPS builds
#[cfg(not(feature = "non-fips"))]
pub const fn init_openssl_providers_for_tests() {
    // No-op in FIPS mode
}

/// Resolve a fallible provider-load `result` into the `Option<T>` fallback semantics used by
/// [`init_openssl_providers`]: a failure is tolerated (returns `Ok(None)`, invoking
/// `log_warning` once) only when `dlopen_impossible` is `true`; on every other target the
/// failure is propagated unchanged as `Err`.
///
/// Deliberately generic over `T`/`E` (not `Provider`/`ErrorStack`) and free of any `OnceLock`
/// or real OpenSSL call, so this branching decision — the actual bug surface of the
/// musl/crt-static fallback — can be unit-tested directly for both outcomes, without needing
/// a real legacy-provider failure or a musl/crt-static build to reach it. See the `tests`
/// module below.
#[cfg(feature = "non-fips")]
fn resolve_optional_provider<T, E>(
    result: Result<T, E>,
    dlopen_impossible: bool,
    log_warning: impl FnOnce(&E),
) -> Result<Option<T>, E> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) if dlopen_impossible => {
            log_warning(&e);
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Run `load` at most once and cache its outcome in `cell`; later calls are no-ops.
///
/// `Ok(None)` (a tolerated failure, see [`resolve_optional_provider`]) is cached like any
/// other success so the load is never retried; an `Err` is returned to the caller and
/// nothing is cached. Generic and `cell`-injected so tests can use a local `OnceLock`.
#[cfg(feature = "non-fips")]
fn init_optional_provider_once<T, E>(
    cell: &std::sync::OnceLock<Option<T>>,
    load: impl FnOnce() -> Result<Option<T>, E>,
) -> Result<(), E> {
    if cell.get().is_none() {
        drop(cell.set(load()?));
    }
    Ok(())
}

/// Make the FIPS provider the only source of algorithms: default fetch property `fips=yes`, and
/// refuse to run when the unvalidated `default` provider is also in service.
///
/// The `OPENSSL_CONF` of an operator may activate `default`, and nothing else would stop
/// implicit fetches from resolving to its non-validated implementations (including the DRBG).
#[cfg(not(feature = "non-fips"))]
#[expect(
    unsafe_code,
    reason = "OpenSSL provider/property queries not wrapped by the openssl crate"
)]
fn enforce_fips_provider_only() -> KResult<()> {
    // SAFETY: a NULL library context selects the default one; no other pointer is passed.
    let fips_enforced = unsafe {
        openssl_sys::EVP_default_properties_enable_fips(ptr::null_mut(), 1) == 1
            && openssl_sys::EVP_default_properties_is_fips_enabled(ptr::null_mut()) == 1
    };
    if !fips_enforced {
        return Err(KmsError::ServerError(
            "OpenSSL: unable to enforce the `fips=yes` default property".to_owned(),
        ));
    }
    // SAFETY: a NULL library context selects the default one and the name is NUL-terminated.
    let default_in_service =
        unsafe { OSSL_PROVIDER_available(ptr::null_mut(), c"default".as_ptr()) } == 1;
    if default_in_service {
        return Err(KmsError::ServerError(
            "OpenSSL: the non-validated `default` provider is active (check OPENSSL_CONF); the \
             FIPS build must run on the FIPS provider only"
                .to_owned(),
        ));
    }
    Ok(())
}

// `OSSL_PROVIDER_available` is not exposed by `openssl-sys`.
#[cfg(not(feature = "non-fips"))]
#[expect(
    unsafe_code,
    reason = "FFI declaration of a provider API missing from openssl-sys"
)]
unsafe extern "C" {
    fn OSSL_PROVIDER_available(ctx: *mut c_void, name: *const c_char) -> c_int;
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
/// Returns an error if the FIPS provider (FIPS mode) or the default provider
/// (non-FIPS mode, pre-3.0 OpenSSL) fails to load. In FIPS mode it also fails when the
/// `fips=yes` default property cannot be enforced or when the unvalidated `default` provider is
/// in service (an `OPENSSL_CONF` activating it): every algorithm must then come from the
/// validated FIPS module. In non-FIPS mode with OpenSSL >= 3.0, a
/// *legacy* provider load failure propagates as an error on every target **except** a fully
/// static musl build (`target_env = "musl"` + `target_feature = "crt-static"`, i.e. the
/// non-FIPS Alpine `.apk`), where `dlopen` can never succeed and the failure is instead
/// logged as a warning — see below.
pub fn init_openssl_providers() -> KResult<()> {
    use std::sync::OnceLock;

    use openssl::provider::Provider;

    #[cfg(not(feature = "non-fips"))]
    {
        static PROVIDER: OnceLock<Provider> = OnceLock::new();
        if PROVIDER.get().is_none() {
            info!("Load FIPS provider");
            let provider = Provider::load(None, "fips")?;
            enforce_fips_provider_only()?;
            drop(PROVIDER.set(provider));
        }
        Ok(())
    }

    #[cfg(feature = "non-fips")]
    {
        use cosmian_logger::warn;

        // OpenSSL's "legacy" module is a separate shared object loaded via `dlopen`.
        // That can never succeed on a fully static musl binary (the non-FIPS Alpine
        // `.apk` package): musl's static libc has no dynamic linker at all, so `dlopen`
        // always fails there, regardless of `OPENSSL_MODULES`. Every *other* target
        // (glibc static/dynamic OpenSSL linking, dynamic musl, macOS, …) keeps a working
        // dynamic linker, so a load failure there is a genuine misconfiguration (e.g. a
        // broken `OPENSSL_MODULES` path) and must keep failing loudly at startup, as
        // before — only this exact target combination gets the silent, logged fallback.
        const LEGACY_PROVIDER_DLOPEN_IMPOSSIBLE: bool =
            cfg!(all(target_env = "musl", target_feature = "crt-static"));

        // `None` means the legacy provider failed to load on a target where that is
        // expected (see `LEGACY_PROVIDER_DLOPEN_IMPOSSIBLE` above) rather than "not yet
        // initialized".
        static PROVIDER: OnceLock<Option<Provider>> = OnceLock::new();

        Ok(init_optional_provider_once(&PROVIDER, || {
            let ossl_number = u64::try_from(openssl::version::number()).unwrap_or(0);
            if ossl_number >= OPENSSL_3_0_VERSION_NUMBER {
                // OpenSSL 3.x: load the legacy provider for old PKCS#12 formats.
                info!("Load legacy provider");
                resolve_optional_provider(
                    Provider::try_load(None, "legacy", true),
                    LEGACY_PROVIDER_DLOPEN_IMPOSSIBLE,
                    |e| {
                        warn!(
                            "Legacy OpenSSL provider unavailable ({e}); old PKCS#12/RC2 \
                             formats are unsupported on this build. All other algorithms \
                             (including PQC and Covercrypt) are unaffected."
                        );
                    },
                )
            } else {
                // OpenSSL < 3.0: load the default provider
                info!("Load default provider");
                Ok(Some(Provider::load(None, "default")?))
            }
        })?)
    }
}

#[cfg(all(test, not(feature = "non-fips")))]
mod fips_tests {
    use std::{fs, process::Command, ptr};

    use super::{init_openssl_providers, safe_openssl_version_info};

    const CHILD_ENV: &str = "KMS_TEST_DEFAULT_PROVIDER_ACTIVATED";
    const CHILD_TEST: &str =
        "openssl_providers::fips_tests::test_init_refuses_active_default_provider";

    #[test]
    #[expect(unsafe_code, reason = "queries the OpenSSL default property state")]
    fn test_init_enforces_fips_default_property() {
        init_openssl_providers().unwrap();
        // SAFETY: a NULL library context selects the default one.
        let enforced =
            unsafe { openssl_sys::EVP_default_properties_is_fips_enabled(ptr::null_mut()) };
        assert_eq!(enforced, 1);
    }

    /// An `OPENSSL_CONF` that activates the unvalidated `default` provider must stop the server.
    /// The OpenSSL configuration is read once per process, hence the re-executed child.
    #[test]
    fn test_init_refuses_active_default_provider() {
        if std::env::var_os(CHILD_ENV).is_some() {
            let error = init_openssl_providers().unwrap_err().to_string();
            assert!(error.contains("`default` provider is active"), "{error}");
            return;
        }
        // The FIPS module's install status lives next to the configuration in use (the Nix
        // OpenSSL has no `/usr/local/cosmian/lib/ssl`); the compiled-in OPENSSLDIR is the
        // fallback when no `OPENSSL_CONF` is set.
        let (_, version_dir, _) = safe_openssl_version_info();
        let compiled_in = version_dir
            .trim_start_matches("OPENSSLDIR: \"")
            .trim_end_matches('"');
        let ssl_dir = std::env::var_os("OPENSSL_CONF")
            .and_then(|conf| {
                std::path::Path::new(&conf)
                    .parent()
                    .map(|dir| dir.display().to_string())
            })
            .unwrap_or_else(|| compiled_in.to_owned());
        let conf = format!(
            "openssl_conf = openssl_init\n.include {ssl_dir}/fipsmodule.cnf\n[openssl_init]\n\
             providers = provider_sect\n[provider_sect]\nfips = fips_sect\nbase = base_sect\n\
             default = default_sect\n[base_sect]\nactivate = 1\n[default_sect]\nactivate = 1\n"
        );
        let conf_path =
            std::env::temp_dir().join(format!("kms-default-active-{}.cnf", std::process::id()));
        fs::write(&conf_path, conf).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env("OPENSSL_CONF", &conf_path)
            .output()
            .unwrap();
        drop(fs::remove_file(&conf_path));
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(all(test, feature = "non-fips"))]
mod tests {
    use super::{init_openssl_providers, resolve_optional_provider};

    /// `init_openssl_providers` must never hard-fail in non-FIPS mode on a normal
    /// (dynamically-linked) test/dev target, and must be idempotent (safe to call more
    /// than once — e.g. once per Actix worker thread).
    ///
    /// This only exercises the success path (the legacy provider loads fine on a normal
    /// dev/CI machine); it cannot reach the musl/crt-static fallback branch, nor the
    /// propagate-the-error branch. Those are covered directly and deterministically by the
    /// `resolve_optional_provider` tests below instead.
    #[test]
    fn test_init_openssl_providers_succeeds_and_is_idempotent() {
        init_openssl_providers().expect("first call must succeed");
        init_openssl_providers().expect("second call must also succeed (OnceLock guard)");
    }

    /// On every target *except* a fully static musl build, a failed load must propagate as
    /// `Err` rather than being silently swallowed — this is the exact regression finding #1
    /// of the alpine-branch review fixed (the fallback had no scoping at all).
    #[test]
    fn test_resolve_optional_provider_propagates_error_when_dlopen_not_impossible() {
        let result: Result<u8, &str> = Err("legacy module not found");
        let mut warned = false;
        let resolved = resolve_optional_provider(result, false, |_| warned = true);
        assert_eq!(resolved, Err("legacy module not found"));
        assert!(
            !warned,
            "must not log a reassuring warning when the failure is actually being propagated"
        );
    }

    /// On a fully static musl build (`dlopen_impossible = true`), a failed load must be
    /// tolerated: turned into `Ok(None)` with the warning callback invoked exactly once.
    #[test]
    fn test_resolve_optional_provider_falls_back_when_dlopen_impossible() {
        let result: Result<u8, &str> = Err("legacy module not found");
        let mut warned = false;
        let resolved = resolve_optional_provider(result, true, |_| warned = true);
        assert_eq!(resolved, Ok(None));
        assert!(warned, "must log a warning when tolerating the failure");
    }

    /// A successful load must always be returned as `Some(value)`, regardless of
    /// `dlopen_impossible`, and must never invoke the warning callback.
    #[test]
    fn test_resolve_optional_provider_success_ignores_dlopen_impossible_flag() {
        for dlopen_impossible in [false, true] {
            let result: Result<u8, &str> = Ok(42);
            let mut warned = false;
            let resolved = resolve_optional_provider(result, dlopen_impossible, |_| warned = true);
            assert_eq!(resolved, Ok(Some(42)));
            assert!(!warned, "must not warn on a successful load");
        }
    }

    /// A failing loader on a dlopen-impossible target must make initialization return
    /// `Ok(())`, cache the failure as `None`, and never invoke the loader again.
    #[test]
    fn test_init_optional_provider_once_caches_tolerated_failure_without_retry() {
        use std::{cell::Cell, sync::OnceLock};

        use super::init_optional_provider_once;

        let cell: OnceLock<Option<u8>> = OnceLock::new();
        let calls = Cell::new(0_u32);
        let failing_loader = || {
            calls.set(calls.get() + 1);
            resolve_optional_provider(Err::<u8, _>("legacy module not found"), true, |_| {})
        };

        assert_eq!(init_optional_provider_once(&cell, failing_loader), Ok(()));
        assert_eq!(cell.get(), Some(&None), "Err must be cached as None");
        assert_eq!(init_optional_provider_once(&cell, failing_loader), Ok(()));
        assert_eq!(calls.get(), 1, "loader must not be retried after caching");
    }

    /// When the failure is propagated, it is returned and nothing is cached.
    #[test]
    fn test_init_optional_provider_once_propagates_error_without_caching() {
        use std::sync::OnceLock;

        use super::init_optional_provider_once;

        let cell: OnceLock<Option<u8>> = OnceLock::new();
        let result = init_optional_provider_once(&cell, || {
            resolve_optional_provider(Err::<u8, _>("boom"), false, |_| {})
        });
        assert_eq!(result, Err("boom"));
        assert!(cell.get().is_none());
    }
}
