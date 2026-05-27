use std::ffi::{CStr, c_int};

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
/// - `version_string` is the OpenSSL version text (e.g., "OpenSSL 3.6.2")
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
    // We need `u64::from()` for cross-platform compatibility (widening is safe).
    #[allow(clippy::useless_conversion)]
    let num = u64::from(unsafe { openssl_sys::OpenSSL_version_num() });
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
/// - **x86_64**: five packed `u64` words (`OPENSSL_ia32cap_P[0..10]`) covering
///   CPUID leaves 1, 7.0, 7.1, and 24.  Each bit is mapped to a well-known flag name.
/// - **AArch64**: a single `u32` word (`OPENSSL_armcap_P`) with ARMv7/v8 extension flags.
/// - **PowerPC**: a single `u32` word (`OPENSSL_ppccap_P`) with AltiVec / VSX flags.
/// - **s390x, RISC-V, other**: the raw OpenSSL string is returned verbatim.
///
/// # Returns
///
/// A `String` such as:
/// ```text
/// OpenSSL CPU features (x86_64): AES-NI, PCLMULQDQ, AVX, AVX2, SHA, RDRAND
/// ```
#[allow(unsafe_code)]
#[must_use]
pub fn cpu_features_info() -> String {
    // OPENSSL_CPU_INFO = 9; this constant is not yet exposed by openssl-sys.
    const OPENSSL_CPU_INFO_QUERY: c_int = 9;

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

/// Decode the x86_64 `OPENSSL_ia32cap` five-word hex string into named flags.
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
    let words: Vec<u64> = hex
        .split(':')
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .collect();

    if words.len() < 5 {
        return format!("<parse error: {hex}>");
    }

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

    let enabled: Vec<&str> = FLAGS
        .iter()
        .filter(|&&(w, bit, _)| (words[w] >> bit) & 1 == 1)
        .map(|&(_, _, name)| name)
        .collect();

    if enabled.is_empty() {
        "<none>".to_owned()
    } else {
        enabled.join(", ")
    }
}

/// Decode the AArch64 `OPENSSL_armcap` single-word hex string into named flags.
///
/// The value is a 32-bit bitmask (`OPENSSL_armcap_P`) populated by the kernel
/// auxiliary vector (AT_HWCAP / AT_HWCAP2) during `OPENSSL_cpuid_setup`.
fn decode_armcap(hex: &str) -> String {
    let cap =
        u32::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);

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
    let cap =
        u32::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);

    #[rustfmt::skip]
    const FLAGS: &[(u32, &str)] = &[
        (1 << 0, "PPC_FPU64"),
        (1 << 1, "PPC_ALTIVEC"),
        (1 << 2, "PPC_CRYPTO207"),
        (1 << 3, "PPC_FPU"),
        (1 << 4, "PPC_MADD300"),
        (1 << 5, "PPC_MFTB"),
    ];

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
/// In non-FIPS mode with OpenSSL >= 3.0: loads the legacy provider for old PKCS#12 formats.
/// In non-FIPS mode with OpenSSL < 3.0: loads the default provider.
/// In FIPS mode: no-op (FIPS provider is loaded via openssl.cnf).
///
/// Note: The default provider is already active via openssl.cnf configuration.
/// This function only adds the legacy provider on top of it.
#[cfg(feature = "non-fips")]
#[allow(unsafe_code, clippy::missing_panics_doc, clippy::expect_used)]
pub fn init_openssl_providers_for_tests() {
    use std::sync::OnceLock;

    use openssl::provider::Provider;

    // Keep provider alive for program lifetime — it must not be dropped
    static PROVIDER: OnceLock<Provider> = OnceLock::new();

    PROVIDER.get_or_init(|| {
        #[allow(clippy::useless_conversion)]
        let ossl_number = u64::from(unsafe { openssl_sys::OpenSSL_version_num() });
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
#[allow(unsafe_code)]
pub fn init_openssl_providers() -> Result<(), openssl::error::ErrorStack> {
    use std::sync::OnceLock;

    use openssl::provider::Provider;

    #[cfg(not(feature = "non-fips"))]
    {
        static PROVIDER: OnceLock<Provider> = OnceLock::new();
        if PROVIDER.get().is_none() {
            info!("Load FIPS provider");
            let provider = Provider::load(None, "fips")?;
            drop(PROVIDER.set(provider));
        }
        Ok(())
    }

    #[cfg(feature = "non-fips")]
    {
        static PROVIDER: OnceLock<Provider> = OnceLock::new();

        if PROVIDER.get().is_none() {
            #[allow(clippy::useless_conversion)]
            let ossl_number = u64::from(unsafe { openssl_sys::OpenSSL_version_num() });
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
