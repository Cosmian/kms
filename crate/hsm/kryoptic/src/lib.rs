//! Copyright 2025 Cosmian Tech SAS
//!
//! PKCS#11 loader for the Kryoptic HSM backend.

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Default name of the `Kryoptic` `PKCS#11` shared library.
/// Overridable at runtime via the `KRYOPTIC_PKCS11_LIB` environment variable.
#[cfg(target_os = "macos")]
pub const KRYOPTIC_PKCS11_LIB: &str = "libkryoptic_pkcs11.dylib";

/// Default name of the `Kryoptic` `PKCS#11` shared library.
/// Overridable at runtime via the `KRYOPTIC_PKCS11_LIB` environment variable.
#[cfg(not(target_os = "macos"))]
pub const KRYOPTIC_PKCS11_LIB: &str = "libkryoptic_pkcs11.so";

#[cfg(test)]
#[cfg(feature = "kryoptic")]
#[expect(
    unsafe_code,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only: loading a C shared library and calling through its function table is \
              inherently unsafe, and a misconfigured test environment should fail loudly"
)]
mod tests;

/// Capability profile for the `Kryoptic` software token.
///
/// Every value is [`HsmCapabilities::default`] — no CBC chunking limit, and
/// `find_max_object_count = 1` — because `Kryoptic` is used here purely as a `PKCS#11` v3.0
/// conformance oracle rather than as a production backend, so none of its limits have been
/// measured the way the vendor HSM profiles' have. The defaults are conservative, not tuned:
/// in particular a `find_max_object_count` of 1 makes `C_FindObjects` return one handle per
/// call, which is correct but chattier than the 16–64 the vendor loaders use. Worth revisiting
/// if `Kryoptic` ever becomes a supported backend.
pub struct KryopticCapabilityProvider;

impl HsmProvider for KryopticCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities::default()
    }
}

/// The Kryoptic software HSM is fully supported by the `BaseHsm` implementation.
pub type Kryoptic = cosmian_kms_base_hsm::BaseHsm<KryopticCapabilityProvider>;
