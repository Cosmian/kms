//! Copyright 2025 Cosmian Tech SAS
//!
//! PKCS#11 loader for the Kryoptic HSM backend.

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Default name of the `Kryoptic` `PKCS#11` shared library.
/// Overridable at runtime via the `KRYOPTIC_PKCS11_LIB` environment variable.
#[cfg(target_os = "macos")]
pub const KRYOPTIC_PKCS11_LIB: &str = "libkryoptic_pkcs11.dylib";

#[cfg(not(target_os = "macos"))]
pub const KRYOPTIC_PKCS11_LIB: &str = "libkryoptic_pkcs11.so";

#[cfg(test)]
// Allow test-specific lint patterns for C library integration
#[allow(unsafe_code)]
#[allow(clippy::panic_in_result_fn)]
#[allow(clippy::panic)]
#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::assertions_on_result_states)]
#[allow(clippy::as_conversions)]
#[allow(clippy::map_err_ignore)]
#[allow(clippy::redundant_clone)]
#[allow(clippy::explicit_iter_loop)]
#[cfg(feature = "kryoptic")]
mod tests;

pub struct KryopticCapabilityProvider;

impl HsmProvider for KryopticCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities::default()
    }
}

/// The Kryoptic software HSM is fully supported by the `BaseHsm` implementation.
pub type Kryoptic = cosmian_kms_base_hsm::BaseHsm<KryopticCapabilityProvider>;
