//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Path to the `SoftHSM2` `PKCS#11` shared library.
/// Overridable at runtime via the `SOFTHSM2_PKCS11_LIB` environment variable.
#[cfg(target_os = "linux")]
pub const SOFTHSM2_PKCS11_LIB: &str = "/usr/lib/softhsm/libsofthsm2.so";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const SOFTHSM2_PKCS11_LIB: &str = "/opt/homebrew/lib/softhsm/libsofthsm2.so";

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const SOFTHSM2_PKCS11_LIB: &str = "/usr/local/lib/softhsm/libsofthsm2.so";

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub const SOFTHSM2_PKCS11_LIB: &str = "libsofthsm2.so";

#[cfg(test)]
#[cfg(feature = "softhsm2")]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests;

pub struct SofthsmCapabilityProvider;

impl HsmProvider for SofthsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 32,
            supports_aes_sensitive_attribute: true,
            supports_rsa_sensitive_attribute: true,
            supports_ec_sensitive_attribute: true,
            supports_aes_gcm_caller_iv: true,
            supports_aes_gcm_message: false,
            rsa_oaep_requires_source_data_ptr: true,
            max_label_len: None,
            // `C_SetAttributeValue` stores CKA_START_DATE/CKA_END_DATE in plaintext on private
            // objects, then `C_GetAttributeValue` fails to decrypt them (CKR_GENERAL_ERROR).
            supports_key_dates: false,
            supports_rsa_oaep_key_wrap: false,
            enforces_ecdsa_digest_strength: false,
            max_concurrent_sessions: 128,
        }
    }
}

/// The softhsm2 is fully supported by the `BaseHsm` implementation
pub type Softhsm2 = cosmian_kms_base_hsm::BaseHsm<SofthsmCapabilityProvider>;
