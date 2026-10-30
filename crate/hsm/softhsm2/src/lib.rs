//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

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
#[cfg(feature = "softhsm2")]
mod tests;

pub struct SofthsmCapabilityProvider;

impl HsmProvider for SofthsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 32,
            aes: AesCapabilities {
                supports_sensitive_attribute: true,
                key_wrap_pad_is_rfc5649: true,
                gcm: AesGcmCapabilities {
                    supports_caller_iv: true,
                    // Development token, not a FIPS-validated module.
                    allows_caller_iv_in_fips: true,
                    supports_message: false,
                },
            },
            rsa: RsaCapabilities {
                supports_sensitive_attribute: true,
                oaep_requires_source_data_ptr: true,
                supports_oaep_key_wrap: false,
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: true,
                enforces_ecdsa_digest_strength: false,
            },
            supports_message_sign_verify: false,
            max_label_len: None,
            // `C_SetAttributeValue` stores CKA_START_DATE/CKA_END_DATE in plaintext on private
            // objects, then `C_GetAttributeValue` fails to decrypt them (CKR_GENERAL_ERROR).
            supports_key_dates: false,
            skip_finalize_on_drop: false,
            max_concurrent_sessions: 128,
        }
    }
}

/// The softhsm2 is fully supported by the `BaseHsm` implementation
pub type Softhsm2 = cosmian_kms_base_hsm::BaseHsm<SofthsmCapabilityProvider>;

/// Capability profile for `hsm_model = "other"`: `SoftHSM2`'s PKCS#11 quirks, but treated as a
/// FIPS-validated module (no caller-chosen AES-GCM IV in FIPS builds, like the other production
/// HSMs; a non-FIPS build still sends one) and trying the PKCS#11 v3 message API when the
/// library exports it.
pub struct OtherCapabilityProvider;

impl HsmProvider for OtherCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        let mut capabilities = SofthsmCapabilityProvider::capabilities();
        capabilities.aes.gcm.allows_caller_iv_in_fips = false;
        capabilities.aes.gcm.supports_message = true;
        capabilities
    }
}

/// Generic PKCS#11 HSM (`hsm_model = "other"`).
pub type OtherHsm = cosmian_kms_base_hsm::BaseHsm<OtherCapabilityProvider>;

#[cfg(test)]
mod capability_tests {
    use cosmian_kms_base_hsm::hsm_capabilities::HsmProvider;

    use super::{OtherCapabilityProvider, SofthsmCapabilityProvider};

    #[test]
    fn only_the_development_token_may_send_a_caller_gcm_iv_in_fips() {
        assert!(
            !OtherCapabilityProvider::capabilities()
                .aes
                .gcm
                .allows_caller_iv_in_fips
        );
        assert!(
            SofthsmCapabilityProvider::capabilities()
                .aes
                .gcm
                .allows_caller_iv_in_fips
        );
    }
}
