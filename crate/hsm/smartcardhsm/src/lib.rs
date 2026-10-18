//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Path to the `SmartcardHSM` `PKCS#11` shared library
pub const SMARTCARDHSM_PKCS11_LIB: &str = "/usr/local/lib/libsc-hsm-pkcs11.so";

#[cfg(test)]
#[cfg(feature = "smartcardhsm")]
mod tests;

pub struct SmartcardHsmCapabilityProvider;

impl HsmProvider for SmartcardHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: Some(1024),
            find_max_object_count: 16, // Don't overwhelm the smart card
            supports_aes_sensitive_attribute: true,
            supports_rsa_sensitive_attribute: true,
            supports_ec_sensitive_attribute: true,
            supports_aes_gcm_caller_iv: true,
            supports_aes_gcm_message: true,
            rsa_oaep_requires_source_data_ptr: false,
            max_label_len: None,
            supports_key_dates: true,
            supports_rsa_oaep_key_wrap: false,
            enforces_ecdsa_digest_strength: false,
            max_concurrent_sessions: 8,
        }
    }
}

/// The smartcardhsm is fully supported by the `BaseHsm` implementation
pub type Smartcardhsm = cosmian_kms_base_hsm::BaseHsm<SmartcardHsmCapabilityProvider>;
