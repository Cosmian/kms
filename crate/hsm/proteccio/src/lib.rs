//! Copyright 2024 Cosmian Tech SAS
use cosmian_kms_base_hsm::{
    BaseHsm,
    hsm_capabilities::{HsmCapabilities, HsmProvider},
};

/// Path to the Proteccio `PKCS#11` shared library
pub const PROTECCIO_PKCS11_LIB: &str = "/lib/libnethsm.so";

pub struct ProteccioCapabilityProvider;

impl HsmProvider for ProteccioCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
            supports_aes_sensitive_attribute: true,
            supports_aes_class_attribute: true,
            supports_aes_key_type_attribute: true,
            supports_aes_value_len_attribute: true,
            supports_aes_token_attribute: true,
            supports_aes_usage_attributes: true,
            supports_aes_label_attribute: true,
            supports_aes_id_attribute: true,
            aes_algorithm_attribute: None,
            supports_rsa_sensitive_attribute: true,
            supports_ec_sensitive_attribute: true,
            supports_aes_gcm_caller_iv: true,
            aes_gcm_mechanism: 0x1087,
            supports_aes_gcm_message: true,
            rsa_oaep_requires_source_data_ptr: false,
            max_label_len: Some(128),
            supports_key_dates: true,
            supports_rsa_oaep_key_wrap: true,
            enforces_ecdsa_digest_strength: false,
        }
    }
}

pub type Proteccio = BaseHsm<ProteccioCapabilityProvider>;

#[cfg(test)]
#[cfg(feature = "proteccio")]
mod tests;
