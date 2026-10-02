//! GCP Cloud HSM PKCS#11 provider.

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Default path for Google's `libkmsp11.so` PKCS#11 compatibility library.
pub const GCP_CLOUD_HSM_PKCS11_LIB: &str = "/usr/lib/x86_64-linux-gnu/libkmsp11.so";

#[cfg(test)]
#[cfg(feature = "gcp_cloud_hsm")]
mod tests;

/// Capability provider for Google's Cloud KMS PKCS#11 library.
pub struct GcpCloudHsmCapabilityProvider;

impl HsmProvider for GcpCloudHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
            supports_aes_sensitive_attribute: false,
            supports_aes_class_attribute: false,
            supports_aes_key_type_attribute: false,
            supports_aes_value_len_attribute: false,
            supports_aes_token_attribute: false,
            supports_aes_usage_attributes: false,
            supports_aes_label_attribute: true,
            supports_aes_id_attribute: false,
            aes_algorithm_attribute: Some((0x8001_E101, 19)),
            supports_rsa_sensitive_attribute: false,
            supports_ec_sensitive_attribute: false,
            supports_aes_gcm_caller_iv: false,
            aes_gcm_mechanism: 0x8001_E101,
            supports_aes_gcm_message: false,
            rsa_oaep_requires_source_data_ptr: false,
            max_label_len: None,
            supports_key_dates: false,
            supports_rsa_oaep_key_wrap: false,
            enforces_ecdsa_digest_strength: false,
        }
    }
}

/// GCP Cloud HSM backed by the generic PKCS#11 HSM implementation.
/// GCP Cloud HSM backed by the generic PKCS#11 HSM implementation.
pub type GcpCloudHsm = cosmian_kms_base_hsm::BaseHsm<GcpCloudHsmCapabilityProvider>;
