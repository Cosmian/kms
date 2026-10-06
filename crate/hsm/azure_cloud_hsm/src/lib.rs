//! Azure Cloud HSM PKCS#11 loader.

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Default path to the Azure Cloud HSM PKCS#11 shared library on Linux.
pub const AZURE_CLOUD_HSM_PKCS11_LIB: &str = "/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so";

#[cfg(test)]
#[cfg(feature = "azure_cloud_hsm")]
mod tests;

/// Capability provider for Azure Cloud HSM.
pub struct AzureCloudHsmCapabilityProvider;

impl HsmProvider for AzureCloudHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
            supports_aes_sensitive_attribute: false,
            supports_rsa_sensitive_attribute: false,
            supports_ec_sensitive_attribute: false,
            supports_aes_gcm_caller_iv: false,
            max_label_len: None,
            skip_finalize_on_drop: true,
        }
    }
}

/// Azure Cloud HSM is supported by the generic `BaseHsm` implementation.
pub type AzureCloudHsm = cosmian_kms_base_hsm::BaseHsm<AzureCloudHsmCapabilityProvider>;
