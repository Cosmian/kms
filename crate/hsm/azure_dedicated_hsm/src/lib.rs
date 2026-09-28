//! Azure Dedicated HSM (Thales Luna 7) PKCS#11 loader.

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Default path to the Thales Luna 7 PKCS#11 shared library on Linux.
pub const AZURE_DEDICATED_HSM_PKCS11_LIB: &str = "/usr/lib/libCryptoki2_64.so";

#[cfg(test)]
#[cfg(feature = "azure_dedicated_hsm")]
mod tests;

/// Capability provider for Azure Dedicated HSM backed by Thales Luna 7.
pub struct AzureDedicatedHsmCapabilityProvider;

impl HsmProvider for AzureDedicatedHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
            supports_aes_sensitive_attribute: false,
            supports_rsa_sensitive_attribute: false,
            supports_ec_sensitive_attribute: false,
            supports_aes_gcm_caller_iv: false,
        }
    }
}

/// Azure Dedicated HSM is fully supported by the generic BaseHsm implementation.
pub type AzureDedicatedHsm = cosmian_kms_base_hsm::BaseHsm<AzureDedicatedHsmCapabilityProvider>;
