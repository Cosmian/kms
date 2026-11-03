//! Azure Cloud HSM PKCS#11 loader.

use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

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
            aes: AesCapabilities {
                supports_sensitive_attribute: false,
                key_wrap_pad_is_rfc5649: false,
                gcm: AesGcmCapabilities {
                    supports_caller_iv: false,
                    allows_caller_iv_in_fips: false,
                    ..AesGcmCapabilities::default()
                },
            },
            rsa: RsaCapabilities {
                supports_sensitive_attribute: false,
                ..RsaCapabilities::default()
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: false,
                ..EcCapabilities::default()
            },
            max_label_len: None,
            skip_finalize_on_drop: true,
            // Same Cavium/Liquidsec PKCS#11 stack as AWS CloudHSM and Crypt2pay: reading
            // CKA_START_DATE/CKA_END_DATE fails with CKR_ATTRIBUTE_TYPE_INVALID.
            supports_key_dates: false,
            ..HsmCapabilities::default()
        }
    }
}

/// Azure Cloud HSM is supported by the generic `BaseHsm` implementation.
pub type AzureCloudHsm = cosmian_kms_base_hsm::BaseHsm<AzureCloudHsmCapabilityProvider>;
