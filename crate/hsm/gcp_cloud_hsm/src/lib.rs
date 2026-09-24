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
        }
    }
}

/// GCP Cloud HSM backed by the generic PKCS#11 HSM implementation.
/// GCP Cloud HSM backed by the generic PKCS#11 HSM implementation.
pub type GcpCloudHsm = cosmian_kms_base_hsm::BaseHsm<GcpCloudHsmCapabilityProvider>;
