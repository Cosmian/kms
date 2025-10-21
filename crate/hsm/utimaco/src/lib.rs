//! Copyright 2024 Cosmian Tech SAS
use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Path to the Utimaco `PKCS#11` shared library
pub const UTIMACO_PKCS11_LIB: &str = "/lib/libcs_pkcs11_R3.so";

#[cfg(test)]
#[cfg(feature = "utimaco")]
mod tests;

pub struct UtimacoCapabilityProvider;

impl HsmProvider for UtimacoCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
        }
    }
}

/// The Utimaco HSM is fully supported by the `BaseHsm` implementation
pub type Utimaco = cosmian_kms_base_hsm::BaseHsm<UtimacoCapabilityProvider>;
