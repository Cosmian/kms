//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

#[cfg(test)]
#[cfg(feature = "smartcardhsm")]
mod tests;

pub struct SmartcardHsmCapabilityProvider;

impl HsmProvider for SmartcardHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: Some(1024),
        }
    }
}

/// The smartcardhsm is fully supported by the BaseHsm implementation
pub type Smartcardhsm = cosmian_kms_base_hsm::BaseHsm<SmartcardHsmCapabilityProvider>;
