//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

#[cfg(test)]
#[cfg(feature = "softhsm2")]
mod tests;

pub struct SofthsmCapabilityProvider;

impl HsmProvider for SofthsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 32,
        }
    }
}

/// The softhsm2 is fully supported by the `BaseHsm` implementation
pub type Softhsm2 = cosmian_kms_base_hsm::BaseHsm<SofthsmCapabilityProvider>;
