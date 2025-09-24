//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

#[cfg(test)]
// Allow test-specific lint patterns for C library integration
#[allow(unsafe_code)]
#[allow(clippy::panic_in_result_fn)]
#[allow(clippy::panic)]
#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::assertions_on_result_states)]
#[allow(clippy::as_conversions)]
#[allow(clippy::map_err_ignore)]
#[allow(clippy::redundant_clone)]
#[allow(clippy::explicit_iter_loop)]
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
