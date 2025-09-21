//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

#[cfg(test)]
#[allow(clippy::expect_used)]
// Allow test-specific lint patterns for C library integration
#[allow(unsafe_code)]
#[allow(clippy::panic_in_result_fn)]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::assertions_on_result_states)]
#[allow(clippy::as_conversions)]
#[allow(clippy::map_err_ignore)]
#[allow(clippy::redundant_clone)]
#[allow(clippy::str_to_string)]
#[allow(clippy::unseparated_literal_suffix)]
#[allow(clippy::borrow_as_ptr)]
#[allow(clippy::ref_as_ptr)]
#[allow(clippy::stable_sort_primitive)]
#[allow(clippy::explicit_iter_loop)]
#[cfg(feature = "smartcardhsm")]
mod tests;

pub struct SmartcardHsmCapabilityProvider;

impl HsmProvider for SmartcardHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: Some(1024),
            find_max_object_count: 16, // Don't overwhelm the smart card
        }
    }
}

/// The smartcardhsm is fully supported by the `BaseHsm` implementation
pub type Smartcardhsm = cosmian_kms_base_hsm::BaseHsm<SmartcardHsmCapabilityProvider>;
