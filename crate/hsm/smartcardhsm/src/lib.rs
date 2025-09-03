//! Copyright 2024 Cosmian Tech SAS

#[cfg(test)]
#[cfg(feature = "smartcardhsm")]
mod tests;

/// The smartcardhsm is fully supported by the BaseHsm implementation
pub type Smartcardhsm = cosmian_kms_base_hsm::BaseHsm;
