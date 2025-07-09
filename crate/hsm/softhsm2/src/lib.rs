//! Copyright 2024 Cosmian Tech SAS

#[cfg(test)]
#[cfg(feature = "softhsm2")]
mod tests;

/// The softhsm2 is fully supported by the BaseHsm implementation
pub type Softhsm2 = cosmian_kms_base_hsm::BaseHsm;
