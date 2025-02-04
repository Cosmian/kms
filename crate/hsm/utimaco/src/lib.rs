//! Copyright 2024 Cosmian Tech SAS

#[cfg(test)]
#[cfg(feature = "utimaco")]
mod tests;

/// The Utimaco HSM is fully supported by the BaseHsm implementation
pub type Utimaco = cosmian_kms_base_hsm::BaseHsm;
