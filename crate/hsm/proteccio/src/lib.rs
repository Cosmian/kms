//! Copyright 2024 Cosmian Tech SAS
use cosmian_kms_base_hsm::BaseHsm;

pub type Proteccio = BaseHsm;

#[cfg(test)]
#[cfg(feature = "proteccio")]
mod tests;
