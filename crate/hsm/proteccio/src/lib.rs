//! Copyright 2024 Cosmian Tech SAS
use cosmian_kms_base_hsm::BaseHsm;

/// Path to the Proteccio `PKCS#11` shared library
pub const PROTECCIO_PKCS11_LIB: &str = "/lib/libnethsm.so";

pub type Proteccio = BaseHsm;

#[cfg(test)]
#[cfg(feature = "proteccio")]
mod tests;
