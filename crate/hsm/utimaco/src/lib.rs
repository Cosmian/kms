//! Copyright 2024 Cosmian Tech SAS

/// Path to the Utimaco `PKCS#11` shared library
pub const UTIMACO_PKCS11_LIB: &str = "/lib/libcs_pkcs11_R3.so";

#[cfg(test)]
#[cfg(feature = "utimaco")]
mod tests;

/// The Utimaco HSM is fully supported by the `BaseHsm` implementation
pub type Utimaco = cosmian_kms_base_hsm::BaseHsm;
