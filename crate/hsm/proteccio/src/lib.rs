//! Copyright 2024 Cosmian Tech SAS
use cosmian_kms_base_hsm::{
    BaseHsm,
    hsm_capabilities::{HsmCapabilities, HsmProvider},
};

/// Path to the Proteccio `PKCS#11` shared library
pub const PROTECCIO_PKCS11_LIB: &str = "/lib/libnethsm.so";

pub struct ProteccioCapabilityProvider;

impl HsmProvider for ProteccioCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
        }
    }
}

pub type Proteccio = BaseHsm<ProteccioCapabilityProvider>;

#[cfg(test)]
#[cfg(feature = "proteccio")]
mod tests;
