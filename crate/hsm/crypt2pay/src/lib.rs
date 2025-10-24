//! Copyright 2024 Cosmian Tech SAS
use cosmian_kms_base_hsm::{
    BaseHsm,
    hsm_capabilities::{HsmCapabilities, HsmProvider},
};

/// Path to the Crypt2pay `PKCS#11` shared library
pub const CRYPT2PAY_PKCS11_LIB: &str = "/lib/libpkcs11c2p.so";

pub struct Crypt2payCapabilityProvider;

impl HsmProvider for Crypt2payCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
        }
    }
}

pub type Crypt2pay = BaseHsm<Crypt2payCapabilityProvider>;

#[cfg(test)]
#[cfg(feature = "crypt2pay")]
mod tests;
