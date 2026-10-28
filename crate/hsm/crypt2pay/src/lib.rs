//! Copyright 2025 Cosmian Tech SAS
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
            supports_aes_sensitive_attribute: true,
            supports_rsa_sensitive_attribute: true,
            supports_ec_sensitive_attribute: true,
            supports_aes_gcm_caller_iv: true,
            aes_key_wrap_pad_is_rfc5649: false,
            // libpkcs11c2p.so stubs both v3 families as notimpl.c (CKR_FUNCTION_NOT_SUPPORTED, 0x54):
            // C_MessageEncryptInit and C_MessageSignInit, on the simulator and the real HSM alike.
            supports_aes_gcm_message: false,
            supports_message_sign_verify: false,
            rsa_oaep_requires_source_data_ptr: false,
            max_label_len: None,
            supports_key_dates: false,
            supports_rsa_oaep_key_wrap: true,
            enforces_ecdsa_digest_strength: false,
            skip_finalize_on_drop: true,
            max_concurrent_sessions: 128,
        }
    }
}

pub type Crypt2pay = BaseHsm<Crypt2payCapabilityProvider>;

#[cfg(test)]
#[cfg(feature = "crypt2pay")]
mod tests;
