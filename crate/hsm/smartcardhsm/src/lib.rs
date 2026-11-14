//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

/// Path to the `SmartcardHSM` `PKCS#11` shared library
pub const SMARTCARDHSM_PKCS11_LIB: &str = "/usr/local/lib/libsc-hsm-pkcs11.so";

#[cfg(test)]
#[cfg(feature = "smartcardhsm")]
mod tests;

pub struct SmartcardHsmCapabilityProvider;

impl HsmProvider for SmartcardHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: Some(1024),
            find_max_object_count: 16, // Don't overwhelm the smart card
            aes: AesCapabilities {
                supports_sensitive_attribute: true,
                key_wrap_pad_is_rfc5649: false,
                gcm: AesGcmCapabilities {
                    supports_caller_iv: true,
                    allows_caller_iv_in_fips: false,
                    supports_message: true,
                },
            },
            rsa: RsaCapabilities {
                supports_sensitive_attribute: true,
                oaep_requires_source_data_ptr: false,
                supports_oaep_key_wrap: false,
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: true,
                enforces_ecdsa_digest_strength: false,
            },
            supports_message_sign_verify: false,
            max_label_len: None,
            supports_key_dates: true,
            skip_finalize_on_drop: false,
            max_concurrent_sessions: 8,
        }
    }
}

/// The smartcardhsm is fully supported by the `BaseHsm` implementation
pub type Smartcardhsm = cosmian_kms_base_hsm::BaseHsm<SmartcardHsmCapabilityProvider>;
