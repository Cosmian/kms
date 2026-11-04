//! Copyright 2024 Cosmian Tech SAS
use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

/// Path to the Utimaco `PKCS#11` shared library
pub const UTIMACO_PKCS11_LIB: &str = "/lib/libcs_pkcs11_R3.so";

#[cfg(test)]
#[cfg(feature = "utimaco")]
mod tests;

pub struct UtimacoCapabilityProvider;

impl HsmProvider for UtimacoCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
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
                supports_oaep_key_wrap: true,
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: true,
                enforces_ecdsa_digest_strength: false,
            },
            supports_message_sign_verify: false,
            max_label_len: None,
            supports_key_dates: true,
            skip_finalize_on_drop: false,
            max_concurrent_sessions: 128,
        }
    }
}

/// The Utimaco HSM is fully supported by the `BaseHsm` implementation
pub type Utimaco = cosmian_kms_base_hsm::BaseHsm<UtimacoCapabilityProvider>;
