//! GCP Cloud HSM PKCS#11 provider.

use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

/// Default path for Google's `libkmsp11.so` PKCS#11 compatibility library.
pub const GCP_CLOUD_HSM_PKCS11_LIB: &str = "/usr/lib/x86_64-linux-gnu/libkmsp11.so";

#[cfg(test)]
#[cfg(feature = "gcp_cloud_hsm")]
mod tests;

/// Capability provider for Google's Cloud KMS PKCS#11 library.
pub struct GcpCloudHsmCapabilityProvider;

impl HsmProvider for GcpCloudHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 64,
            aes: AesCapabilities {
                supports_sensitive_attribute: false,
                key_wrap_pad_is_rfc5649: false,
                gcm: AesGcmCapabilities {
                    supports_caller_iv: false,
                    allows_caller_iv_in_fips: false,
                    supports_message: false,
                },
            },
            rsa: RsaCapabilities {
                supports_sensitive_attribute: false,
                oaep_requires_source_data_ptr: false,
                supports_oaep_key_wrap: false,
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: false,
                enforces_ecdsa_digest_strength: false,
            },
            supports_message_sign_verify: false,
            max_label_len: None,
            supports_key_dates: false,
            skip_finalize_on_drop: false,
            max_concurrent_sessions: 128,
        }
    }
}

/// GCP Cloud HSM backed by the generic PKCS#11 HSM implementation.
/// GCP Cloud HSM backed by the generic PKCS#11 HSM implementation.
pub type GcpCloudHsm = cosmian_kms_base_hsm::BaseHsm<GcpCloudHsmCapabilityProvider>;
