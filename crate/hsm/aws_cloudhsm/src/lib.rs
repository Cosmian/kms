//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

/// Path to the AWS `CloudHSM` `PKCS#11` shared library (AWS `CloudHSM` Client SDK 5).
/// See <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html>.
pub const AWS_CLOUDHSM_PKCS11_LIB: &str = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";

#[cfg(test)]
#[cfg(feature = "aws_cloudhsm")]
mod tests;

/// Capability provider for AWS `CloudHSM` (Client SDK 5 PKCS#11 library).
pub struct AwsCloudHsmCapabilityProvider;

impl HsmProvider for AwsCloudHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            // AWS CloudHSM's PKCS#11 v2.40 library does not document a CBC chunking limit.
            max_cbc_data_size: None,
            // Conservative default, in line with the other proprietary HSM vendors (Utimaco).
            find_max_object_count: 64,
            aes: AesCapabilities {
                supports_sensitive_attribute: false,
                key_wrap_pad_is_rfc5649: false,
                gcm: AesGcmCapabilities {
                    supports_caller_iv: false,
                    allows_caller_iv_in_fips: false,
                    supports_message: true,
                },
            },
            rsa: RsaCapabilities {
                supports_sensitive_attribute: false,
                oaep_requires_source_data_ptr: false,
                supports_oaep_key_wrap: true,
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: false,
                enforces_ecdsa_digest_strength: true,
            },
            supports_message_sign_verify: false,
            max_label_len: None,
            // C_GetAttributeValue on CKA_START_DATE/CKA_END_DATE returns CKR_ATTRIBUTE_TYPE_INVALID.
            supports_key_dates: false,
            skip_finalize_on_drop: false,
            max_concurrent_sessions: 128,
        }
    }
}

/// AWS `CloudHSM` is fully supported by the `BaseHsm` implementation.
///
/// Authentication note: the PKCS#11 login PIN expected by AWS `CloudHSM`'s Crypto User (CU) is
/// the string `"<cu_username>:<cu_password>"` (see
/// <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-pin.html>). This is a pure
/// configuration convention: pass it directly as the `--hsm-password` value (or
/// `KMS_HSM_PASSWORD` environment variable) — no code change is required here.
pub type AwsCloudhsm = cosmian_kms_base_hsm::BaseHsm<AwsCloudHsmCapabilityProvider>;
