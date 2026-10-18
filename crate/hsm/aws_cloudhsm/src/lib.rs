//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Path to the AWS `CloudHSM` `PKCS#11` shared library (AWS `CloudHSM` Client SDK 5).
/// See <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html>.
pub const AWS_CLOUDHSM_PKCS11_LIB: &str = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";

#[cfg(test)]
#[cfg(feature = "aws_cloudhsm")]
mod tests;

pub struct AwsCloudHsmCapabilityProvider;

impl HsmProvider for AwsCloudHsmCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            // AWS CloudHSM's PKCS#11 v2.40 library does not document a CBC chunking limit.
            max_cbc_data_size: None,
            // Conservative default, in line with the other proprietary HSM vendors (Utimaco).
            find_max_object_count: 64,
            supports_aes_sensitive_attribute: false,
            supports_rsa_sensitive_attribute: false,
            supports_ec_sensitive_attribute: false,
            supports_aes_gcm_caller_iv: false,
            supports_aes_gcm_message: true,
            rsa_oaep_requires_source_data_ptr: false,
            max_label_len: None,
            // C_GetAttributeValue on CKA_START_DATE/CKA_END_DATE returns CKR_ATTRIBUTE_TYPE_INVALID.
            supports_key_dates: false,
            supports_rsa_oaep_key_wrap: true,
            enforces_ecdsa_digest_strength: true,
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
