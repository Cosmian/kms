//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{HsmCapabilities, HsmProvider};

/// Path to the AWS `CloudHSM` `PKCS#11` shared library (AWS `CloudHSM` Client SDK 5).
/// See <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html>.
pub const AWS_CLOUDHSM_PKCS11_LIB: &str = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";

#[cfg(test)]
#[allow(clippy::expect_used)]
// Allow test-specific lint patterns for C library integration
#[allow(unsafe_code)]
#[allow(clippy::panic_in_result_fn)]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::assertions_on_result_states)]
#[allow(clippy::as_conversions)]
#[allow(clippy::map_err_ignore)]
#[allow(clippy::redundant_clone)]
#[allow(clippy::str_to_string)]
#[allow(clippy::unseparated_literal_suffix)]
#[allow(clippy::borrow_as_ptr)]
#[allow(clippy::ref_as_ptr)]
#[allow(clippy::stable_sort_primitive)]
#[allow(clippy::explicit_iter_loop)]
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
