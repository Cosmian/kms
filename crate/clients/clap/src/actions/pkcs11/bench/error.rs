use cosmian_kmip::KmipError;
use cosmian_kms_client::KmsClientError;

/// Errors produced by the `cosmian_pkcs11` load benchmark harness.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BenchError {
    /// A PKCS#11 C API call (via `cosmian_kms_base_hsm`) returned a non-`CKR_OK` result.
    #[error("PKCS#11 error: {0}")]
    Hsm(#[from] cosmian_kms_base_hsm::HError),

    /// A KMS REST call (used to provision benchmark keys) failed.
    #[error("KMS REST call failed: {0}")]
    Kms(#[from] KmsClientError),

    /// A KMIP request/response type failed to build.
    #[error("failed to build KMIP request: {0}")]
    Kmip(#[from] KmipError),

    /// Benchmark setup or argument-parsing error.
    #[error("benchmark error: {0}")]
    Setup(String),

    /// Report/JSON output could not be written.
    #[error("failed to write benchmark report: {0}")]
    Report(String),
}

/// Convenience `Result` alias for this module.
pub(crate) type BenchResult<T> = Result<T, BenchError>;
