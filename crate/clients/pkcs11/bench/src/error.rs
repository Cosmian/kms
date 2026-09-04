use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kms_client::KmsClientError;
use pkcs11_sys::{CK_RV, CKR_FUNCTION_NOT_SUPPORTED};

/// Errors produced by the `cosmian_pkcs11` load benchmark harness.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BenchError {
    /// The provider `.so`/`.dylib` could not be `dlopen()`-ed.
    #[error("failed to load PKCS#11 library: {0}")]
    Load(#[from] libloading::Error),

    /// A required Cryptoki symbol is missing from the loaded library.
    #[error("PKCS#11 library is missing the required symbol: {0}")]
    MissingSymbol(String),

    /// A Cryptoki C API call returned a non-`CKR_OK` result.
    #[error("PKCS#11 call {op} failed with CK_RV=0x{rv:08X}")]
    Cryptoki { op: &'static str, rv: CK_RV },

    /// A KMS REST call (used to provision benchmark keys) failed.
    #[error("KMS REST call failed: {0}")]
    Kms(#[from] KmsClientError),

    /// A KMIP request/response type failed to build.
    #[error("failed to build KMIP request: {0}")]
    Kmip(String),

    /// Benchmark setup or argument-parsing error.
    #[error("benchmark error: {0}")]
    Setup(String),

    /// Report/JSON output could not be written.
    #[error("failed to write benchmark report: {0}")]
    Report(String),
}

impl BenchError {
    /// Returns `true` if this error is the provider reporting
    /// `CKR_FUNCTION_NOT_SUPPORTED` for a Cryptoki call. The caller should treat
    /// this as "skip this benchmark", not a hard failure.
    pub(crate) const fn is_function_not_supported(&self) -> bool {
        matches!(
            self,
            Self::Cryptoki {
                rv: CKR_FUNCTION_NOT_SUPPORTED,
                ..
            }
        )
    }
}

/// Convenience `Result` alias for this crate.
pub(crate) type BenchResult<T> = Result<T, BenchError>;
