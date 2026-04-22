use thiserror::Error;

#[cfg(windows)]


/// SECURITY_STATUS / HRESULT constants used by the NCrypt KSP interface.
///
/// Windows defines these as `i32` (HRESULT) or on some surfaces `u32`.
/// Here we use `i32` to match `windows_sys`'s `HRESULT`.
pub type SecurityStatus = i32;

pub const ERROR_SUCCESS: SecurityStatus = 0x0000_0000_u32 as i32;
pub const NTE_BAD_UID: SecurityStatus = 0x8009_0001_u32 as i32;
pub const NTE_BAD_HASH: SecurityStatus = 0x8009_0002_u32 as i32;
pub const NTE_BAD_KEY: SecurityStatus = 0x8009_0003_u32 as i32;
pub const NTE_BAD_LEN: SecurityStatus = 0x8009_0004_u32 as i32;
pub const NTE_BAD_DATA: SecurityStatus = 0x8009_0009_u32 as i32;
pub const NTE_BAD_ALGID: SecurityStatus = 0x8009_000D_u32 as i32;
pub const NTE_BAD_FLAGS: SecurityStatus = 0x8009_000F_u32 as i32;
pub const NTE_BAD_KEYSET: SecurityStatus = 0x8009_0016_u32 as i32;
pub const NTE_BAD_PROV_TYPE: SecurityStatus = 0x8009_0014_u32 as i32;
pub const NTE_EXISTS: SecurityStatus = 0x8009_000F_u32 as i32;
pub const NTE_NO_KEY: SecurityStatus = 0x8009_0008_u32 as i32;
pub const NTE_NO_MEMORY: SecurityStatus = 0x8009_0011_u32 as i32;
pub const NTE_NOT_SUPPORTED: SecurityStatus = 0x8009_0029_u32 as i32;
pub const NTE_INVALID_PARAMETER: SecurityStatus = 0x8009_0027_u32 as i32;
pub const NTE_INVALID_HANDLE: SecurityStatus = 0x8009_0026_u32 as i32;
pub const NTE_FAIL: SecurityStatus = 0x8009_002A_u32 as i32;
pub const NTE_SILENT_CONTEXT: SecurityStatus = 0x8009_002B_u32 as i32;
pub const NTE_PERM: SecurityStatus = 0x8009_0010_u32 as i32;
pub const NTE_BUFFER_TOO_SMALL: SecurityStatus = 0x8009_0028_u32 as i32; // ERROR_INSUFFICIENT_BUFFER mapped
pub const NTE_KEY_DOES_NOT_EXIST: SecurityStatus = 0x8009_0008_u32 as i32;
pub const NTE_OP_OK: SecurityStatus = 0;

// NTSTATUS success
pub const STATUS_SUCCESS_VAL: i32 = 0x0000_0000;

/// Errors produced by the CNG KSP implementation.
#[derive(Debug, Error)]
pub enum KspError {
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("key already exists: {0}")]
    KeyExists(String),

    #[error("algorithm not supported: {0}")]
    AlgorithmNotSupported(String),

    #[error("operation not supported: {0}")]
    NotSupported(String),

    #[error("KMS backend error: {0}")]
    Backend(String),

    #[error("UTF-16 string conversion error")]
    StringConversion,

    #[error("memory allocation failure")]
    OutOfMemory,

    #[error("internal error: {0}")]
    Internal(String),

    #[error("export not permitted for this key")]
    ExportNotPermitted,

    #[error("invalid handle")]
    InvalidHandle,
}

impl KspError {
    /// Convert to the Windows `SECURITY_STATUS` code expected by NCrypt callers.
    #[must_use]
    pub const fn to_security_status(&self) -> SecurityStatus {
        match self {
            Self::InvalidParameter(_) => NTE_INVALID_PARAMETER,
            Self::KeyNotFound(_) => NTE_NO_KEY,
            Self::KeyExists(_) => NTE_EXISTS,
            Self::AlgorithmNotSupported(_) => NTE_BAD_ALGID,
            Self::NotSupported(_) => NTE_NOT_SUPPORTED,
            Self::Backend(_) | Self::Internal(_) => NTE_FAIL,
            Self::StringConversion | Self::OutOfMemory => NTE_NO_MEMORY,
            Self::ExportNotPermitted => NTE_PERM,
            Self::InvalidHandle => NTE_INVALID_HANDLE,
        }
    }
}

pub type KspResult<T> = Result<T, KspError>;
