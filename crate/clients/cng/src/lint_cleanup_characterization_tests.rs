//! Characterization tests pinning the BASE behavior of `lib.rs` and `error.rs`.

use crate::error::{self, KspError};

#[test]
fn characterization_security_status_constants() {
    let table: [(i32, [u8; 4]); 22] = [
        (error::ERROR_SUCCESS, [0x00, 0x00, 0x00, 0x00]),
        (error::NTE_BAD_UID, [0x80, 0x09, 0x00, 0x01]),
        (error::NTE_BAD_HASH, [0x80, 0x09, 0x00, 0x02]),
        (error::NTE_BAD_KEY, [0x80, 0x09, 0x00, 0x03]),
        (error::NTE_BAD_LEN, [0x80, 0x09, 0x00, 0x04]),
        (error::NTE_BAD_DATA, [0x80, 0x09, 0x00, 0x05]),
        (error::NTE_BAD_ALGID, [0x80, 0x09, 0x00, 0x08]),
        (error::NTE_BAD_FLAGS, [0x80, 0x09, 0x00, 0x09]),
        (error::NTE_NO_KEY, [0x80, 0x09, 0x00, 0x0D]),
        (error::NTE_NO_MEMORY, [0x80, 0x09, 0x00, 0x0E]),
        (error::NTE_EXISTS, [0x80, 0x09, 0x00, 0x0F]),
        (error::NTE_PERM, [0x80, 0x09, 0x00, 0x10]),
        (error::NTE_BAD_PROV_TYPE, [0x80, 0x09, 0x00, 0x14]),
        (error::NTE_BAD_KEYSET, [0x80, 0x09, 0x00, 0x16]),
        (error::NTE_FAIL, [0x80, 0x09, 0x00, 0x20]),
        (error::NTE_SILENT_CONTEXT, [0x80, 0x09, 0x00, 0x22]),
        (error::NTE_INVALID_HANDLE, [0x80, 0x09, 0x00, 0x26]),
        (error::NTE_INVALID_PARAMETER, [0x80, 0x09, 0x00, 0x27]),
        (error::NTE_BUFFER_TOO_SMALL, [0x80, 0x09, 0x00, 0x28]),
        (error::NTE_NOT_SUPPORTED, [0x80, 0x09, 0x00, 0x29]),
        (error::NTE_NO_MORE_ITEMS, [0x80, 0x09, 0x00, 0x2A]),
        (error::NTE_OP_OK, [0x00, 0x00, 0x00, 0x00]),
    ];
    for (value, be) in table {
        assert_eq!(value, i32::from_be_bytes(be));
    }
}

#[test]
fn characterization_status_success_val() {
    assert_eq!(error::STATUS_SUCCESS_VAL, 0);
    assert_eq!(error::STATUS_SUCCESS_VAL, error::ERROR_SUCCESS);
}

#[test]
fn characterization_ksp_error_to_security_status() {
    let table: [(KspError, i32); 11] = [
        (
            KspError::InvalidParameter("x".to_owned()),
            error::NTE_INVALID_PARAMETER,
        ),
        (KspError::KeyNotFound("x".to_owned()), error::NTE_BAD_KEYSET),
        (KspError::KeyExists("x".to_owned()), error::NTE_EXISTS),
        (
            KspError::AlgorithmNotSupported("x".to_owned()),
            error::NTE_BAD_ALGID,
        ),
        (
            KspError::NotSupported("x".to_owned()),
            error::NTE_NOT_SUPPORTED,
        ),
        (KspError::Backend("x".to_owned()), error::NTE_FAIL),
        (KspError::Internal("x".to_owned()), error::NTE_FAIL),
        (KspError::StringConversion, error::NTE_NO_MEMORY),
        (KspError::OutOfMemory, error::NTE_NO_MEMORY),
        (KspError::ExportNotPermitted, error::NTE_PERM),
        (KspError::InvalidHandle, error::NTE_INVALID_HANDLE),
    ];
    for (err, status) in table {
        assert_eq!(err.to_security_status(), status);
    }
}

#[test]
fn characterization_ksp_error_display() {
    assert_eq!(
        KspError::InvalidParameter("a".to_owned()).to_string(),
        "invalid parameter: a"
    );
    assert_eq!(
        KspError::KeyNotFound("a".to_owned()).to_string(),
        "key not found: a"
    );
    assert_eq!(
        KspError::KeyExists("a".to_owned()).to_string(),
        "key already exists: a"
    );
    assert_eq!(
        KspError::AlgorithmNotSupported("a".to_owned()).to_string(),
        "algorithm not supported: a"
    );
    assert_eq!(
        KspError::NotSupported("a".to_owned()).to_string(),
        "operation not supported: a"
    );
    assert_eq!(
        KspError::Backend("a".to_owned()).to_string(),
        "KMS backend error: a"
    );
    assert_eq!(
        KspError::StringConversion.to_string(),
        "UTF-16 string conversion error"
    );
    assert_eq!(
        KspError::OutOfMemory.to_string(),
        "memory allocation failure"
    );
    assert_eq!(
        KspError::Internal("a".to_owned()).to_string(),
        "internal error: a"
    );
    assert_eq!(
        KspError::ExportNotPermitted.to_string(),
        "export not permitted for this key"
    );
    assert_eq!(KspError::InvalidHandle.to_string(), "invalid handle");
}

#[cfg(not(windows))]
#[test]
fn characterization_non_windows_stubs() {
    assert!(!crate::is_ksp_registered());
    assert_eq!(crate::dll_directory(), None);
    assert_eq!(crate::KSP_PROVIDER_NAME, "Cosmian KMS Key Storage Provider");
    assert!(crate::KSP_PROVIDER_NAME_W.is_empty());
    assert_eq!(
        crate::register_ksp(std::path::Path::new("x.dll")).unwrap_err(),
        "KSP registration is only supported on Windows"
    );
    assert_eq!(
        crate::unregister_ksp().unwrap_err(),
        "KSP unregistration is only supported on Windows"
    );
    // SAFETY: the non-Windows stub takes no arguments and touches no memory.
    assert_eq!(
        unsafe { crate::GetKeyStorageInterface() },
        error::NTE_NOT_SUPPORTED
    );
}
