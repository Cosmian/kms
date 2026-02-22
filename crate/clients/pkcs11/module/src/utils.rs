#![allow(clippy::as_conversions)]
#![allow(clippy::as_ptr_cast_mut)]

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_INVALID_HANDLE, CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CK_VOID_PTR, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL,
    CKA_SENSITIVE, CKA_VALUE_LEN, CKK_AES, CKM_AES_CBC_PAD, CKM_AES_KEY_GEN, CKR_OK,
};

use crate::{
    core::mechanism::AES_IV_SIZE,
    pkcs11::{C_Decrypt, C_DecryptInit, C_Encrypt, C_EncryptInit, C_GenerateKey},
};

#[expect(clippy::missing_panics_doc)]
#[must_use]
pub fn test_generate_key(session_h: CK_ULONG) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: [0_u8; 16].as_mut_ptr().cast::<std::ffi::c_void>(),
        ulParameterLen: 16,
    };
    let pMechanism: CK_MECHANISM_PTR = &raw mut mechanism;

    let mut sym_key_template = vec![
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: std::ptr::from_ref(&CKK_AES) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: "sk_id".as_ptr() as CK_VOID_PTR,
            ulValueLen: "sk_id".len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE,
            pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE,
            pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: std::ptr::from_ref(&(16 as CK_ULONG)) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];

    let mut key_handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_GenerateKey(
                session_h,
                pMechanism,
                sym_key_template.as_mut_ptr(),
                sym_key_template.len() as CK_ULONG,
                &raw mut key_handle,
            )
        },
        CKR_OK
    );

    // Expect key_handle to be a valid handle.
    assert_ne!(key_handle, CK_INVALID_HANDLE);
    key_handle
}

/// Encryption test: call to `C_EncryptInit` and `C_Encrypt`
#[expect(clippy::missing_panics_doc)]
#[must_use]
pub fn test_encrypt(
    session_h: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE,
    plaintext: Vec<u8>,
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: [0_u8; AES_IV_SIZE].as_mut_ptr().cast::<std::ffi::c_void>(),
        ulParameterLen: AES_IV_SIZE as CK_ULONG,
    };
    let pMechanism: CK_MECHANISM_PTR = &raw mut mechanism;

    let mut encrypted_data = vec![0_u8; plaintext.len() + AES_IV_SIZE];
    let mut encrypted_data_len = encrypted_data.len() as CK_ULONG;
    let mut pt = plaintext;

    assert_eq!(
        unsafe { C_EncryptInit(session_h, pMechanism, key_handle) },
        CKR_OK
    );

    assert_eq!(
        unsafe {
            C_Encrypt(
                session_h,
                pt.as_mut_ptr(),
                pt.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(),
                &raw mut encrypted_data_len,
            )
        },
        CKR_OK
    );

    // Expect encrypted_data_len to be the length of the encrypted data.
    assert_ne!(encrypted_data_len, 0);
    encrypted_data
}

/// Decryption test: call to `C_DecryptInit` and `C_Decrypt`
#[expect(
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::indexing_slicing
)]
#[must_use]
pub fn test_decrypt(
    session_h: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE,
    encrypted_data: Vec<u8>,
) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: [0_u8; AES_IV_SIZE].as_mut_ptr().cast::<std::ffi::c_void>(),
        ulParameterLen: AES_IV_SIZE as CK_ULONG,
    };
    let pMechanism: CK_MECHANISM_PTR = &raw mut mechanism;

    let mut encrypted_data = encrypted_data;
    let mut decrypted_data = vec![0_u8; encrypted_data.len()];
    let mut decrypted_data_len = decrypted_data.len() as CK_ULONG;

    assert_eq!(
        unsafe { C_DecryptInit(session_h, pMechanism, key_handle) },
        CKR_OK
    );

    assert_eq!(
        unsafe {
            C_Decrypt(
                session_h,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                decrypted_data.as_mut_ptr(),
                &raw mut decrypted_data_len,
            )
        },
        CKR_OK
    );

    // Expect decrypted_data_len to be the length of the decrypted data.
    assert_ne!(decrypted_data_len, 0);
    decrypted_data[..decrypted_data_len as usize].to_vec()
}
