//! Copyright 2024 Cosmian Tech SAS

mod error;

pub use base_hsm::BaseHsm;
pub use error::{HError, HResult};
pub use session::{AesKeySize, HsmEncryptionAlgorithm, RsaKeySize, RsaOaepDigest, Session};
pub use slots::{ObjectHandlesCache, SlotManager};

mod base_hsm;
mod hsm_lib;
mod session;

mod kms_hsm;
mod slots;

pub mod hsm_capabilities;
pub mod test_helpers;

// AES key template
// If sensitive is true, the key is not exportable
// Proteccio does not allow setting the ID attribute for secret keys so we use the LABEL
// so we do the same with other HSMs

#[macro_export]
macro_rules! aes_key_template {
    ($id:expr, $size:expr, $sensitive:expr) => {{
        use pkcs11_sys::*;
        let size = $size;
        [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: std::ptr::from_ref::<CK_ULONG>(&CKO_SECRET_KEY)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_ULONG>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref::<CK_ULONG>(&CKK_AES)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_ULONG>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: std::ptr::from_ref(&size)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_ULONG>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref::<u8>(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_ENCRYPT,
                pValue: std::ptr::from_ref::<u8>(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_DECRYPT,
                pValue: std::ptr::from_ref::<u8>(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: $id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from($id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: std::ptr::from_ref::<u8>(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: std::ptr::from_ref::<u8>(&$sensitive)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: std::ptr::from_ref::<u8>(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_BBOOL>())?,
            },
        ]
    }};
}

/// Macro to simplify HSM function calls with automatic return value checking
#[macro_export]
macro_rules! hsm_call {
    ($hsm_lib:expr, $msg:expr, $fn_name:ident $(, $args:expr)*) => {
        {
            let hsm_lib_ref = &$hsm_lib;
            let function_name = stringify!($fn_name);
            #[expect(unsafe_code)]
            #[expect(clippy::macro_metavars_in_unsafe)]
            let rv = match hsm_lib_ref.$fn_name {
                Some(func) => unsafe { func($($args),*) },
                None => return Err($crate::HError::Default(format!("{} not available on library", function_name))),
            };
            if rv != pkcs11_sys::CKR_OK {
                return Err($crate::HError::Default(format!("{}. Return code: {}", $msg, rv)));
            }
            rv
        }
    };
}
