//! Copyright 2024 Cosmian Tech SAS

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
extern crate core;

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

pub mod test_helpers;

// AES key template
// If sensitive is true, the key is not exportable
// Proteccio does not allow setting the ID attribute for secret keys so we use the LABEL
// so we do the same with other HSMs

#[macro_export]
macro_rules! aes_key_template {
    ($id:expr, $size:expr, $sensitive:expr) => {
        [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &CKO_SECRET_KEY as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &CKK_AES as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: &$size as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_ENCRYPT,
                pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_DECRYPT,
                pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: $id.as_ptr() as CK_VOID_PTR,
                ulValueLen: $id.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: &$sensitive as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ]
    };
}
