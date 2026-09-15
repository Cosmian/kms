use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM,
    CK_MECHANISM_PTR, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CKA_CLASS, CKA_DECRYPT,
    CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE,
    CKA_TOKEN, CKA_VALUE_LEN, CKK_AES, CKM_AES_KEY_GEN, CKO_SECRET_KEY,
};

use crate::{HError, HResult, hsm_call, session::Session};

#[derive(Debug, Clone, Copy)]
pub enum AesKeySize {
    Aes128,
    Aes256,
}

impl Session {
    /// Generate an AES key
    ///
    /// If exportable is set to `false`, the `sensitive` flag is set to true,
    /// and the key will not be exportable.
    pub fn generate_aes_key(
        &self,
        id: &[u8],
        size: AesKeySize,
        sensitive: bool,
    ) -> HResult<CK_OBJECT_HANDLE> {
        {
            let size = CK_ULONG::try_from(match size {
                AesKeySize::Aes128 => 16_u64,
                AesKeySize::Aes256 => 32_u64,
            })
            .map_err(|e| HError::Default(format!("AES key size conversion failed: {e}")))?;
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_KEY_GEN,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };
            let key_class = CKO_SECRET_KEY;
            let key_type = CKK_AES;
            let true_value = CK_TRUE;
            let extractable = if sensitive { CK_FALSE } else { CK_TRUE };
            let mut template = vec![
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&key_class)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&key_type)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_VALUE_LEN,
                    pValue: std::ptr::from_ref(&size)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_TOKEN,
                    pValue: std::ptr::from_ref(&true_value)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_ENCRYPT,
                    pValue: std::ptr::from_ref(&true_value)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_DECRYPT,
                    pValue: std::ptr::from_ref(&true_value)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                    ulValueLen: CK_ULONG::try_from(id.len())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_ID,
                    pValue: id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                    ulValueLen: CK_ULONG::try_from(id.len())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_PRIVATE,
                    pValue: std::ptr::from_ref(&true_value)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_EXTRACTABLE,
                    pValue: std::ptr::from_ref(&extractable)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                },
            ];
            if sensitive {
                template.push(CK_ATTRIBUTE {
                    type_: CKA_SENSITIVE,
                    pValue: std::ptr::from_ref(&true_value)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                });
            }
            let p_mechanism: CK_MECHANISM_PTR = &raw mut mechanism;
            let p_mut_template: CK_ATTRIBUTE_PTR = template.as_mut_ptr();
            let mut aes_key_handle = CK_OBJECT_HANDLE::default();
            #[cfg(target_os = "windows")]
            let len = u32::try_from(template.len())?;
            #[cfg(not(target_os = "windows"))]
            let len = u64::try_from(template.len())?;
            hsm_call!(
                self.hsm(),
                "Failed generating key",
                C_GenerateKey,
                self.session_handle(),
                p_mechanism,
                p_mut_template,
                len,
                &raw mut aes_key_handle
            );
            self.object_handles_cache()
                .insert(id.to_vec(), aes_key_handle)?;
            Ok(aes_key_handle)
        }
    }
}
