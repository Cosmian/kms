use std::ptr;

use pkcs11_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE,
    CKA_SENSITIVE, CKA_TOKEN, CKA_VALUE_LEN, CKK_AES, CKM_AES_KEY_GEN, CKO_SECRET_KEY, CKR_OK,
    CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_BBOOL, CK_FALSE, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CK_VOID_PTR,
};

use crate::{session::Session, PError, PResult};

pub enum AesKeySize {
    Aes128,
    Aes256,
}

/// AES key template
/// If sensitive is true, the key is not exportable
/// Proteccio does not allow setting the ID attribute for secret keys so we use the LABEL
/// so we do the same with Utimaco
pub(crate) const fn aes_key_template(
    id: &[u8],
    size: CK_ULONG,
    sensitive: bool,
) -> [CK_ATTRIBUTE; 10] {
    let sensitive: CK_BBOOL = if sensitive { CK_TRUE } else { CK_FALSE };
    [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &CKO_SECRET_KEY as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &CKK_AES as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: &size as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: id.as_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE,
            pValue: &sensitive as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ]
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
    ) -> PResult<CK_OBJECT_HANDLE> {
        unsafe {
            let ck_fn = self.hsm().C_GenerateKey.ok_or_else(|| {
                PError::Default("C_GenerateKey not available on library".to_string())
            })?;
            let size = match size {
                AesKeySize::Aes128 => 16,
                AesKeySize::Aes256 => 32,
            } as CK_ULONG;
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_KEY_GEN,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };
            let mut template = aes_key_template(id, size, sensitive);
            let pMechanism: CK_MECHANISM_PTR = &mut mechanism;
            let pMutTemplate: CK_ATTRIBUTE_PTR = template.as_mut_ptr();
            let mut aes_key_handle = CK_OBJECT_HANDLE::default();
            #[cfg(target_os = "windows")]
            let len = u32::try_from(template.len())?;
            #[cfg(not(target_os = "windows"))]
            let len = u64::try_from(template.len())?;
            let rv = ck_fn(
                self.session_handle(),
                pMechanism,
                pMutTemplate,
                len,
                &mut aes_key_handle,
            );
            if rv != CKR_OK {
                return Err(PError::Default(format!("Failed generating key: {rv}")));
            }
            self.object_handles_cache()
                .insert(id.to_vec(), aes_key_handle);
            Ok(aes_key_handle)
        }
    }
}
