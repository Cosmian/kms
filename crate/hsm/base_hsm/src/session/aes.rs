use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_BBOOL, CK_FALSE, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CK_VOID_PTR, CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT,
    CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE, CKA_TOKEN, CKA_VALUE_LEN,
    CKK_AES, CKM_AES_KEY_GEN, CKO_SECRET_KEY, CKR_OK,
};

use crate::{HError, HResult, aes_key_template, check_rv, session::Session};

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
        unsafe {
            let ck_fn = self.hsm().C_GenerateKey.ok_or_else(|| {
                HError::Default("C_GenerateKey not available on library".to_string())
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
            let is_sensitive = if sensitive { CK_TRUE } else { CK_FALSE };
            let mut template = aes_key_template!(id, size, is_sensitive);
            let pMechanism: CK_MECHANISM_PTR = &raw mut mechanism;
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
                &raw mut aes_key_handle,
            );
            check_rv!(rv, "Failed generating key");
            self.object_handles_cache()
                .insert(id.to_vec(), aes_key_handle)?;
            Ok(aes_key_handle)
        }
    }
}
