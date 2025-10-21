use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE_PTR, CK_FALSE, CK_MECHANISM, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_TRUE,
    CK_ULONG, CKM_AES_KEY_GEN,
};

use crate::{HError, HResult, aes_key_template, hsm_call, session::Session};

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
            let is_sensitive = if sensitive { CK_TRUE } else { CK_FALSE };
            let mut template = aes_key_template!(id, size, is_sensitive);
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
