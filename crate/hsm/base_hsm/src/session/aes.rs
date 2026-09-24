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
    /// Generate a sensitive AES key using the PKCS#11 default sensitivity attributes.
    pub fn generate_sensitive_aes_key(
        &self,
        id: &[u8],
        size: AesKeySize,
    ) -> HResult<CK_OBJECT_HANDLE> {
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
        let mut template = aes_key_template!(id, size);
        let mut aes_key_handle = CK_OBJECT_HANDLE::default();
        #[cfg(target_os = "windows")]
        let len = u32::try_from(template.len())?;
        #[cfg(not(target_os = "windows"))]
        let len = u64::try_from(template.len())?;
        hsm_call!(
            self.hsm(),
            "Failed generating sensitive key",
            C_GenerateKey,
            self.session_handle(),
            &raw mut mechanism,
            template.as_mut_ptr(),
            len,
            &raw mut aes_key_handle
        );
        self.object_handles_cache()
            .insert(id.to_vec(), aes_key_handle)?;
        Ok(aes_key_handle)
    }

    /// Generate an exportable AES key using `CKA_EXTRACTABLE=true`, without
    /// setting `CKA_SENSITIVE`: AWS `CloudHSM` rejects any explicit value for
    /// the Sensitive attribute.
    pub fn generate_exportable_aes_key(
        &self,
        id: &[u8],
        size: AesKeySize,
    ) -> HResult<CK_OBJECT_HANDLE> {
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
        let extractable = CK_TRUE;
        let mut template = aes_key_template!(id, size, extractable);
        let mut aes_key_handle = CK_OBJECT_HANDLE::default();
        #[cfg(target_os = "windows")]
        let len = u32::try_from(template.len())?;
        #[cfg(not(target_os = "windows"))]
        let len = u64::try_from(template.len())?;
        hsm_call!(
            self.hsm(),
            "Failed generating exportable key",
            C_GenerateKey,
            self.session_handle(),
            &raw mut mechanism,
            template.as_mut_ptr(),
            len,
            &raw mut aes_key_handle
        );
        self.object_handles_cache()
            .insert(id.to_vec(), aes_key_handle)?;
        Ok(aes_key_handle)
    }

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
        // Some vendors (AWS CloudHSM) reject any explicit value for CKA_SENSITIVE on
        // C_GenerateKey; fall back to the attribute-free/extractable-only templates,
        // which reach the same effective non-extractable/extractable state on those HSMs.
        if !self.hsm_capabilities().supports_aes_sensitive_attribute {
            return if sensitive {
                self.generate_sensitive_aes_key(id, size)
            } else {
                self.generate_exportable_aes_key(id, size)
            };
        }
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
            // A sensitive key must not be extractable: derive CKA_EXTRACTABLE from
            // the `sensitive` flag instead of hard-coding it to CK_TRUE.
            let is_extractable = if sensitive { CK_FALSE } else { CK_TRUE };
            let mut template = aes_key_template!(id, size, is_sensitive, is_extractable);
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
