use std::{collections::HashSet, ptr};

use pkcs11_sys::{
    CK_ATTRIBUTE_PTR, CK_FALSE, CK_MECHANISM, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_TRUE,
    CK_ULONG, CKM_AES_KEY_GEN,
};

use super::{serialize_tagged_label, utf8_label};
use crate::{HError, HResult, aes_key_template, hsm_call, session::Session};

#[derive(Debug, Clone, Copy)]
pub enum AesKeySize {
    Aes128,
    Aes256,
}

impl Session {
    /// Helper for AES key generation with an explicit `CKA_EXTRACTABLE` but no
    /// `CKA_SENSITIVE` (AWS `CloudHSM` rejects any explicit value for the latter).
    fn generate_aes_key_internal(
        &self,
        id: &[u8],
        size: AesKeySize,
        extractable: bool,
        error_context: &'static str,
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
        let mut aes_key_handle = CK_OBJECT_HANDLE::default();

        let extractable = if extractable { CK_TRUE } else { CK_FALSE };
        let mut template = aes_key_template!(id, size, extractable);
        #[cfg(target_os = "windows")]
        let len = u32::try_from(template.len())?;
        #[cfg(not(target_os = "windows"))]
        let len = u64::try_from(template.len())?;
        hsm_call!(
            self.hsm(),
            error_context,
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

    /// Generate a sensitive AES key using `CKA_EXTRACTABLE=false`, without
    /// setting `CKA_SENSITIVE`: AWS `CloudHSM` rejects any explicit value for
    /// the Sensitive attribute.
    pub fn generate_sensitive_aes_key(
        &self,
        id: &[u8],
        size: AesKeySize,
    ) -> HResult<CK_OBJECT_HANDLE> {
        self.generate_aes_key_internal(id, size, false, "Failed generating sensitive key")
    }

    /// Generate an exportable AES key using `CKA_EXTRACTABLE=true`, without
    /// setting `CKA_SENSITIVE`: AWS `CloudHSM` rejects any explicit value for
    /// the Sensitive attribute.
    pub fn generate_exportable_aes_key(
        &self,
        id: &[u8],
        size: AesKeySize,
    ) -> HResult<CK_OBJECT_HANDLE> {
        self.generate_aes_key_internal(id, size, true, "Failed generating exportable key")
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
        tags: Option<&HashSet<String>>,
    ) -> HResult<CK_OBJECT_HANDLE> {
        // Some vendors (AWS CloudHSM) reject any explicit value for CKA_SENSITIVE on
        // C_GenerateKey; fall back to the CKA_EXTRACTABLE-only templates, so a sensitive
        // key is still explicitly non-extractable on those HSMs.
        if !self.hsm_capabilities().aes.supports_sensitive_attribute {
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
            let label = serialize_tagged_label(id, tags, self.hsm_capabilities().max_label_len)?
                .unwrap_or_else(|| utf8_label(id));
            let mut template =
                aes_key_template!(id, label, size, is_sensitive, is_extractable).to_vec();
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
