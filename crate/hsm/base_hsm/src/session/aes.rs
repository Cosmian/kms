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
    /// Helper for AES key generation without explicit `CKA_SENSITIVE`
    /// (used by AWS `CloudHSM` or when default sensitivity attributes are requested).
    fn generate_aes_key_internal(
        &self,
        id: &[u8],
        size: AesKeySize,
        extractable: Option<bool>,
        algorithm: Option<CK_ULONG>,
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
        let aes_algorithm_attribute = self.hsm_capabilities().aes_algorithm_attribute.map(
            |(attribute_type, default_algorithm)| {
                (attribute_type, algorithm.unwrap_or(default_algorithm))
            },
        );

        if let Some(extractable) = extractable {
            let extractable = if extractable { CK_TRUE } else { CK_FALSE };
            let mut template = aes_key_template!(id, size, extractable).to_vec();
            if !self.hsm_capabilities().supports_aes_class_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_CLASS);
            }
            if !self.hsm_capabilities().supports_aes_key_type_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_KEY_TYPE);
            }
            if !self.hsm_capabilities().supports_aes_value_len_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_VALUE_LEN);
            }
            if !self.hsm_capabilities().supports_aes_token_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_TOKEN);
            }
            if !self.hsm_capabilities().supports_aes_usage_attributes {
                template.retain(|attribute| {
                    !matches!(
                        attribute.type_,
                        pkcs11_sys::CKA_ENCRYPT | pkcs11_sys::CKA_DECRYPT | pkcs11_sys::CKA_PRIVATE
                    )
                });
            }
            if !self.hsm_capabilities().supports_aes_label_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_LABEL);
            }
            if !self.hsm_capabilities().supports_aes_id_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_ID);
            }
            if let Some((attribute_type, algorithm)) = aes_algorithm_attribute {
                template.push(pkcs11_sys::CK_ATTRIBUTE {
                    type_: attribute_type,
                    pValue: std::ptr::from_ref(&algorithm)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_ULONG>())?,
                });
            }
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
        } else {
            let mut template = aes_key_template!(id, size).to_vec();
            if !self.hsm_capabilities().supports_aes_class_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_CLASS);
            }
            if !self.hsm_capabilities().supports_aes_key_type_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_KEY_TYPE);
            }
            if !self.hsm_capabilities().supports_aes_value_len_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_VALUE_LEN);
            }
            if !self.hsm_capabilities().supports_aes_token_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_TOKEN);
            }
            if !self.hsm_capabilities().supports_aes_usage_attributes {
                template.retain(|attribute| {
                    !matches!(
                        attribute.type_,
                        pkcs11_sys::CKA_ENCRYPT | pkcs11_sys::CKA_DECRYPT | pkcs11_sys::CKA_PRIVATE
                    )
                });
            }
            if !self.hsm_capabilities().supports_aes_label_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_LABEL);
            }
            if !self.hsm_capabilities().supports_aes_id_attribute {
                template.retain(|attribute| attribute.type_ != pkcs11_sys::CKA_ID);
            }
            if let Some((attribute_type, algorithm)) = aes_algorithm_attribute {
                template.push(pkcs11_sys::CK_ATTRIBUTE {
                    type_: attribute_type,
                    pValue: std::ptr::from_ref(&algorithm)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_ULONG>())?,
                });
            }
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
        }

        self.object_handles_cache()
            .insert(id.to_vec(), aes_key_handle)?;
        Ok(aes_key_handle)
    }

    /// Generate a sensitive AES key using the PKCS#11 default sensitivity attributes.
    pub fn generate_sensitive_aes_key(
        &self,
        id: &[u8],
        size: AesKeySize,
    ) -> HResult<CK_OBJECT_HANDLE> {
        self.generate_aes_key_internal(id, size, None, None, "Failed generating sensitive key")
    }

    /// Generate a sensitive AES key with a provider-specific algorithm value.
    pub fn generate_sensitive_aes_key_with_algorithm(
        &self,
        id: &[u8],
        size: AesKeySize,
        algorithm: CK_ULONG,
    ) -> HResult<CK_OBJECT_HANDLE> {
        self.generate_aes_key_internal(
            id,
            size,
            None,
            Some(algorithm),
            "Failed generating sensitive key",
        )
    }

    /// Generate an exportable AES key using `CKA_EXTRACTABLE=true`, without
    /// setting `CKA_SENSITIVE`: AWS `CloudHSM` rejects any explicit value for
    /// the Sensitive attribute.
    pub fn generate_exportable_aes_key(
        &self,
        id: &[u8],
        size: AesKeySize,
    ) -> HResult<CK_OBJECT_HANDLE> {
        self.generate_aes_key_internal(
            id,
            size,
            Some(true),
            None,
            "Failed generating exportable key",
        )
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
