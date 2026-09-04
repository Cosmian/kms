//! PKCS#11 v3.0 message-based AEAD operations (OASIS Cryptoki v3.0 §5.20/§5.21),
//! used for AES-GCM as a "message" operation instead of the classic
//! `C_Encrypt`/`C_EncryptUpdate` flow.
//!
//! These entry points are additive and only usable when the loaded library
//! reports support via `HsmLib::supports_message_encrypt`/`supports_message_decrypt`
//! (see `hsm_lib.rs`); any v2.40-only library (or a v3.0 library that does not
//! implement this optional operation family) gracefully falls back to an explicit
//! "not supported" error rather than attempting an FFI call through a null function
//! pointer.

use std::ptr;

use cosmian_kms_interfaces::EncryptedContent;
use pkcs11_sys::{
    CK_GCM_MESSAGE_PARAMS, CK_MECHANISM, CK_OBJECT_HANDLE, CK_ULONG, CKG_NO_GENERATE, CKM_AES_GCM,
    CKR_OK,
};
use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroizing;

use crate::{HError, HResult, session::Session};

const AES_GCM_MESSAGE_IV_LENGTH: usize = 12;
const AES_GCM_MESSAGE_TAG_LENGTH: usize = 16;

impl Session {
    /// Encrypt `plaintext` under `key_handle` using AES-GCM as a PKCS#11 v3.0
    /// "message" operation (`C_MessageEncryptInit`/`C_EncryptMessage`/`C_MessageEncryptFinal`).
    ///
    /// A fresh random 96-bit IV is generated client-side for every call (`ivGenerator`
    /// is set to `CKG_NO_GENERATE`, i.e. the caller supplies the IV), matching the
    /// existing classic `Session::encrypt` `AesGcm` behavior.
    ///
    /// # Errors
    /// Returns an error if the loaded library does not support the message-based
    /// encryption function family (`HsmLib::supports_message_encrypt`).
    pub fn encrypt_message_aes_gcm(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        aad: &[u8],
        plaintext: &[u8],
    ) -> HResult<EncryptedContent> {
        if !self.hsm().supports_message_encrypt() {
            return Err(HError::Default(
                "The loaded PKCS#11 library does not support message-based encryption \
                 (C_MessageEncryptInit/C_EncryptMessage/C_MessageEncryptFinal — OASIS \
                 Cryptoki v3.0 §5.20)"
                    .to_owned(),
            ));
        }

        let mut nonce = [0_u8; AES_GCM_MESSAGE_IV_LENGTH];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| HError::Default(format!("Error generating random nonce: {e}")))?;
        let mut tag = vec![0_u8; AES_GCM_MESSAGE_TAG_LENGTH];
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: nonce.as_mut_ptr(),
            ulIvLen: CK_ULONG::try_from(AES_GCM_MESSAGE_IV_LENGTH)?,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: CK_ULONG::try_from(AES_GCM_MESSAGE_TAG_LENGTH * 8)?,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        #[expect(unsafe_code)]
        // SAFETY: capability-checked above; every function called below was
        // resolved from the same loaded library and matches its documented
        // PKCS#11 v3.0 signature.
        unsafe {
            let init = self
                .hsm()
                .C_MessageEncryptInit
                .ok_or_else(|| HError::Default("C_MessageEncryptInit unavailable".to_owned()))?;
            let rv = init(self.session_handle(), &raw mut mechanism, key_handle);
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to initialize message-based encryption. Return code: {rv}"
                )));
            }

            let encrypt = self
                .hsm()
                .C_EncryptMessage
                .ok_or_else(|| HError::Default("C_EncryptMessage unavailable".to_owned()))?;
            let mut aad = aad.to_vec();
            let mut plaintext = plaintext.to_vec();

            // Two-call idiom: first with a NULL output buffer to get the required size.
            let mut ciphertext_len: CK_ULONG = 0;
            let rv = encrypt(
                self.session_handle(),
                (&raw mut params).cast::<std::ffi::c_void>(),
                CK_ULONG::try_from(size_of::<CK_GCM_MESSAGE_PARAMS>())?,
                aad.as_mut_ptr(),
                CK_ULONG::try_from(aad.len())?,
                plaintext.as_mut_ptr(),
                CK_ULONG::try_from(plaintext.len())?,
                ptr::null_mut(),
                &raw mut ciphertext_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to size message-based ciphertext. Return code: {rv}"
                )));
            }

            let mut ciphertext = vec![0_u8; usize::try_from(ciphertext_len)?];
            let rv = encrypt(
                self.session_handle(),
                (&raw mut params).cast::<std::ffi::c_void>(),
                CK_ULONG::try_from(size_of::<CK_GCM_MESSAGE_PARAMS>())?,
                aad.as_mut_ptr(),
                CK_ULONG::try_from(aad.len())?,
                plaintext.as_mut_ptr(),
                CK_ULONG::try_from(plaintext.len())?,
                ciphertext.as_mut_ptr(),
                &raw mut ciphertext_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to perform message-based encryption. Return code: {rv}"
                )));
            }
            ciphertext.truncate(usize::try_from(ciphertext_len)?);

            let end = self
                .hsm()
                .C_MessageEncryptFinal
                .ok_or_else(|| HError::Default("C_MessageEncryptFinal unavailable".to_owned()))?;
            let rv = end(self.session_handle());
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to finalize message-based encryption. Return code: {rv}"
                )));
            }

            Ok(EncryptedContent {
                iv: Some(nonce.to_vec()),
                ciphertext,
                tag: Some(tag),
            })
        }
    }

    /// Decrypt `ciphertext` (with detached `tag`/`iv`) under `key_handle` using
    /// AES-GCM as a PKCS#11 v3.0 "message" operation
    /// (`C_MessageDecryptInit`/`C_DecryptMessage`/`C_MessageDecryptFinal`).
    ///
    /// # Errors
    /// Returns an error if the loaded library does not support the message-based
    /// decryption function family (`HsmLib::supports_message_decrypt`).
    pub fn decrypt_message_aes_gcm(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        aad: &[u8],
        iv: &[u8],
        tag: &[u8],
        ciphertext: &[u8],
    ) -> HResult<Zeroizing<Vec<u8>>> {
        if !self.hsm().supports_message_decrypt() {
            return Err(HError::Default(
                "The loaded PKCS#11 library does not support message-based decryption \
                 (C_MessageDecryptInit/C_DecryptMessage/C_MessageDecryptFinal — OASIS \
                 Cryptoki v3.0 §5.21)"
                    .to_owned(),
            ));
        }

        let mut iv = iv.to_vec();
        let mut tag = tag.to_vec();
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: CK_ULONG::try_from(iv.len())?,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: CK_ULONG::try_from(tag.len() * 8)?,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        #[expect(unsafe_code)]
        // SAFETY: capability-checked above; every function called below was
        // resolved from the same loaded library and matches its documented
        // PKCS#11 v3.0 signature.
        unsafe {
            let init = self
                .hsm()
                .C_MessageDecryptInit
                .ok_or_else(|| HError::Default("C_MessageDecryptInit unavailable".to_owned()))?;
            let rv = init(self.session_handle(), &raw mut mechanism, key_handle);
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to initialize message-based decryption. Return code: {rv}"
                )));
            }

            let decrypt = self
                .hsm()
                .C_DecryptMessage
                .ok_or_else(|| HError::Default("C_DecryptMessage unavailable".to_owned()))?;
            let mut aad = aad.to_vec();
            let mut ciphertext = ciphertext.to_vec();

            let mut plaintext_len: CK_ULONG = 0;
            let rv = decrypt(
                self.session_handle(),
                (&raw mut params).cast::<std::ffi::c_void>(),
                CK_ULONG::try_from(size_of::<CK_GCM_MESSAGE_PARAMS>())?,
                aad.as_mut_ptr(),
                CK_ULONG::try_from(aad.len())?,
                ciphertext.as_mut_ptr(),
                CK_ULONG::try_from(ciphertext.len())?,
                ptr::null_mut(),
                &raw mut plaintext_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to size message-based plaintext. Return code: {rv}"
                )));
            }

            let mut plaintext = vec![0_u8; usize::try_from(plaintext_len)?];
            let rv = decrypt(
                self.session_handle(),
                (&raw mut params).cast::<std::ffi::c_void>(),
                CK_ULONG::try_from(size_of::<CK_GCM_MESSAGE_PARAMS>())?,
                aad.as_mut_ptr(),
                CK_ULONG::try_from(aad.len())?,
                ciphertext.as_mut_ptr(),
                CK_ULONG::try_from(ciphertext.len())?,
                plaintext.as_mut_ptr(),
                &raw mut plaintext_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to perform message-based decryption. Return code: {rv}"
                )));
            }
            plaintext.truncate(usize::try_from(plaintext_len)?);

            let end = self
                .hsm()
                .C_MessageDecryptFinal
                .ok_or_else(|| HError::Default("C_MessageDecryptFinal unavailable".to_owned()))?;
            let rv = end(self.session_handle());
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to finalize message-based decryption. Return code: {rv}"
                )));
            }

            Ok(Zeroizing::new(plaintext))
        }
    }
}
