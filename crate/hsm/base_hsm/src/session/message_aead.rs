//! PKCS#11 v3.0 message-based AEAD operations (OASIS Cryptoki v3.0 §5.9/§5.11),
//! used for AES-GCM as a "message" operation instead of the classic
//! `C_Encrypt`/`C_EncryptUpdate` flow.
//!
//! These entry points are additive and only usable when the loaded library
//! reports support via `HsmLib::supports_message_encrypt`/`supports_message_decrypt`
//! (see `hsm_lib.rs`); any v2.40-only library (or a v3.0 library that does not
//! implement this optional operation family) gracefully falls back to an explicit
//! "not supported" error rather than attempting an FFI call through a null function
//! pointer.
//!
//! Both operations issue exactly one `C_EncryptMessage`/`C_DecryptMessage` call rather
//! than the two-call "probe for the output size, then encrypt" idiom used elsewhere in
//! this crate, because each such call "begins and terminates a message
//! encryption operation" (§5.9.2/§5.11.2) and would therefore look like a second message
//! reusing the same IV. See the comments at each call site.

use std::ptr;

use cosmian_kms_interfaces::EncryptedContent;
use pkcs11_sys::{
    CK_GCM_MESSAGE_PARAMS, CK_MECHANISM, CK_OBJECT_HANDLE, CK_ULONG, CKG_GENERATE_RANDOM,
    CKG_NO_GENERATE, CKM_AES_GCM, CKR_BUFFER_TOO_SMALL, CKR_OK,
};
use zeroize::Zeroizing;

use crate::{HError, HResult, session::Session};

const AES_GCM_MESSAGE_IV_LENGTH: usize = 12;
const AES_GCM_MESSAGE_TAG_LENGTH: usize = 16;

impl Session {
    /// Encrypt `plaintext` under `key_handle` using AES-GCM as a PKCS#11 v3.0
    /// "message" operation (`C_MessageEncryptInit`/`C_EncryptMessage`/`C_MessageEncryptFinal`).
    ///
    /// The HSM/KMS generates a fresh random 96-bit IV for every call (`ivGenerator`
    /// is set to `CKG_GENERATE_RANDOM`), and the IV is returned in the output buffer.
    /// Exactly one
    /// `C_EncryptMessage` call is issued per invocation, so the token never sees the
    /// same IV twice within a message-encryption operation — see the call site for why
    /// that matters.
    ///
    /// # Errors
    /// Returns an error if the loaded library does not support the message-based
    /// encryption function family (`HsmLib::supports_message_encrypt`), or if it
    /// reports that a ciphertext buffer the size of the plaintext is too small (which
    /// would contradict AES-GCM's detached-tag message layout).
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
                 Cryptoki v3.0 §5.9)"
                    .to_owned(),
            ));
        }

        // Let the HSM/KMS generate the IV with CKG_GENERATE_RANDOM
        // pIv will be filled by C_EncryptMessage as output
        let mut nonce = [0_u8; AES_GCM_MESSAGE_IV_LENGTH];
        let mut tag = vec![0_u8; AES_GCM_MESSAGE_TAG_LENGTH];
        let mut params = CK_GCM_MESSAGE_PARAMS {
            pIv: nonce.as_mut_ptr(),
            ulIvLen: CK_ULONG::try_from(AES_GCM_MESSAGE_IV_LENGTH)?,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
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

            // Deliberately a *single* call, not the two-call "NULL output buffer first to
            // learn the size" idiom used elsewhere in this crate. Per OASIS Cryptoki v3.0
            // base §5.9.2, "a call to `C_EncryptMessage` begins and terminates a message
            // encryption operation" — so a size probe followed by the real call would present
            // the token with two distinct messages, each with a different IV (since
            // `ivGenerator = CKG_GENERATE_RANDOM` lets the HSM generate fresh IVs).
            // This single-call constraint also means ciphertext and tag lengths are
            // known upfront per current-mechanisms §2.13.2 (tag in `pTag` field,
            // ciphertext size = plaintext size), so no length probe is needed.

            // `Vec::as_mut_ptr` never yields NULL (an unallocated `Vec` returns a
            // dangling-but-non-null pointer), so a zero-length plaintext — a legitimate
            // AEAD input when there is AAD to authenticate — still selects base §5.2's
            // real call rather than being misread as a size probe.
            let mut ciphertext = vec![0_u8; plaintext.len()];
            let mut ciphertext_len = CK_ULONG::try_from(ciphertext.len())?;
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
            // Deliberately not retried with a larger buffer: a second `C_EncryptMessage`
            // would re-present the same IV, which is precisely what the single-call flow
            // above exists to avoid. Report it instead, with enough detail to diagnose a
            // token that disagrees with the detached-tag length invariant.
            if rv == CKR_BUFFER_TOO_SMALL {
                return Err(HError::Default(format!(
                    "Message-based encryption rejected a {} byte ciphertext buffer for a {} \
                     byte plaintext (token reports {ciphertext_len} bytes required). CKM_AES_GCM \
                     in message mode returns its tag detached in CK_GCM_MESSAGE_PARAMS.pTag \
                     (OASIS Cryptoki v3.0 current-mechanisms §2.13.2), so ciphertext and \
                     plaintext must be the same length; retrying with a larger buffer is refused \
                     because it would re-present the same IV to the token",
                    ciphertext.len(),
                    plaintext.len(),
                )));
            }
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
    /// decryption function family (`HsmLib::supports_message_decrypt`), or if it reports
    /// that a plaintext buffer the size of the ciphertext is too small (which would
    /// contradict AES-GCM's detached-tag message layout).
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
                 Cryptoki v3.0 §5.11)"
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

            // Single call, for the reason spelled out in `encrypt_message_aes_gcm`: OASIS
            // Cryptoki v3.0 base §5.11.2 likewise states that "a call to
            // `C_DecryptMessage` begins and terminates a message decryption operation", so
            // a NULL-buffer size probe followed by the real call would make the token see
            // two messages sharing one IV — against current-mechanisms §2.13.5's "each IV
            // must be unique for a given session". The size needs no probing: the tag is
            // supplied detached in `CK_GCM_MESSAGE_PARAMS.pTag` rather than appended to
            // the ciphertext, and `CKM_AES_GCM` is CTR-based, so the plaintext is exactly
            // as long as the ciphertext.
            let mut plaintext = vec![0_u8; ciphertext.len()];
            let mut plaintext_len = CK_ULONG::try_from(plaintext.len())?;
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
            // Not retried with a larger buffer: unlike the encrypt side there is no IV to
            // reuse, but a second `C_DecryptMessage` would re-run tag verification on a
            // terminated operation, and a token needing more than `ciphertext.len()` bytes
            // contradicts the detached-tag layout. Report it instead.
            if rv == CKR_BUFFER_TOO_SMALL {
                return Err(HError::Default(format!(
                    "Message-based decryption rejected a {} byte plaintext buffer for a {} byte \
                     ciphertext (token reports {plaintext_len} bytes required). CKM_AES_GCM in \
                     message mode takes its tag detached in CK_GCM_MESSAGE_PARAMS.pTag (OASIS \
                     Cryptoki v3.0 current-mechanisms §2.13.2), so plaintext and ciphertext \
                     must be the same length",
                    plaintext.len(),
                    ciphertext.len(),
                )));
            }
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
