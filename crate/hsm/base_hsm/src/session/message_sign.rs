//! PKCS#11 v3.0 message-based signing operations (OASIS Cryptoki v3.0 §5.22),
//! used to drive `C_MessageSignInit`/`C_SignMessage`/`C_MessageSignFinal` on
//! libraries that export the v3.0 function table.
//!
//! These entry points are additive and only usable when the loaded library
//! reports support via `HsmLib::supports_message_sign` (see `hsm_lib.rs`); any
//! v2.40-only library (or a v3.0 library that does not implement this optional
//! operation family) gracefully falls back to an explicit "not supported" error
//! rather than attempting an FFI call through a null function pointer.
//!
//! # Operation lifecycle
//!
//! `Session::sign` opens a context lazily with `ensure_message_context`, reuses it while the
//! key, mechanism and parameters stay the same, and closes it on change, on error, before a
//! classic init, before `C_FindObjectsInit`, and on non-signature checkout. The public
//! `message_sign_init`/`sign_message`/`message_sign_final` drive the same context explicitly
//! (used by `ckms pkcs11 bench`).
//!
//! # Mechanism support
//!
//! The Cosmian provider only accepts `CKM_EDDSA` here: the RSA-PKCS and
//! SHA-RSA-PKCS mappings are provided for completeness against the generic
//! v3.0 spec, but a token that does not implement them for the message-based
//! path returns `CKR_FUNCTION_NOT_SUPPORTED` from `C_MessageSignInit`.

use std::ptr;

use pkcs11_sys::{
    CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV, CK_ULONG, CKM_EDDSA, CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK, CKR_OPERATION_NOT_INITIALIZED,
};

use super::{message_context::MessageFamily, session_impl::is_signing_algorithm_supported};
use crate::{
    HError, HResult, hsm_call, pkcs11_return_code_name,
    session::{HsmSigningAlgorithm, Session},
};

fn sign_message_error(rv: CK_RV) -> HError {
    HError::Default(format!(
        "Failed to sign message. Return code: {rv} ({rv:#010x}, {})",
        pkcs11_return_code_name(rv)
    ))
}

impl Session {
    /// Initialize a message-based signing operation
    /// (`C_MessageSignInit`) over `key_handle` with `algorithm`.
    ///
    /// Closes any message-signing context already open on the session, then opens a new
    /// one that `sign_message` (and `Session::sign` with the same key and mechanism) reuses
    /// until `message_sign_final`.
    ///
    /// # Errors
    /// Returns an error if `algorithm` is unavailable in the current FIPS mode,
    /// if the loaded library does not support the message-based signing function
    /// family (`HsmLib::supports_message_sign`), if `algorithm` has no
    /// message-based mechanism mapping (only `Eddsa`, `Ed25519`/`Ed448`, and the
    /// RSA-PKCS variants are supported here), or if `C_MessageSignInit` fails.
    pub fn message_sign_init(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: HsmSigningAlgorithm,
    ) -> HResult<()> {
        if !is_signing_algorithm_supported(algorithm) {
            return Err(HError::Default(format!(
                "Signing algorithm {algorithm:?} is unavailable in FIPS mode"
            )));
        }
        if !self.hsm().supports_message_sign() {
            return Err(HError::Default(
                "The loaded PKCS#11 library does not support message-based signing \
                 (C_MessageSignInit/C_SignMessage/C_MessageSignFinal)"
                    .to_owned(),
            ));
        }

        let mechanism = match algorithm {
            HsmSigningAlgorithm::Eddsa => CKM_EDDSA,
            #[cfg(feature = "non-fips")]
            HsmSigningAlgorithm::Ed25519 | HsmSigningAlgorithm::Ed448 => CKM_EDDSA,
            HsmSigningAlgorithm::RsaPkcsV15 => CKM_RSA_PKCS,
            HsmSigningAlgorithm::Sha256WithRsa => CKM_SHA256_RSA_PKCS,
            HsmSigningAlgorithm::Sha384WithRsa => CKM_SHA384_RSA_PKCS,
            HsmSigningAlgorithm::Sha512WithRsa => CKM_SHA512_RSA_PKCS,
            HsmSigningAlgorithm::Sha1WithRsa => CKM_SHA1_RSA_PKCS,
            other => {
                return Err(HError::Default(format!(
                    "Message-based signing is not supported for {other:?}"
                )));
            }
        };

        let mut mechanism = CK_MECHANISM {
            mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        self.end_message_context(MessageFamily::Sign);
        hsm_call!(
            self.hsm(),
            "Failed to initialize message signing",
            C_MessageSignInit,
            self.session_handle(),
            &raw mut mechanism,
            key_handle
        );
        self.record_message_context(MessageFamily::Sign, key_handle, &mechanism)
    }

    /// Signs through the session's persistent message context. `Ok(None)` means the message
    /// path is disabled for this slot or the token rejected the mechanism; the caller then
    /// uses `C_SignInit`/`C_Sign`.
    pub(crate) fn try_sign_message(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        data: &[u8],
    ) -> HResult<Option<Vec<u8>>> {
        let mechanism_type = mechanism.mechanism;
        if !self.message_family_enabled(MessageFamily::Sign, mechanism_type)? {
            return Ok(None);
        }
        let mut reinitialized = false;
        loop {
            if !self.ensure_message_context(MessageFamily::Sign, key_handle, mechanism)? {
                return Ok(None);
            }
            let (rv, signature) = self
                .call_sign_message(data)
                .inspect_err(|_| self.end_message_context(MessageFamily::Sign))?;
            if rv == CKR_OK {
                return Ok(Some(signature));
            }
            if rv == CKR_OPERATION_NOT_INITIALIZED && !reinitialized {
                // The token terminated the context: re-init once and retry.
                self.forget_message_context(MessageFamily::Sign);
                reinitialized = true;
                continue;
            }
            self.end_message_context(MessageFamily::Sign);
            return Err(sign_message_error(rv));
        }
    }

    /// One `C_SignMessage` call (plus a retry on `CKR_BUFFER_TOO_SMALL`); the caller maps the
    /// return code.
    fn call_sign_message(&self, data: &[u8]) -> HResult<(CK_RV, Vec<u8>)> {
        let mut data = data.to_vec();
        let data_len = CK_ULONG::try_from(data.len())?;
        let data_ptr = data.as_mut_ptr();
        Self::call_into_signature_buffer("C_SignMessage", |sig_ptr, sig_len| {
            #[expect(unsafe_code)]
            // SAFETY: `data_ptr`/`data_len` describe the live `data` buffer; `sig_ptr` points to
            // a buffer of `*sig_len` bytes owned by `call_into_signature_buffer`; a null
            // `pParameter` with length 0 is valid for mechanisms without per-message parameters.
            let rv = self
                .hsm()
                .C_SignMessage
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |func| unsafe {
                    func(
                        self.session_handle(),
                        ptr::null_mut(),
                        0,
                        data_ptr,
                        data_len,
                        sig_ptr,
                        sig_len,
                    )
                });
            Ok(rv)
        })
    }

    /// Signs `data` with the message-signing context opened by `message_sign_init`
    /// (`C_SignMessage`). One `C_SignMessage` call into a 512-byte buffer; a second call only
    /// if the token answers `CKR_BUFFER_TOO_SMALL`.
    ///
    /// # Errors
    /// Returns an error if the loaded library does not expose `C_SignMessage` or if it fails.
    pub fn sign_message(&self, data: &[u8]) -> HResult<Vec<u8>> {
        let (rv, signature) = self.call_sign_message(data)?;
        if rv != CKR_OK {
            return Err(sign_message_error(rv));
        }
        Ok(signature)
    }

    /// Finalize the message-based signing operation (`C_MessageSignFinal`).
    ///
    /// # Errors
    /// Returns an error if `C_MessageSignFinal` fails.
    pub fn message_sign_final(&self) -> HResult<()> {
        self.forget_message_context(MessageFamily::Sign);
        hsm_call!(
            self.hsm(),
            "Failed to finalize message signing",
            C_MessageSignFinal,
            self.session_handle()
        );
        Ok(())
    }
}
