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
//! Exactly one `message_sign_init` per session, then any number of
//! `sign_message` calls, then a single `message_sign_final`. This mirrors the
//! multi-part message-signing flow of §5.22.2/§5.22.4, where the mechanism and
//! key are fixed at init and each subsequent `C_SignMessage` signs one message
//! under them.
//!
//! # Mechanism support
//!
//! The Cosmian provider only accepts `CKM_EDDSA` here: the RSA-PKCS and
//! SHA-RSA-PKCS mappings are provided for completeness against the generic
//! v3.0 spec, but a token that does not implement them for the message-based
//! path returns `CKR_FUNCTION_NOT_SUPPORTED` from `C_MessageSignInit`.

use std::ptr;

use pkcs11_sys::{
    CK_MECHANISM, CK_OBJECT_HANDLE, CK_ULONG, CKM_EDDSA, CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
};

use crate::{
    HError, HResult, hsm_call,
    session::{HsmSigningAlgorithm, Session},
};

use super::session_impl::is_signing_algorithm_supported;

impl Session {
    /// Initialize a message-based signing operation
    /// (`C_MessageSignInit`) over `key_handle` with `algorithm`.
    ///
    /// Must be called exactly once before any number of `sign_message` calls on
    /// the same session, and followed by a single `message_sign_final`.
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

        hsm_call!(
            self.hsm(),
            "Failed to initialize message signing",
            C_MessageSignInit,
            self.session_handle(),
            &raw mut mechanism,
            key_handle
        );
        Ok(())
    }

    /// Sign `data` using the message-based signing operation initialized by
    /// `message_sign_init`, returning the signature (`C_SignMessage`).
    ///
    /// Uses the two-call "probe for the signature length, then sign" idiom: the
    /// first `C_SignMessage` call passes a null output buffer to learn the
    /// signature size, the second writes it.
    ///
    /// # Errors
    /// Returns an error if the loaded library does not expose `C_SignMessage`, or
    /// if the signature length reported by the second call differs from the
    /// length reported by the first.
    pub fn sign_message(&self, data: &[u8]) -> HResult<Vec<u8>> {
        let mut data = data.to_vec();

        let mut signature_len: CK_ULONG = 0;
        hsm_call!(
            self.hsm(),
            "Failed to get message signature length",
            C_SignMessage,
            self.session_handle(),
            ptr::null_mut::<std::ffi::c_void>(),
            0,
            data.as_mut_ptr(),
            CK_ULONG::try_from(data.len())?,
            ptr::null_mut(),
            &raw mut signature_len
        );

        let expected_len = signature_len;
        let mut signature = vec![0_u8; usize::try_from(signature_len)?];
        hsm_call!(
            self.hsm(),
            "Failed to sign message",
            C_SignMessage,
            self.session_handle(),
            ptr::null_mut::<std::ffi::c_void>(),
            0,
            data.as_mut_ptr(),
            CK_ULONG::try_from(data.len())?,
            signature.as_mut_ptr(),
            &raw mut signature_len
        );

        if signature_len != expected_len {
            return Err(HError::Default(format!(
                "C_SignMessage: signature length mismatch: expected {expected_len}, got \
                 {signature_len}"
            )));
        }
        Ok(signature)
    }

    /// Finalize the message-based signing operation (`C_MessageSignFinal`).
    ///
    /// # Errors
    /// Returns an error if `C_MessageSignFinal` fails.
    pub fn message_sign_final(&self) -> HResult<()> {
        hsm_call!(
            self.hsm(),
            "Failed to finalize message signing",
            C_MessageSignFinal,
            self.session_handle()
        );
        Ok(())
    }
}
