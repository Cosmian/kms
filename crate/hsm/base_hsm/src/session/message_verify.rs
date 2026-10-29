//! PKCS#11 v3.0 message-based signature verification (OASIS Cryptoki v3.0 §5.23), routed
//! through the persistent context managed by `message_context.rs`.

use std::ptr;

use pkcs11_sys::{
    CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV, CK_ULONG, CKR_FUNCTION_NOT_SUPPORTED, CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
};

use super::{message_context::MessageFamily, session_impl::is_mechanism_unsupported_rv};
use crate::{HError, HResult, pkcs11_return_code_name, session::Session};

impl Session {
    /// Verifies through the session's persistent message context (`C_VerifyMessage`).
    /// `Ok(None)`: message path disabled or mechanism rejected; caller uses `C_VerifyInit`/`C_Verify`.
    pub(crate) fn try_verify_message(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        data: &[u8],
        signature: &[u8],
    ) -> HResult<Option<bool>> {
        // Copy the field out of the (possibly packed) `CK_MECHANISM` before formatting it.
        let mechanism_type = mechanism.mechanism;
        if !self.message_family_enabled(MessageFamily::Verify, mechanism_type)? {
            return Ok(None);
        }
        let mut reinitialized = false;
        loop {
            if !self.ensure_message_context(MessageFamily::Verify, key_handle, mechanism)? {
                return Ok(None);
            }
            let rv = self.call_verify_message(data, signature).inspect_err(|_| {
                self.end_message_context(MessageFamily::Verify);
            })?;
            if rv == CKR_OK {
                return Ok(Some(true));
            }
            if rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE {
                return Ok(Some(false));
            }
            if rv == CKR_OPERATION_NOT_INITIALIZED && !reinitialized {
                // The token terminated the context: re-init once and retry.
                self.forget_message_context(MessageFamily::Verify);
                reinitialized = true;
                continue;
            }
            self.end_message_context(MessageFamily::Verify);
            return Err(
                if is_mechanism_unsupported_rv(rv) || rv == CKR_FUNCTION_NOT_SUPPORTED {
                    HError::Default(format!(
                        "The loaded PKCS#11 library does not support mechanism {mechanism_type}. \
                     Return code: {rv}"
                    ))
                } else {
                    HError::Default(format!(
                        "Failed to verify message signature. Return code: {rv} ({rv:#010x}, {})",
                        pkcs11_return_code_name(rv)
                    ))
                },
            );
        }
    }

    fn call_verify_message(&self, data: &[u8], signature: &[u8]) -> HResult<CK_RV> {
        let mut data = data.to_vec();
        let mut signature = signature.to_vec();
        let data_len = CK_ULONG::try_from(data.len())?;
        let signature_len = CK_ULONG::try_from(signature.len())?;
        #[expect(unsafe_code)]
        // SAFETY: `data` and `signature` are live owned buffers whose lengths are passed
        // alongside their pointers; a null `pParameter` with length 0 is valid for mechanisms
        // without per-message parameters.
        let rv = self
            .hsm()
            .C_VerifyMessage
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |func| unsafe {
                func(
                    self.session_handle(),
                    ptr::null_mut(),
                    0,
                    data.as_mut_ptr(),
                    data_len,
                    signature.as_mut_ptr(),
                    signature_len,
                )
            });
        Ok(rv)
    }
}
