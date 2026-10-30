//! Persistent PKCS#11 v3.0 message-signature contexts (`C_MessageSignInit` /
//! `C_MessageVerifyInit`), shared by `Session::sign` and `Session::verify`.
//!
//! A context stays open on the pooled session after use, so repeated operations with the
//! same key, mechanism and parameters cost one `C_SignMessage` / `C_VerifyMessage` each.

use std::{
    collections::HashSet,
    sync::{MutexGuard, PoisonError},
};

use cosmian_logger::{debug, warn};
use pkcs11_sys::{
    CK_MECHANISM, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RV, CKR_FUNCTION_NOT_SUPPORTED, CKR_OK,
    CKR_OPERATION_ACTIVE,
};

use super::session_impl::is_mechanism_unsupported_rv;
use crate::{HError, HResult, pkcs11_return_code_name, session::Session};

/// Mechanisms the slot's token rejected at `C_MessageSignInit`/`C_MessageVerifyInit`;
/// shared by every session of one slot.
#[derive(Debug, Default)]
pub(crate) struct MessageMechanismSupport {
    pub(crate) sign_unsupported: HashSet<CK_MECHANISM_TYPE>,
    pub(crate) verify_unsupported: HashSet<CK_MECHANISM_TYPE>,
}

/// Which message-based operation family a context belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageFamily {
    Sign,
    Verify,
}

impl MessageFamily {
    const fn other(self) -> Self {
        match self {
            Self::Sign => Self::Verify,
            Self::Verify => Self::Sign,
        }
    }

    const fn noun(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
        }
    }

    const fn final_name(self) -> &'static str {
        match self {
            Self::Sign => "C_MessageSignFinal",
            Self::Verify => "C_MessageVerifyFinal",
        }
    }
}

/// Identity of an open message context: same key, mechanism type and parameter bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessageContextKey {
    key_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: Vec<u8>,
}

impl MessageContextKey {
    pub(crate) fn new(key_handle: CK_OBJECT_HANDLE, mechanism: &CK_MECHANISM) -> HResult<Self> {
        // Copy the fields out of the (possibly packed) `CK_MECHANISM` first: references into a
        // packed struct are rejected by rustc (`E0793`).
        let mechanism_type = mechanism.mechanism;
        let parameter_ptr = mechanism.pParameter;
        let parameter_len = usize::try_from(mechanism.ulParameterLen)?;
        let parameter = if parameter_ptr.is_null() || parameter_len == 0 {
            Vec::new()
        } else {
            #[expect(unsafe_code)]
            // SAFETY: callers build `pParameter` from a live parameter struct of exactly
            // `ulParameterLen` bytes (`sign_with_pss_mechanism`/`verify_with_pss_mechanism`).
            let bytes =
                unsafe { std::slice::from_raw_parts(parameter_ptr.cast::<u8>(), parameter_len) };
            bytes.to_vec()
        };
        Ok(Self {
            key_handle,
            mechanism: mechanism_type,
            parameter,
        })
    }
}

/// Message contexts currently open on one session.
#[derive(Debug, Default)]
pub(crate) struct OpenMessageContexts {
    sign: Option<MessageContextKey>,
    verify: Option<MessageContextKey>,
}

impl OpenMessageContexts {
    const fn slot(&mut self, family: MessageFamily) -> &mut Option<MessageContextKey> {
        match family {
            MessageFamily::Sign => &mut self.sign,
            MessageFamily::Verify => &mut self.verify,
        }
    }
}

/// Whether a return code from a message-family init means "use the classic API instead".
pub(crate) const fn is_message_unsupported_rv(rv: CK_RV) -> bool {
    rv == CKR_FUNCTION_NOT_SUPPORTED || is_mechanism_unsupported_rv(rv)
}

impl Session {
    fn open_contexts(&self) -> MutexGuard<'_, OpenMessageContexts> {
        // Plain per-session data: a poisoned lock leaves it consistent.
        self.open_message_contexts()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_message_support(&self) -> HResult<MutexGuard<'_, MessageMechanismSupport>> {
        self.message_mechanism_support()
            .lock()
            .map_err(|e| HError::Default(format!("Failed to lock message mechanism support: {e}")))
    }

    /// Records an explicitly opened context (`message_sign_init`) so `sign` can reuse it.
    pub(crate) fn record_message_context(
        &self,
        family: MessageFamily,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &CK_MECHANISM,
    ) -> HResult<()> {
        *self.open_contexts().slot(family) = Some(MessageContextKey::new(key_handle, mechanism)?);
        Ok(())
    }

    /// Whether the message path may be tried for `mechanism_type`: the provider opted in, the
    /// library exports the family, and the token did not already reject this mechanism.
    pub(crate) fn message_family_enabled(
        &self,
        family: MessageFamily,
        mechanism_type: CK_MECHANISM_TYPE,
    ) -> HResult<bool> {
        if !self.hsm_capabilities().supports_message_sign_verify {
            return Ok(false);
        }
        let exported = match family {
            MessageFamily::Sign => self.hsm().supports_message_sign(),
            MessageFamily::Verify => self.hsm().supports_message_verify(),
        };
        if !exported {
            return Ok(false);
        }
        let support = self.lock_message_support()?;
        let rejected = match family {
            MessageFamily::Sign => &support.sign_unsupported,
            MessageFamily::Verify => &support.verify_unsupported,
        };
        Ok(!rejected.contains(&mechanism_type))
    }

    /// Marks the family's context closed without any FFI call (the token already ended it).
    pub(crate) fn forget_message_context(&self, family: MessageFamily) {
        self.open_contexts().slot(family).take();
    }

    /// Closes the family's open context, if any. A failing final is only logged: the next
    /// init surfaces a truly stuck operation as `CKR_OPERATION_ACTIVE`.
    pub(crate) fn end_message_context(&self, family: MessageFamily) {
        if self.open_contexts().slot(family).take().is_none() {
            return;
        }
        let hsm = self.hsm();
        let handle = self.session_handle();
        #[expect(unsafe_code)]
        // SAFETY: `handle` is this session's live PKCS#11 session handle; the final functions
        // take no other argument.
        let rv = match family {
            MessageFamily::Sign => hsm
                .C_MessageSignFinal
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |f| unsafe { f(handle) }),
            MessageFamily::Verify => hsm
                .C_MessageVerifyFinal
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |f| unsafe { f(handle) }),
        };
        if rv != CKR_OK {
            warn!(
                "{} failed: {rv:#010x} ({}); context dropped",
                family.final_name(),
                pkcs11_return_code_name(rv)
            );
        }
    }

    /// Closes both message contexts; no FFI call when nothing is open.
    pub(crate) fn end_message_operations(&self) {
        self.end_message_context(MessageFamily::Sign);
        self.end_message_context(MessageFamily::Verify);
    }

    #[expect(unsafe_code)]
    fn raw_message_init(
        &self,
        family: MessageFamily,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
    ) -> CK_RV {
        let hsm = self.hsm();
        let handle = self.session_handle();
        // SAFETY: `mechanism` is a live `&mut CK_MECHANISM` whose `pParameter` points to a live
        // parameter struct for the duration of the call; handles are opaque.
        match family {
            MessageFamily::Sign => hsm
                .C_MessageSignInit
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |f| unsafe {
                    f(handle, mechanism, key_handle)
                }),
            MessageFamily::Verify => hsm
                .C_MessageVerifyInit
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |f| unsafe {
                    f(handle, mechanism, key_handle)
                }),
        }
    }

    /// Makes sure a message context for `family` is open for this key and mechanism.
    ///
    /// Returns `Ok(false)` when the token rejects the mechanism (cached per slot): the caller
    /// then uses the classic API.
    pub(crate) fn ensure_message_context(
        &self,
        family: MessageFamily,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
    ) -> HResult<bool> {
        let key = MessageContextKey::new(key_handle, mechanism)?;
        if self.open_contexts().slot(family).as_ref() == Some(&key) {
            return Ok(true);
        }
        self.end_message_context(family);
        let mut rv = self.raw_message_init(family, key_handle, mechanism);
        if rv == CKR_OPERATION_ACTIVE {
            self.end_message_context(family.other());
            rv = self.raw_message_init(family, key_handle, mechanism);
        }
        if rv == CKR_OK {
            *self.open_contexts().slot(family) = Some(key);
            return Ok(true);
        }
        let mechanism_type = key.mechanism;
        if is_message_unsupported_rv(rv) {
            // Keyed by mechanism type only: a `CKR_MECHANISM_PARAM_INVALID` caused by one
            // parameter set disables the message path for that mechanism on this slot, and the
            // classic path still serves it.
            let mut support = self.lock_message_support()?;
            match family {
                MessageFamily::Sign => support.sign_unsupported.insert(mechanism_type),
                MessageFamily::Verify => support.verify_unsupported.insert(mechanism_type),
            };
            debug!(
                "PKCS#11 message-based {0} unsupported for mechanism {mechanism_type:#x} ({1}); \
                 using C_{2}Init",
                family.noun(),
                pkcs11_return_code_name(rv),
                match family {
                    MessageFamily::Sign => "Sign",
                    MessageFamily::Verify => "Verify",
                }
            );
            return Ok(false);
        }
        Err(HError::Default(format!(
            "Failed to initialize message-based {}. Return code: {rv} ({rv:#010x}, {})",
            match family {
                MessageFamily::Sign => "signing",
                MessageFamily::Verify => "verification",
            },
            pkcs11_return_code_name(rv)
        )))
    }
}
