use std::ptr;

use cosmian_logger::warn;
use libloading::Library;
use pkcs11_sys::{
    CK_C_CloseSession, CK_C_Decrypt, CK_C_DecryptFinal, CK_C_DecryptInit, CK_C_DecryptMessage,
    CK_C_DecryptMessageBegin, CK_C_DecryptMessageNext, CK_C_DecryptUpdate, CK_C_DeriveKey,
    CK_C_DestroyObject, CK_C_Encrypt, CK_C_EncryptFinal, CK_C_EncryptInit, CK_C_EncryptMessage,
    CK_C_EncryptMessageBegin, CK_C_EncryptMessageNext, CK_C_EncryptUpdate, CK_C_Finalize,
    CK_C_FindObjects, CK_C_FindObjectsFinal, CK_C_FindObjectsInit, CK_C_GenerateKey,
    CK_C_GenerateKeyPair, CK_C_GenerateRandom, CK_C_GetAttributeValue, CK_C_GetInfo,
    CK_C_GetMechanismInfo, CK_C_GetMechanismList, CK_C_INITIALIZE_ARGS, CK_C_Initialize,
    CK_C_Login, CK_C_LoginUser, CK_C_Logout, CK_C_MessageDecryptFinal, CK_C_MessageDecryptInit,
    CK_C_MessageEncryptFinal, CK_C_MessageEncryptInit, CK_C_MessageSignFinal, CK_C_MessageSignInit,
    CK_C_MessageVerifyFinal, CK_C_MessageVerifyInit, CK_C_OpenSession, CK_C_SeedRandom,
    CK_C_SessionCancel, CK_C_SetAttributeValue, CK_C_Sign, CK_C_SignInit, CK_C_SignMessage,
    CK_C_SignMessageBegin, CK_C_SignMessageNext, CK_C_UnwrapKey, CK_C_Verify, CK_C_VerifyInit,
    CK_C_VerifyMessage, CK_C_VerifyMessageBegin, CK_C_VerifyMessageNext, CK_C_WrapKey,
    CKF_OS_LOCKING_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK,
};

use crate::{
    HResult, hsm_call,
    pkcs11_v3::{self, CkInterface, InterfaceDescriptor},
};

/// Defense-in-depth cap on the PKCS#11 v3.0 interface count reported by
/// `C_GetInterfaceList` before allocating a buffer for it (see threat-model finding
/// T-101). No conformant library is expected to exceed this by orders of magnitude.
const MAX_PLAUSIBLE_PKCS11_V3_INTERFACES: pkcs11_sys::CK_ULONG = 4096;

/// A struct representing a Hardware Security Module (HSM) library interface using PKCS#11.
///
/// This struct provides a safe wrapper around the PKCS#11 library functions, managing
/// the dynamic loading of the HSM library and providing access to cryptographic operations.
///
/// # Fields
///
/// All fields are PKCS#11 function pointers that correspond to various cryptographic
/// and key management operations. The fields are marked as `pub(crate)` to allow
/// access within the crate while maintaining encapsulation.
///
/// # Examples
///
/// ```no_run
/// use hsm_common::HsmLib;
///
/// let hsm = HsmLib::instantiate("/path/to/hsm/library.so").expect("Failed to load HSM library");
/// ```
///
/// # Safety
///
/// This struct handles unsafe FFI calls to the PKCS#11 library internally. The public
/// interface is designed to be safe to use, but care must be taken when using the
/// raw function pointers directly.
///
/// The library automatically handles initialization and cleanup through the `Drop` trait,
/// ensuring proper finalization of the HSM when the struct is dropped.
///
/// # Methods
///
/// - `instantiate<P>`: Creates a new instance of the HSM library
/// - `initialize`: Initializes the HSM with OS locking capabilities
/// - `finalize`: Properly closes the HSM connection
///
/// # Error Handling
///
/// Operations return `PResult<T>`, which is a custom result type for handling
/// HSM-specific errors. Failed operations typically return `PError` variants
/// with descriptive error messages.
#[expect(dead_code)]
#[expect(non_snake_case)]
pub struct HsmLib {
    _library: Library,
    pub(crate) C_Initialize: CK_C_Initialize,
    pub(crate) C_Finalize: CK_C_Finalize,

    pub(crate) C_OpenSession: CK_C_OpenSession,
    pub(crate) C_CloseSession: CK_C_CloseSession,

    pub(crate) C_DestroyObject: CK_C_DestroyObject,

    pub(crate) C_Decrypt: CK_C_Decrypt,
    pub(crate) C_DecryptInit: CK_C_DecryptInit,
    pub(crate) C_DecryptUpdate: CK_C_DecryptUpdate,
    pub(crate) C_DecryptFinal: CK_C_DecryptFinal,

    pub(crate) C_Encrypt: CK_C_Encrypt,
    pub(crate) C_EncryptInit: CK_C_EncryptInit,
    pub(crate) C_EncryptUpdate: CK_C_EncryptUpdate,
    pub(crate) C_EncryptFinal: CK_C_EncryptFinal,

    pub(crate) C_FindObjectsInit: CK_C_FindObjectsInit,
    pub(crate) C_FindObjects: CK_C_FindObjects,
    pub(crate) C_FindObjectsFinal: CK_C_FindObjectsFinal,

    pub(crate) C_GenerateKey: CK_C_GenerateKey,
    pub(crate) C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub(crate) C_GenerateRandom: CK_C_GenerateRandom,
    pub(crate) C_SeedRandom: CK_C_SeedRandom,

    pub(crate) C_GetAttributeValue: CK_C_GetAttributeValue,
    pub(crate) C_SetAttributeValue: CK_C_SetAttributeValue,

    pub(crate) C_GetInfo: CK_C_GetInfo,
    pub(crate) C_GetMechanismList: CK_C_GetMechanismList,
    pub(crate) C_GetMechanismInfo: CK_C_GetMechanismInfo,

    pub(crate) C_Login: CK_C_Login,
    pub(crate) C_Logout: CK_C_Logout,

    pub(crate) C_WrapKey: CK_C_WrapKey,
    pub(crate) C_UnwrapKey: CK_C_UnwrapKey,

    pub(crate) C_SignInit: CK_C_SignInit,
    pub(crate) C_Sign: CK_C_Sign,

    /// Classic (v2.01+) signature verification, needed by any signing mechanism
    /// exposed through `Session::verify` (e.g. `EdDSA` — OASIS Cryptoki v3.0 §2.3.9).
    pub(crate) C_VerifyInit: CK_C_VerifyInit,
    pub(crate) C_Verify: CK_C_Verify,

    /// Classic (v2.01+) key derivation, used for `CKM_HKDF_DERIVE` (OASIS Cryptoki
    /// v3.0 §2.3.11) as well as any future non-v3-only derive mechanism.
    pub(crate) C_DeriveKey: CK_C_DeriveKey,

    /// PKCS#11 v3.0 interfaces discovery entry point (OASIS Cryptoki v3.0 §3.2).
    ///
    /// This is `None` for any v2.40-only library, which is the
    /// normal, fully-supported case: resolution is best-effort and never fails
    /// `instantiate`. See `supports_pkcs11_v3_interfaces` and
    /// `list_pkcs11_v3_interfaces` (additive capability probe, issue #1153).
    pub(crate) C_GetInterfaceList: pkcs11_v3::CkCGetInterfaceList,

    // --- PKCS#11 v3.0 function pointers (all additive/best-effort, see below) ---
    //
    // Every field in this group is resolved the same way as `C_GetInterfaceList`:
    // `library.get(...).ok()`, so a missing symbol on a v2.40-only library never
    // fails `instantiate`. None of these are used by any existing v2.x code path;
    // they are exposed only through the capability-gated helpers below and the
    // session-layer v3.0 mechanisms that consume them.
    /// OASIS Cryptoki v3.0 §5.6 — role-based login (added in v3.0).
    pub(crate) C_LoginUser: CK_C_LoginUser,
    /// OASIS Cryptoki v3.0 §5.6 — cancel an active operation on a session.
    pub(crate) C_SessionCancel: CK_C_SessionCancel,

    /// OASIS Cryptoki v3.0 §5.20 — message-based encryption (e.g. AEAD such as
    /// AES-GCM/AES-CCM used as a "message" operation instead of the classic
    /// `C_Encrypt`/`C_EncryptUpdate` flow).
    pub(crate) C_MessageEncryptInit: CK_C_MessageEncryptInit,
    pub(crate) C_EncryptMessage: CK_C_EncryptMessage,
    pub(crate) C_EncryptMessageBegin: CK_C_EncryptMessageBegin,
    pub(crate) C_EncryptMessageNext: CK_C_EncryptMessageNext,
    pub(crate) C_MessageEncryptFinal: CK_C_MessageEncryptFinal,

    /// OASIS Cryptoki v3.0 §5.21 — message-based decryption, mirroring the
    /// message-based encryption family above.
    pub(crate) C_MessageDecryptInit: CK_C_MessageDecryptInit,
    pub(crate) C_DecryptMessage: CK_C_DecryptMessage,
    pub(crate) C_DecryptMessageBegin: CK_C_DecryptMessageBegin,
    pub(crate) C_DecryptMessageNext: CK_C_DecryptMessageNext,
    pub(crate) C_MessageDecryptFinal: CK_C_MessageDecryptFinal,

    /// OASIS Cryptoki v3.0 §5.22 — message-based signing.
    pub(crate) C_MessageSignInit: CK_C_MessageSignInit,
    pub(crate) C_SignMessage: CK_C_SignMessage,
    pub(crate) C_SignMessageBegin: CK_C_SignMessageBegin,
    pub(crate) C_SignMessageNext: CK_C_SignMessageNext,
    pub(crate) C_MessageSignFinal: CK_C_MessageSignFinal,

    /// OASIS Cryptoki v3.0 §5.23 — message-based signature verification.
    pub(crate) C_MessageVerifyInit: CK_C_MessageVerifyInit,
    pub(crate) C_VerifyMessage: CK_C_VerifyMessage,
    pub(crate) C_VerifyMessageBegin: CK_C_VerifyMessageBegin,
    pub(crate) C_VerifyMessageNext: CK_C_VerifyMessageNext,
    pub(crate) C_MessageVerifyFinal: CK_C_MessageVerifyFinal,

    /// PKCS#11 v3.0 interfaces discovery entry point (OASIS Cryptoki v3.0 §3.2).
    ///
    /// This is `None` for any v2.40-only library, which is the
    /// normal, fully-supported case: resolution is best-effort and never fails
    /// `instantiate`. See `supports_pkcs11_v3_interfaces` and
    /// `list_pkcs11_v3_interfaces` (additive capability probe, issue #1153).
    pub(crate) C_GetInterfaceList: pkcs11_v3::CkCGetInterfaceList,
}

impl HsmLib {
    pub(crate) fn instantiate<P>(path: P) -> HResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        #[expect(unsafe_code)]
        unsafe {
            let library = Library::new(path)?;

            // Resolve the two spec-mandated function-table entry points best-effort.
            // Preferring the v3.0 interface (a superset of the v2.40 one, see
            // `pkcs11_v3`) means Kryoptic-style libraries that only export
            // `C_GetInterfaceList`/`C_GetInterface`/`C_GetFunctionList` — no individual
            // `C_XXX` symbols — still resolve every function below. Libraries that
            // additionally export individual symbols (SoftHSM2, Utimaco, Proteccio,
            // Crypt2Pay) are entirely unaffected: per-symbol `dlsym` is tried first in
            // the `resolve!`/`resolve_v3_only!` macros and always wins when available,
            // so existing production behavior is unchanged.
            let v3_function_list = pkcs11_v3::get_v3_function_list(&library);
            let v2_function_list = if v3_function_list.is_some() {
                None
            } else {
                pkcs11_v3::get_v2_function_list(&library)
            };

            // Resolves a function present in both the v2.40 and v3.0 function-list
            // structs: per-symbol `dlsym` first (unchanged historical behavior), then
            // the v3.0 function list, then the v2.40 one.
            macro_rules! resolve {
                ($name:literal, $field:ident) => {
                    library
                        .get($name)
                        .ok()
                        .map(|s| *s)
                        .or_else(|| v3_function_list.and_then(|f| f.$field))
                        .or_else(|| v2_function_list.and_then(|f| f.$field))
                };
            }
            // Resolves a v3.0-only function (absent from `CK_FUNCTION_LIST`): per-symbol
            // `dlsym` first, then the v3.0 function list only.
            macro_rules! resolve_v3_only {
                ($name:literal, $field:ident) => {
                    library
                        .get($name)
                        .ok()
                        .map(|s| *s)
                        .or_else(|| v3_function_list.and_then(|f| f.$field))
                };
            }

            let hsm_lib = Self {
                C_Initialize: resolve!(b"C_Initialize", C_Initialize),
                C_Finalize: resolve!(b"C_Finalize", C_Finalize),
                C_OpenSession: resolve!(b"C_OpenSession", C_OpenSession),
                C_CloseSession: resolve!(b"C_CloseSession", C_CloseSession),
                C_Encrypt: resolve!(b"C_Encrypt", C_Encrypt),
                C_EncryptInit: resolve!(b"C_EncryptInit", C_EncryptInit),
                C_EncryptUpdate: resolve!(b"C_EncryptUpdate", C_EncryptUpdate),
                C_EncryptFinal: resolve!(b"C_EncryptFinal", C_EncryptFinal),
                C_Decrypt: resolve!(b"C_Decrypt", C_Decrypt),
                C_DecryptInit: resolve!(b"C_DecryptInit", C_DecryptInit),
                C_DecryptUpdate: resolve!(b"C_DecryptUpdate", C_DecryptUpdate),
                C_DecryptFinal: resolve!(b"C_DecryptFinal", C_DecryptFinal),
                C_DestroyObject: resolve!(b"C_DestroyObject", C_DestroyObject),
                C_FindObjectsInit: resolve!(b"C_FindObjectsInit", C_FindObjectsInit),
                C_FindObjects: resolve!(b"C_FindObjects", C_FindObjects),
                C_FindObjectsFinal: resolve!(b"C_FindObjectsFinal", C_FindObjectsFinal),
                C_GenerateKey: resolve!(b"C_GenerateKey", C_GenerateKey),
                C_GenerateKeyPair: resolve!(b"C_GenerateKeyPair", C_GenerateKeyPair),
                C_GenerateRandom: resolve!(b"C_GenerateRandom", C_GenerateRandom),
                C_SeedRandom: resolve!(b"C_SeedRandom", C_SeedRandom),
                C_GetAttributeValue: resolve!(b"C_GetAttributeValue", C_GetAttributeValue),
                C_SetAttributeValue: resolve!(b"C_SetAttributeValue", C_SetAttributeValue),
                C_GetInfo: resolve!(b"C_GetInfo", C_GetInfo),
                C_GetMechanismList: resolve!(b"C_GetMechanismList", C_GetMechanismList),
                C_GetMechanismInfo: resolve!(b"C_GetMechanismInfo", C_GetMechanismInfo),
                C_Login: resolve!(b"C_Login", C_Login),
                C_Logout: resolve!(b"C_Logout", C_Logout),
                C_WrapKey: resolve!(b"C_WrapKey", C_WrapKey),
                C_UnwrapKey: resolve!(b"C_UnwrapKey", C_UnwrapKey),
                C_SignInit: resolve!(b"C_SignInit", C_SignInit),
                C_Sign: resolve!(b"C_Sign", C_Sign),
                C_VerifyInit: resolve!(b"C_VerifyInit", C_VerifyInit),
                C_Verify: resolve!(b"C_Verify", C_Verify),
                C_DeriveKey: resolve!(b"C_DeriveKey", C_DeriveKey),
                // PKCS#11 v3.0 capability probe: resolved best-effort. Missing on any
                // v2.40-only library (the common case), which must never fail loading.
                C_GetInterfaceList: resolve_v3_only!(b"C_GetInterfaceList", C_GetInterfaceList),
                // PKCS#11 v3.0 function pointers: all resolved best-effort, so a
                // v2.40-only library that lacks any of these symbols still loads
                // successfully — only the corresponding v3.0 capability/mechanism is
                // reported as unavailable (see the `supports_*` helpers below).
                C_LoginUser: resolve_v3_only!(b"C_LoginUser", C_LoginUser),
                C_SessionCancel: resolve_v3_only!(b"C_SessionCancel", C_SessionCancel),
                C_MessageEncryptInit: resolve_v3_only!(
                    b"C_MessageEncryptInit",
                    C_MessageEncryptInit
                ),
                C_EncryptMessage: resolve_v3_only!(b"C_EncryptMessage", C_EncryptMessage),
                C_EncryptMessageBegin: resolve_v3_only!(
                    b"C_EncryptMessageBegin",
                    C_EncryptMessageBegin
                ),
                C_EncryptMessageNext: resolve_v3_only!(
                    b"C_EncryptMessageNext",
                    C_EncryptMessageNext
                ),
                C_MessageEncryptFinal: resolve_v3_only!(
                    b"C_MessageEncryptFinal",
                    C_MessageEncryptFinal
                ),
                C_MessageDecryptInit: resolve_v3_only!(
                    b"C_MessageDecryptInit",
                    C_MessageDecryptInit
                ),
                C_DecryptMessage: resolve_v3_only!(b"C_DecryptMessage", C_DecryptMessage),
                C_DecryptMessageBegin: resolve_v3_only!(
                    b"C_DecryptMessageBegin",
                    C_DecryptMessageBegin
                ),
                C_DecryptMessageNext: resolve_v3_only!(
                    b"C_DecryptMessageNext",
                    C_DecryptMessageNext
                ),
                C_MessageDecryptFinal: resolve_v3_only!(
                    b"C_MessageDecryptFinal",
                    C_MessageDecryptFinal
                ),
                C_MessageSignInit: resolve_v3_only!(b"C_MessageSignInit", C_MessageSignInit),
                C_SignMessage: resolve_v3_only!(b"C_SignMessage", C_SignMessage),
                C_SignMessageBegin: resolve_v3_only!(b"C_SignMessageBegin", C_SignMessageBegin),
                C_SignMessageNext: resolve_v3_only!(b"C_SignMessageNext", C_SignMessageNext),
                C_MessageSignFinal: resolve_v3_only!(b"C_MessageSignFinal", C_MessageSignFinal),
                C_MessageVerifyInit: resolve_v3_only!(b"C_MessageVerifyInit", C_MessageVerifyInit),
                C_VerifyMessage: resolve_v3_only!(b"C_VerifyMessage", C_VerifyMessage),
                C_VerifyMessageBegin: resolve_v3_only!(
                    b"C_VerifyMessageBegin",
                    C_VerifyMessageBegin
                ),
                C_VerifyMessageNext: resolve_v3_only!(b"C_VerifyMessageNext", C_VerifyMessageNext),
                C_MessageVerifyFinal: resolve_v3_only!(
                    b"C_MessageVerifyFinal",
                    C_MessageVerifyFinal
                ),
                // PKCS#11 v3.0 capability probe: resolved best-effort. Missing on any
                // v2.40-only library (the common case), which must never fail loading.
                C_GetInterfaceList: library.get(b"C_GetInterfaceList").ok().map(|s| *s),
                // we need to keep the library alive
                _library: library,
            };

            // At least the core v2.40 functions must have resolved through one of the
            // three paths above (per-symbol, v3.0 function list, v2.40 function list);
            // otherwise this is not a usable PKCS#11 library at all.
            if hsm_lib.C_Initialize.is_none()
                || hsm_lib.C_OpenSession.is_none()
                || hsm_lib.C_Sign.is_none()
            {
                return Err(crate::HError::Default(
                    "The loaded library does not expose a usable PKCS#11 function table: none \
                     of per-symbol exports, C_GetInterfaceList/C_GetInterface, or \
                     C_GetFunctionList resolved the mandatory Cryptoki functions"
                        .to_owned(),
                ));
            }

            Self::initialize(&hsm_lib)?;
            Ok(hsm_lib)
        }
    }

    /// Initialize the PKCS#11 library.
    ///
    /// This method calls `C_Initialize` with OS locking support enabled.
    /// Note: This will fail if the library is already initialized.
    pub fn initialize(hsm_lib: &Self) -> HResult<()> {
        let p_init_args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        #[expect(unsafe_code)]
        let rv = match hsm_lib.C_Initialize {
            Some(func) => unsafe {
                func(
                    (&raw const p_init_args)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                )
            },
            None => {
                return Err(crate::HError::Default(
                    "C_Initialize not available on library".to_owned(),
                ));
            }
        };
        if rv == CKR_CRYPTOKI_ALREADY_INITIALIZED {
            // The library was already initialized by a previous instance using the same .so
            // (e.g. two [[hsm_instances]] entries with the same softhsm2 model). This is
            // harmless — all slots remain accessible.
            warn!("HSM library already initialized (CKR_CRYPTOKI_ALREADY_INITIALIZED); continuing");
        } else if rv != CKR_OK {
            return Err(crate::HError::Default(format!(
                "Failed initializing the HSM. Return code: {rv}"
            )));
        }
        Ok(())
    }

    /// Finalize the PKCS#11 library.
    ///
    /// This method calls `C_Finalize` to properly close the PKCS#11 library connection.
    pub fn finalize(&self) -> HResult<()> {
        hsm_call!(
            self,
            "Failed to finalize the HSM",
            C_Finalize,
            ptr::null_mut()
        );
        Ok(())
    }

    /// Get PKCS#11 info as raw bytes.
    ///
    /// This method calls `C_GetInfo` and returns the raw `CK_INFO` structure
    /// serialized as bytes for KMIP PKCS#11 operations.
    pub fn get_info(&self) -> HResult<Vec<u8>> {
        use pkcs11_sys::CK_INFO;
        let mut info = CK_INFO::default();
        hsm_call!(self, "Failed getting HSM info", C_GetInfo, &raw mut info);

        // Serialize CK_INFO struct to bytes
        // SAFETY: CK_INFO is a repr(C) struct with fixed layout
        #[expect(unsafe_code)]
        unsafe {
            let bytes = std::slice::from_raw_parts(
                (&raw const info).cast::<u8>(),
                std::mem::size_of::<CK_INFO>(),
            );
            Ok(bytes.to_vec())
        }
    }

    /// Get PKCS#11 info as Info struct.
    ///
    /// This method calls `C_GetInfo` and returns the `Info` structure
    /// with parsed library information.
    pub fn get_info_struct(&self) -> HResult<Info> {
        use pkcs11_sys::CK_INFO;
        let mut info = CK_INFO::default();
        hsm_call!(self, "Failed getting HSM info", C_GetInfo, &raw mut info);
        Ok(info.into())
    }

    /// Returns `true` if the loaded PKCS#11 library exposes the v3.0 interfaces
    /// discovery entry point (`C_GetInterfaceList`).
    ///
    /// This is a pure capability probe: it does not change how any Cryptoki function
    /// is resolved or invoked. v2.40-only libraries (e.g. `SoftHSM2`) simply do not
    /// export this symbol and are reported as `false`, which is expected and fully
    /// supported. See issue #1153 ("PKCS#11 v3.0: scope decision & FFI foundation").
    #[must_use]
    pub fn supports_pkcs11_v3_interfaces(&self) -> bool {
        self.C_GetInterfaceList.is_some()
    }

    /// Lists the PKCS#11 v3.0 interfaces exposed by the loaded library, if any.
    ///
    /// Returns `Ok(None)` when the library does not export `C_GetInterfaceList`
    /// (i.e. a v2.40-only library — the common case today). Returns `Ok(Some(list))`,
    /// possibly empty, when the library does support v3.0 interface discovery.
    ///
    /// This is an additive, read-only capability probe: it never affects the
    /// per-symbol function resolution used everywhere else in this crate, so
    /// existing v2.x HSM integrations are entirely unaffected (see issue #1153).
    pub fn list_pkcs11_v3_interfaces(&self) -> HResult<Option<Vec<InterfaceDescriptor>>> {
        let Some(get_interface_list) = self.C_GetInterfaceList else {
            return Ok(None);
        };

        // First call: pass a NULL buffer to obtain the interface count, mirroring the
        // existing two-call convention already used for `C_GetMechanismList` elsewhere
        // in this crate.
        let mut count: pkcs11_sys::CK_ULONG = 0;
        #[expect(unsafe_code)]
        // SAFETY: `get_interface_list` was resolved from the loaded library and matches
        // the documented `C_GetInterfaceList` signature. Passing a null buffer pointer
        // with a valid `&mut count` out-parameter is the standard PKCS#11 two-call
        // idiom for querying the required buffer size.
        let rv = unsafe { get_interface_list(ptr::null_mut(), &raw mut count) };
        if rv != CKR_OK {
            return Err(crate::HError::Default(format!(
                "Failed to query the PKCS#11 v3.0 interface count. Return code: {rv}"
            )));
        }
        if count == 0 {
            return Ok(Some(Vec::new()));
        }
        // Defense-in-depth against a misbehaving/malicious native library reporting an
        // absurd interface count: no conformant PKCS#11 v3.0 library exposes more than a
        // handful of interfaces (e.g. "PKCS 11", vendor extensions), so cap well above any
        // plausible legitimate value before allocating (threat-model finding T-101).
        if count > MAX_PLAUSIBLE_PKCS11_V3_INTERFACES {
            return Err(crate::HError::Default(format!(
                "PKCS#11 v3.0 interface count {count} exceeds the plausible maximum of \
                 {MAX_PLAUSIBLE_PKCS11_V3_INTERFACES}; refusing to allocate (possible \
                 misbehaving library)"
            )));
        }
        let count_usize = usize::try_from(count).map_err(|e| {
            crate::HError::Default(format!(
                "PKCS#11 v3.0 interface count {count} does not fit in `usize`: {e}"
            ))
        })?;

        let mut buffer = vec![CkInterface::default(); count_usize];
        #[expect(unsafe_code)]
        // SAFETY: `buffer` was allocated using the exact count returned by the first
        // call, as required by the PKCS#11 v3.0 specification for `C_GetInterfaceList`.
        let rv = unsafe { get_interface_list(buffer.as_mut_ptr(), &raw mut count) };
        if rv != CKR_OK {
            return Err(crate::HError::Default(format!(
                "Failed to retrieve the PKCS#11 v3.0 interface list. Return code: {rv}"
            )));
        }
        // Defensive clamp: some libraries may report a smaller final count than the
        // buffer they were given (never larger, per spec — but never trust native
        // input for a slice length).
        let final_len = usize::try_from(count)
            .unwrap_or(count_usize)
            .min(buffer.len());
        buffer.truncate(final_len);
        Ok(Some(pkcs11_v3::parse_interfaces(&buffer)))
    }

    /// Returns `true` if the loaded PKCS#11 library exposes the v3.0 interfaces
    /// discovery entry point (`C_GetInterfaceList`).
    ///
    /// This is a pure capability probe: it does not change how any Cryptoki function
    /// is resolved or invoked. v2.40-only libraries (e.g. `SoftHSM2`) simply do not
    /// export this symbol and are reported as `false`, which is expected and fully
    /// supported. See issue #1153 ("PKCS#11 v3.0: scope decision & FFI foundation").
    #[must_use]
    pub fn supports_pkcs11_v3_interfaces(&self) -> bool {
        self.C_GetInterfaceList.is_some()
    }

    /// Lists the PKCS#11 v3.0 interfaces exposed by the loaded library, if any.
    ///
    /// Returns `Ok(None)` when the library does not export `C_GetInterfaceList`
    /// (i.e. a v2.40-only library — the common case today). Returns `Ok(Some(list))`,
    /// possibly empty, when the library does support v3.0 interface discovery.
    ///
    /// This is an additive, read-only capability probe: it never affects the
    /// per-symbol function resolution used everywhere else in this crate, so
    /// existing v2.x HSM integrations are entirely unaffected (see issue #1153).
    pub fn list_pkcs11_v3_interfaces(&self) -> HResult<Option<Vec<InterfaceDescriptor>>> {
        let Some(get_interface_list) = self.C_GetInterfaceList else {
            return Ok(None);
        };

        // First call: pass a NULL buffer to obtain the interface count, mirroring the
        // existing two-call convention already used for `C_GetMechanismList` elsewhere
        // in this crate.
        let mut count: pkcs11_sys::CK_ULONG = 0;
        #[expect(unsafe_code)]
        // SAFETY: `get_interface_list` was resolved from the loaded library and matches
        // the documented `C_GetInterfaceList` signature. Passing a null buffer pointer
        // with a valid `&mut count` out-parameter is the standard PKCS#11 two-call
        // idiom for querying the required buffer size.
        let rv = unsafe { get_interface_list(ptr::null_mut(), &raw mut count) };
        if rv != CKR_OK {
            return Err(crate::HError::Default(format!(
                "Failed to query the PKCS#11 v3.0 interface count. Return code: {rv}"
            )));
        }
        if count == 0 {
            return Ok(Some(Vec::new()));
        }
        // Defense-in-depth against a misbehaving/malicious native library reporting an
        // absurd interface count: no conformant PKCS#11 v3.0 library exposes more than a
        // handful of interfaces (e.g. "PKCS 11", vendor extensions), so cap well above any
        // plausible legitimate value before allocating (threat-model finding T-101).
        if count > MAX_PLAUSIBLE_PKCS11_V3_INTERFACES {
            return Err(crate::HError::Default(format!(
                "PKCS#11 v3.0 interface count {count} exceeds the plausible maximum of \
                 {MAX_PLAUSIBLE_PKCS11_V3_INTERFACES}; refusing to allocate (possible \
                 misbehaving library)"
            )));
        }
        let count_usize = usize::try_from(count).map_err(|e| {
            crate::HError::Default(format!(
                "PKCS#11 v3.0 interface count {count} does not fit in `usize`: {e}"
            ))
        })?;

        let mut buffer = vec![CkInterface::default(); count_usize];
        #[expect(unsafe_code)]
        // SAFETY: `buffer` was allocated using the exact count returned by the first
        // call, as required by the PKCS#11 v3.0 specification for `C_GetInterfaceList`.
        let rv = unsafe { get_interface_list(buffer.as_mut_ptr(), &raw mut count) };
        if rv != CKR_OK {
            return Err(crate::HError::Default(format!(
                "Failed to retrieve the PKCS#11 v3.0 interface list. Return code: {rv}"
            )));
        }
        // Defensive clamp: some libraries may report a smaller final count than the
        // buffer they were given (never larger, per spec — but never trust native
        // input for a slice length).
        let final_len = usize::try_from(count)
            .unwrap_or(count_usize)
            .min(buffer.len());
        buffer.truncate(final_len);
        Ok(Some(pkcs11_v3::parse_interfaces(&buffer)))
    }

    /// Returns `true` if the loaded library exposes `C_LoginUser` (OASIS Cryptoki
    /// v3.0 §5.6 role-based login). `false` on any v2.40-only library.
    #[must_use]
    pub fn supports_login_user(&self) -> bool {
        self.C_LoginUser.is_some()
    }

    /// Returns `true` if the loaded library exposes `C_SessionCancel` (OASIS
    /// Cryptoki v3.0 §5.6). `false` on any v2.40-only library.
    #[must_use]
    pub fn supports_session_cancel(&self) -> bool {
        self.C_SessionCancel.is_some()
    }

    /// Returns `true` if the loaded library exposes the full message-based
    /// encryption function family (OASIS Cryptoki v3.0 §5.20), used for AEAD
    /// mechanisms (e.g. AES-GCM/AES-CCM) operated as "message" operations rather
    /// than through the classic `C_Encrypt`/`C_EncryptUpdate` flow.
    ///
    /// This is an all-or-nothing check: a conformant v3.0 library exposes every
    /// function in the family together, so a partial resolution (which would only
    /// happen with a non-conformant library) is conservatively reported as
    /// unsupported.
    #[must_use]
    pub fn supports_message_encrypt(&self) -> bool {
        self.C_MessageEncryptInit.is_some()
            && self.C_EncryptMessage.is_some()
            && self.C_EncryptMessageBegin.is_some()
            && self.C_EncryptMessageNext.is_some()
            && self.C_MessageEncryptFinal.is_some()
    }

    /// Returns `true` if the loaded library exposes the full message-based
    /// decryption function family (OASIS Cryptoki v3.0 §5.21). See
    /// `supports_message_encrypt` for the all-or-nothing rationale.
    #[must_use]
    pub fn supports_message_decrypt(&self) -> bool {
        self.C_MessageDecryptInit.is_some()
            && self.C_DecryptMessage.is_some()
            && self.C_DecryptMessageBegin.is_some()
            && self.C_DecryptMessageNext.is_some()
            && self.C_MessageDecryptFinal.is_some()
    }

    /// Returns `true` if the loaded library exposes the full message-based
    /// signing function family (OASIS Cryptoki v3.0 §5.22). See
    /// `supports_message_encrypt` for the all-or-nothing rationale.
    #[must_use]
    pub fn supports_message_sign(&self) -> bool {
        self.C_MessageSignInit.is_some()
            && self.C_SignMessage.is_some()
            && self.C_SignMessageBegin.is_some()
            && self.C_SignMessageNext.is_some()
            && self.C_MessageSignFinal.is_some()
    }

    /// Returns `true` if the loaded library exposes the full message-based
    /// signature verification function family (OASIS Cryptoki v3.0 §5.23). See
    /// `supports_message_encrypt` for the all-or-nothing rationale.
    #[must_use]
    pub fn supports_message_verify(&self) -> bool {
        self.C_MessageVerifyInit.is_some()
            && self.C_VerifyMessage.is_some()
            && self.C_VerifyMessageBegin.is_some()
            && self.C_VerifyMessageNext.is_some()
            && self.C_MessageVerifyFinal.is_some()
    }
}

pub struct Info {
    pub cryptoki_version: (u8, u8),
    pub manufacturer_id: String,
    pub flags: u64,
    pub library_description: String,
    pub library_version: (u8, u8),
}

impl From<pkcs11_sys::CK_INFO> for Info {
    fn from(info: pkcs11_sys::CK_INFO) -> Self {
        use std::ffi::CStr;
        #[cfg(target_os = "windows")]
        let flags = u64::from(info.flags);
        #[cfg(not(target_os = "windows"))]
        let flags = info.flags;
        Self {
            cryptoki_version: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
            manufacturer_id: CStr::from_bytes_until_nul(&info.manufacturerID)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            flags,
            library_description: CStr::from_bytes_until_nul(&info.libraryDescription)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            library_version: (info.libraryVersion.major, info.libraryVersion.minor),
        }
    }
}

impl std::fmt::Display for Info {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cryptoki Version: {}.{}\nManufacturer ID: {}\nFlags: {}\nLibrary Description: \
             {}\nLibrary Version: {}.{}",
            self.cryptoki_version.0,
            self.cryptoki_version.1,
            self.manufacturer_id,
            self.flags,
            self.library_description,
            self.library_version.0,
            self.library_version.1
        )
    }
}

impl Drop for HsmLib {
    fn drop(&mut self) {
        drop(self.finalize());
    }
}

#[cfg(test)]
mod function_table_fallback_tests {
    use std::{
        path::PathBuf,
        process::Command,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    use super::HsmLib;
    use crate::{HError, HResult};

    /// Monotonic counter giving each `compile_minimal_pkcs11_shim()` invocation a
    /// unique output filename. Required because this module now has several
    /// `#[test]` functions calling the helper concurrently (the default `cargo
    /// test` runner parallelises tests within a binary): a shared, fixed output
    /// path let one test's (re)compilation truncate/replace the file out from
    /// under another test's concurrent `dlopen`, causing sporadic "no such file"
    /// failures.
    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    /// Serializes invocations of the C compiler across the concurrently-running
    /// tests in this module. Unlike GCC/Clang (`-o <unique>.{so,dylib}`, no
    /// leftover intermediate file), MSVC's `cl.exe` does not honor `-o` as an
    /// object-output path (only accepts it as a deprecated legacy alias — see the
    /// `D9035` compiler warning) and always writes an intermediate
    /// `minimal_pkcs11.obj` at a fixed location relative to the current
    /// directory, regardless of the requested (unique) `.dll` output path.
    /// Concurrent `cargo test` threads invoking `cl.exe` at the same time
    /// therefore race on that single shared `.obj` file (`C1083: Cannot open
    /// compiler generated file ... Permission denied`, then a
    /// corrupted/partially-linked `.dll` causing a later access violation on
    /// load) — observed only on Windows CI. Serializing the compiler invocation
    /// itself (not just the final output filename) avoids the race on every
    /// platform, at the cost of a little test time.
    static COMPILE_LOCK: Mutex<()> = Mutex::new(());

    /// Returns the current Rust host target triple (e.g.
    /// `aarch64-apple-darwin`), needed because `cc::Build` requires `TARGET`/`HOST`
    /// to be set (normally supplied by Cargo to build scripts, but absent in a plain
    /// `#[test]` context).
    fn host_target_triple() -> HResult<String> {
        let output = Command::new("rustc")
            .arg("-vV")
            .output()
            .map_err(|e| HError::Default(format!("failed to invoke rustc: {e}")))?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .map(str::to_owned)
            .ok_or_else(|| {
                HError::Default("rustc -vV output did not contain a \"host: \" line".to_owned())
            })
    }

    /// Compiles `tests/fixtures/minimal_pkcs11.c` — a strictly spec-conformant PKCS#11
    /// v3.0 shim that exports *only* `C_GetFunctionList`/`C_GetInterface` (no
    /// individual `C_XXX` symbols) — into a shared library, mirroring how Kryoptic
    /// and other strictly conformant libraries behave. Returns an error with a
    /// descriptive message on any compiler failure so a broken fixture never
    /// silently skips the regression test below.
    fn compile_minimal_pkcs11_shim() -> HResult<PathBuf> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let source = PathBuf::from(manifest_dir).join("tests/fixtures/minimal_pkcs11.c");
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| {
            std::env::temp_dir()
                .join("cosmian_kms_base_hsm_test_fixtures")
                .to_string_lossy()
                .into_owned()
        }));
        std::fs::create_dir_all(&out_dir).map_err(|e| {
            HError::Default(format!("failed to create test fixture output dir: {e}"))
        })?;

        let extension = if cfg!(target_os = "windows") {
            "dll"
        } else if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        };
        let output = out_dir.join(format!(
            "minimal_pkcs11_{}_{}.{extension}",
            std::process::id(),
            NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));

        // `cc::Build` targets static libs/object files, not shared libraries, so the
        // shared-library flag is invoked manually via the resolved compiler. `target`
        // and `host` must be set explicitly since we are not running inside a Cargo
        // build script (where Cargo would set the `TARGET`/`HOST` env vars for us).
        let triple = host_target_triple()?;
        let compiler = cc::Build::new()
            .opt_level(0)
            .target(&triple)
            .host(&triple)
            .cargo_metadata(false) // this is a plain test, not a build script
            .get_compiler();
        let mut cmd = Command::new(compiler.path());
        for (key, value) in compiler.env() {
            cmd.env(key, value);
        }
        cmd.args(compiler.args());
        if !cfg!(target_os = "windows") {
            // Silence the intentional generic-function-pointer-cast warning below:
            // this is a throwaway test fixture standing in for a real vendor PKCS#11
            // library, not shipped code subject to the workspace's zero-warnings rule.
            cmd.arg("-w");
        }
        if cfg!(target_os = "macos") {
            cmd.arg("-dynamiclib");
        } else if cfg!(target_os = "windows") {
            cmd.arg("/LD");
        } else {
            cmd.arg("-shared");
        }
        if !cfg!(target_os = "windows") {
            cmd.arg("-fPIC");
        }
        cmd.arg(&source);
        cmd.arg("-o").arg(&output);

        // See `COMPILE_LOCK`'s doc comment: on Windows, `cl.exe` writes a
        // fixed-name intermediate `.obj` shared by every concurrent invocation,
        // so the compiler must be invoked one test at a time. `PoisonError` is
        // ignored (`unwrap_or_else`) so a prior test panicking while holding the
        // lock cannot spuriously fail every subsequent test in this module.
        let _guard = COMPILE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = cmd.status().map_err(|e| {
            HError::Default(format!(
                "failed to invoke the C compiler for the test fixture: {e}"
            ))
        })?;
        if !status.success() {
            return Err(HError::Default(format!(
                "failed to compile the minimal PKCS#11 test fixture {source:?}: compiler exited \
                 with {status}"
            )));
        }
        Ok(output)
    }

    /// Regression test for the `C_GetFunctionList`/`C_GetInterface` fallback path
    /// (PKCS#11 v3.1 §5.4.4/§5.4.6): a library exporting *only* the three
    /// function-table entry points must still load and expose a working v3.0
    /// interface, exactly as validated manually against Kryoptic 1.5.2.
    #[test]
    fn function_table_only_library_loads_via_fallback() -> HResult<()> {
        let path = compile_minimal_pkcs11_shim()?;
        let hsm_lib = HsmLib::instantiate(&path)?;

        if !hsm_lib.supports_pkcs11_v3_interfaces() {
            return Err(HError::Default(
                "the fallback-resolved library must report v3.0 interface support".to_owned(),
            ));
        }
        let Some(interfaces) = hsm_lib.list_pkcs11_v3_interfaces()? else {
            return Err(HError::Default(
                "a v3.0-capable library must report at least one interface".to_owned(),
            ));
        };
        if !interfaces.iter().any(|i| i.name == "PKCS 11") {
            return Err(HError::Default(format!(
                "expected a \"PKCS 11\" interface entry, got: {interfaces:?}"
            )));
        }
        Ok(())
    }

    /// Builds a `Session` directly against the minimal fixture library, bypassing
    /// `SlotManager` (which the fixture does not implement enough of `C_GetSlotList`
    /// et al. to support) — sufficient for exercising `Session` methods that only
    /// need an `HsmLib` and an opaque session handle.
    fn test_session(hsm_lib: HsmLib) -> crate::Session {
        crate::Session::new(
            std::sync::Arc::new(hsm_lib),
            1, // opaque session handle; every fixture stub ignores it
            std::sync::Arc::new(crate::ObjectHandlesCache::new()),
            std::sync::Arc::new(std::sync::Mutex::new(None)),
            false,
            crate::hsm_capabilities::HsmCapabilities::default(),
        )
    }

    /// `CKM_EDDSA` (v3.0-only) must be gracefully reported as unsupported —
    /// not silently incorrectly signed — when the loaded library is v2.40-only, per the
    /// additive/non-breaking philosophy established for issue #1153.
    #[test]
    fn eddsa_sign_gracefully_reports_unsupported_mechanism() -> HResult<()> {
        let path = compile_minimal_pkcs11_shim()?;
        let hsm_lib = HsmLib::instantiate(&path)?;
        let session = test_session(hsm_lib);

        let Err(err) = session.sign(1, crate::HsmSigningAlgorithm::Eddsa, b"data") else {
            return Err(HError::Default(
                "signing with CKM_EDDSA on a v2.40-only library must fail".to_owned(),
            ));
        };
        if !err.to_string().contains("112") {
            return Err(HError::Default(format!(
                "expected the CKR_MECHANISM_INVALID (112) return code in the error, got: {err}"
            )));
        }
        Ok(())
    }

    /// Same as above, for `Session::verify`.
    #[test]
    fn eddsa_verify_gracefully_reports_unsupported_mechanism() -> HResult<()> {
        let path = compile_minimal_pkcs11_shim()?;
        let hsm_lib = HsmLib::instantiate(&path)?;
        let session = test_session(hsm_lib);

        let Err(err) = session.verify(1, crate::HsmSigningAlgorithm::Eddsa, b"data", b"sig") else {
            return Err(HError::Default(
                "verifying with CKM_EDDSA on a v2.40-only library must fail".to_owned(),
            ));
        };
        if !err.to_string().contains("does not support mechanism") {
            return Err(HError::Default(format!(
                "expected a clear \"does not support mechanism\" error, got: {err}"
            )));
        }
        Ok(())
    }

    /// A mechanism the fixture library does accept (any classic RSA-family signing
    /// mechanism) must still succeed end-to-end — proving graceful degradation
    /// only rejects genuinely unsupported v3.0-only mechanisms, not everything.
    #[test]
    fn rsa_sign_succeeds_through_classic_mechanism() -> HResult<()> {
        let path = compile_minimal_pkcs11_shim()?;
        let hsm_lib = HsmLib::instantiate(&path)?;
        let session = test_session(hsm_lib);

        session.sign(1, crate::HsmSigningAlgorithm::Sha256WithRsa, b"data")?;
        Ok(())
    }

    /// `CKM_HKDF_DERIVE` (v3.0-only) must be gracefully reported as unsupported on
    /// a v2.40-only library, mirroring the `EdDSA` sign/verify behaviour above.
    #[test]
    fn hkdf_derive_gracefully_reports_unsupported_mechanism() -> HResult<()> {
        let path = compile_minimal_pkcs11_shim()?;
        let hsm_lib = HsmLib::instantiate(&path)?;
        let session = test_session(hsm_lib);

        let Err(err) = session.derive_hkdf_key(
            1,
            pkcs11_sys::CKM_SHA256,
            None,
            b"info",
            32,
            b"derived",
            true,
        ) else {
            return Err(HError::Default(
                "deriving via CKM_HKDF_DERIVE on a v2.40-only library must fail".to_owned(),
            ));
        };
        if !err.to_string().contains("112") {
            return Err(HError::Default(format!(
                "expected the CKR_MECHANISM_INVALID (112) return code in the error, got: {err}"
            )));
        }
        Ok(())
    }

    /// Message-based AEAD (`C_MessageEncryptInit`/... , v3.0-only) must be
    /// proactively gated by the `supports_message_encrypt`/`supports_message_decrypt`
    /// capability checks — not attempted and left to fail deep inside the FFI call —
    /// since the fixture exports no message-based function-table entries at all.
    #[test]
    fn message_aead_gracefully_reports_unsupported_capability() -> HResult<()> {
        let path = compile_minimal_pkcs11_shim()?;
        let hsm_lib = HsmLib::instantiate(&path)?;
        if hsm_lib.supports_message_encrypt() {
            return Err(HError::Default(
                "the minimal fixture must not report message-encrypt support".to_owned(),
            ));
        }
        let session = test_session(hsm_lib);

        let Err(err) = session.encrypt_message_aes_gcm(1, b"aad", b"plaintext") else {
            return Err(HError::Default(
                "message-based AES-GCM encryption must fail on a v2.40-only library".to_owned(),
            ));
        };
        if !err.to_string().to_lowercase().contains("message") {
            return Err(HError::Default(format!(
                "expected an error mentioning the missing message-based functions, got: {err}"
            )));
        }
        Ok(())
    }
}
