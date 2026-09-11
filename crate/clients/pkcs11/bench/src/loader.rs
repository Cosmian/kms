//! Real `dlopen()`-based Cryptoki v3.1 client for the `cosmian_pkcs11` provider.
//!
//! This mirrors exactly how a real PKCS#11 consumer (Oracle TDE, OpenSSH,
//! `VeraCrypt`, ...) drives the module: `dlopen()` the shared library, resolve
//! the standard v3 interface through `C_GetInterface`, and call its function table.

use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FLAGS, CK_FUNCTION_LIST_3_0, CK_INTERFACE_PTR, CK_KEY_TYPE,
    CK_MECHANISM, CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE,
    CK_SLOT_ID, CK_TRUE, CK_ULONG, CK_USER_TYPE, CK_VERSION, CKA_CLASS, CKA_EXTRACTABLE,
    CKA_KEY_TYPE, CKA_LABEL, CKA_SENSITIVE, CKA_VALUE_LEN, CKF_RW_SESSION, CKF_SERIAL_SESSION,
    CKK_AES, CKM_AES_CBC_PAD, CKM_AES_KEY_GEN, CKR_OK, CKU_USER,
};

use crate::error::{BenchError, BenchResult};

/// A 16-byte all-zero IV used for every `CKM_AES_CBC_PAD` call in this benchmark.
///
/// Reusing a fixed IV across calls is intentionally insecure (never do this in
/// production code); it is only acceptable here because this is a throughput/latency
/// micro-benchmark, not a security-sensitive path.
const AES_IV_SIZE: usize = 16;
pub(crate) const SIGN_PROFILE_BUCKETS: usize = 150;
pub(crate) const SIGN_PROFILE_PHASE_NAMES: [&str; 11] = [
    "c-sign-body",
    "session-map-lookup",
    "session-lock-wait",
    "session-callback",
    "private-key-sign",
    "backend-lookup",
    "backend-remote-sign",
    "request-build",
    "runtime-block-on",
    "kms-client-sign",
    "signature-copy",
];

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SignPhaseSnapshot {
    pub(crate) count: u64,
    pub(crate) total_ns: u64,
    pub(crate) max_ns: u64,
    pub(crate) buckets: [u64; SIGN_PROFILE_BUCKETS],
}

impl Default for SignPhaseSnapshot {
    fn default() -> Self {
        Self {
            count: 0,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; SIGN_PROFILE_BUCKETS],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SignProfileSnapshot {
    pub(crate) phases: [SignPhaseSnapshot; SIGN_PROFILE_PHASE_NAMES.len()],
}

impl Default for SignProfileSnapshot {
    fn default() -> Self {
        Self {
            phases: [SignPhaseSnapshot::default(); SIGN_PROFILE_PHASE_NAMES.len()],
        }
    }
}

type ProfileResetFn = unsafe extern "C" fn();
type ProfileSetEnabledFn = unsafe extern "C" fn(bool);
type ProfileSnapshotFn = unsafe extern "C" fn(*mut SignProfileSnapshot) -> CK_RV;

/// Checks a `CK_RV` return code, turning anything other than `CKR_OK` into a
/// [`BenchError::Cryptoki`].
const fn check(op: &'static str, rv: CK_RV) -> BenchResult<()> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(BenchError::Cryptoki { op, rv })
    }
}

/// An owned `dlopen()` handle for the `cosmian_pkcs11` cdylib plus a snapshot of its
/// Cryptoki v3 function table.
pub(crate) struct Pkcs11Lib {
    // Kept alive for the lifetime of the process: dropping it would unmap the
    // library while `functions`' pointers are still callable.
    _library: libloading::Library,
    functions: CK_FUNCTION_LIST_3_0,
    profile_reset: Option<ProfileResetFn>,
    profile_set_enabled: Option<ProfileSetEnabledFn>,
    profile_snapshot: Option<ProfileSnapshotFn>,
}

impl Pkcs11Lib {
    /// Loads the provider library at `path` and resolves its standard PKCS#11 v3
    /// interface via `C_GetInterface`.
    pub(crate) fn load(path: &str) -> BenchResult<Self> {
        // SAFETY: `dlopen()`-ing a shared library runs its static initializers; this
        // is the documented, unavoidable risk of loading native code and is exactly
        // what any real PKCS#11 consumer application does with this provider.
        let library = unsafe { libloading::Library::new(path) }?;

        // SAFETY: `C_GetInterface` is the standard PKCS#11 v3 discovery symbol with
        // this exact ABI. The symbol does not outlive `library`, kept in `self`.
        let get_interface: libloading::Symbol<
            '_,
            unsafe extern "C" fn(
                *mut u8,
                *mut CK_VERSION,
                *mut CK_INTERFACE_PTR,
                CK_FLAGS,
            ) -> CK_RV,
        > = unsafe { library.get(b"C_GetInterface\0") }.map_err(|load_err| {
            BenchError::MissingSymbol(format!("C_GetInterface ({load_err})"))
        })?;

        let mut requested_version = CK_VERSION { major: 3, minor: 1 };
        let mut interface_ptr: CK_INTERFACE_PTR = ptr::null_mut();
        // SAFETY: null interface name requests the provider's standard interface;
        // version and interface pointers are valid writable out-parameters.
        let rv = unsafe {
            get_interface(
                ptr::null_mut(),
                &raw mut requested_version,
                &raw mut interface_ptr,
                0,
            )
        };
        check("C_GetInterface", rv)?;
        if interface_ptr.is_null() {
            return Err(BenchError::MissingSymbol(
                "C_GetInterface returned a null interface".to_owned(),
            ));
        }
        // SAFETY: the interface pointer was validated non-null after CKR_OK; this
        // provider exposes its standard v3 interface as CK_FUNCTION_LIST_3_0.
        let functions_ptr = unsafe {
            (*interface_ptr)
                .pFunctionList
                .cast::<CK_FUNCTION_LIST_3_0>()
        };
        if functions_ptr.is_null() {
            return Err(BenchError::MissingSymbol(
                "C_GetInterface returned a null v3 function list".to_owned(),
            ));
        }
        // SAFETY: `functions_ptr` targets the provider's static v3 table, and the
        // copied table remains usable while `_library` remains loaded.
        let functions = unsafe { *functions_ptr };
        if functions.version.major != 3 || functions.version.minor != 1 {
            return Err(BenchError::Setup(format!(
                "provider returned PKCS#11 {}.{} instead of the requested v3.1 interface",
                functions.version.major, functions.version.minor
            )));
        }
        // These are non-standard, benchmark-only symbols compiled into the provider
        // only when its `benchmarking` feature is enabled.
        let profile_reset = unsafe {
            library
                .get::<ProfileResetFn>(b"cosmian_pkcs11_benchmark_sign_profile_reset\0")
                .ok()
                .map(|symbol| *symbol)
        };
        let profile_snapshot = unsafe {
            library
                .get::<ProfileSnapshotFn>(b"cosmian_pkcs11_benchmark_sign_profile_snapshot\0")
                .ok()
                .map(|symbol| *symbol)
        };
        let profile_set_enabled = unsafe {
            library
                .get::<ProfileSetEnabledFn>(b"cosmian_pkcs11_benchmark_sign_profile_set_enabled\0")
                .ok()
                .map(|symbol| *symbol)
        };

        Ok(Self {
            _library: library,
            functions,
            profile_reset,
            profile_set_enabled,
            profile_snapshot,
        })
    }

    pub(crate) fn reset_sign_profile(&self) -> BenchResult<()> {
        let reset = self.profile_reset.ok_or_else(|| {
            BenchError::MissingSymbol(
                "cosmian_pkcs11_benchmark_sign_profile_reset (build provider with the \
                 benchmarking feature)"
                    .to_owned(),
            )
        })?;
        // SAFETY: the symbol was resolved with the exact exported C ABI and takes no
        // pointers or caller-owned state.
        unsafe { reset() };
        Ok(())
    }

    pub(crate) fn sign_profile_snapshot(&self) -> BenchResult<SignProfileSnapshot> {
        let snapshot_fn = self.profile_snapshot.ok_or_else(|| {
            BenchError::MissingSymbol(
                "cosmian_pkcs11_benchmark_sign_profile_snapshot (build provider with the \
                 benchmarking feature)"
                    .to_owned(),
            )
        })?;
        let mut snapshot = SignProfileSnapshot::default();
        // SAFETY: `snapshot` is correctly aligned, writable, and lives for the
        // duration of the call; the symbol uses the exact matching C ABI.
        check("sign profile snapshot", unsafe {
            snapshot_fn(&raw mut snapshot)
        })?;
        Ok(snapshot)
    }

    pub(crate) fn set_sign_profile_enabled(&self, enabled: bool) -> BenchResult<()> {
        let set_enabled = self.profile_set_enabled.ok_or_else(|| {
            BenchError::MissingSymbol(
                "cosmian_pkcs11_benchmark_sign_profile_set_enabled (build provider with the \
                 benchmarking feature)"
                    .to_owned(),
            )
        })?;
        // SAFETY: the symbol was resolved with the exact exported C ABI and takes a
        // plain boolean value.
        unsafe { set_enabled(enabled) };
        Ok(())
    }
}

/// One Cryptoki session opened against the loaded provider.
///
/// The load sweep now opens **one dedicated session per concurrent worker thread**
/// (see [`crate::load::run_for`]) instead of sharing a single handle across every
/// thread: `crate/clients/pkcs11/module/src/sessions.rs` guards each session with its
/// *own* lock (not one process-wide lock covering every session), so concurrent
/// operations against *different* sessions now run in parallel — mirroring how a
/// well-behaved, high-concurrency PKCS#11 consumer (e.g. a connection-pooled
/// disk-encryption integration) would actually use the provider, and letting this
/// benchmark's concurrency sweep demonstrate that real parallelism instead of
/// measuring artificial single-session contention.
pub(crate) struct Pkcs11Session<'lib> {
    lib: &'lib Pkcs11Lib,
    handle: CK_SESSION_HANDLE,
}

/// `C_Initialize` is a process-wide, one-time Cryptoki call — a second call returns
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` — so it must run exactly once even though
/// [`Pkcs11Session::open`] is now called once per pooled session. All calls happen
/// sequentially on the main thread before any worker thread is spawned (see
/// `main.rs`), so a plain `AtomicBool` (no `Once`) is sufficient: there is never a
/// concurrent race to initialize.
static CRYPTOKI_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

impl<'lib> Pkcs11Session<'lib> {
    pub(crate) fn reset_sign_profile(&self) -> BenchResult<()> {
        self.lib.reset_sign_profile()
    }

    pub(crate) fn sign_profile_snapshot(&self) -> BenchResult<SignProfileSnapshot> {
        self.lib.sign_profile_snapshot()
    }

    pub(crate) fn set_sign_profile_enabled(&self, enabled: bool) -> BenchResult<()> {
        self.lib.set_sign_profile_enabled(enabled)
    }

    /// Initializes the Cryptoki library on the first call only, discovers its (sole)
    /// slot, and opens one read/write serial session, logging in as the normal user
    /// (a no-op unless the provider is configured for OIDC-pin mode, which this
    /// benchmark does not use).
    pub(crate) fn open(lib: &'lib Pkcs11Lib) -> BenchResult<Self> {
        let f = &lib.functions;

        if !CRYPTOKI_INITIALIZED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let c_initialize = f.C_Initialize.ok_or_else(|| missing("C_Initialize"))?;
            // SAFETY: `pInitArgs` is `NULL`, which is valid per the Cryptoki spec (no
            // application-supplied locking callbacks).
            check("C_Initialize", unsafe { c_initialize(ptr::null_mut()) })?;
        }

        let c_get_slot_list = f.C_GetSlotList.ok_or_else(|| missing("C_GetSlotList"))?;
        let mut slot_count: CK_ULONG = 0;
        // SAFETY: passing a null slot-list pointer with a valid `pulCount` out-param is
        // the documented way to query the slot count first.
        check("C_GetSlotList(count)", unsafe {
            c_get_slot_list(0, ptr::null_mut(), &raw mut slot_count)
        })?;
        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        // SAFETY: `slots` was just sized to `slot_count`, which the library itself
        // reported in the call above.
        check("C_GetSlotList", unsafe {
            c_get_slot_list(0, slots.as_mut_ptr(), &raw mut slot_count)
        })?;
        let slot_id = *slots
            .first()
            .ok_or_else(|| BenchError::Setup("provider reported no PKCS#11 slots".to_owned()))?;

        let c_open_session = f.C_OpenSession.ok_or_else(|| missing("C_OpenSession"))?;
        let mut handle: CK_SESSION_HANDLE = 0;
        let flags: CK_FLAGS = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        // SAFETY: no notification callback is registered (`Notify: None`), which is a
        // valid, documented configuration for a session that is only ever polled.
        check("C_OpenSession", unsafe {
            c_open_session(slot_id, flags, ptr::null_mut(), None, &raw mut handle)
        })?;

        if let Some(c_login) = f.C_Login {
            // SAFETY: `pPin`/`ulPinLen` describe an empty (zero-length) PIN buffer,
            // which is a no-op for this provider unless OIDC-pin mode is configured
            // (not used by this benchmark).
            let rv = unsafe { c_login(handle, CKU_USER as CK_USER_TYPE, ptr::null_mut(), 0) };
            check("C_Login", rv)?;
        }

        Ok(Self { lib, handle })
    }

    /// Finds the first object of the given `CK_OBJECT_CLASS` (e.g. `CKO_SECRET_KEY`,
    /// `CKO_PRIVATE_KEY`) visible to the provider's current backend.
    pub(crate) fn find_first_by_class(
        &self,
        class: CK_OBJECT_CLASS,
    ) -> BenchResult<CK_OBJECT_HANDLE> {
        self.find_first(class, None)
    }

    /// Finds the first object of the given `CK_OBJECT_CLASS` *and* `CK_KEY_TYPE`
    /// (e.g. `CKO_PRIVATE_KEY` + `CKK_RSA`, or `CKO_PRIVATE_KEY` + `CKK_EC_EDWARDS`).
    ///
    /// Needed because the benchmark provisions more than one key of the same class
    /// (an RSA and an Ed25519 key pair both create `CKO_PRIVATE_KEY`/`CKO_PUBLIC_KEY`
    /// objects) — filtering by class alone would non-deterministically return
    /// whichever key the backend happens to enumerate first.
    pub(crate) fn find_first_by_class_and_key_type(
        &self,
        class: CK_OBJECT_CLASS,
        key_type: CK_KEY_TYPE,
    ) -> BenchResult<CK_OBJECT_HANDLE> {
        self.find_first(class, Some(key_type))
    }

    /// Shared `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` implementation
    /// backing [`Self::find_first_by_class`] and
    /// [`Self::find_first_by_class_and_key_type`].
    fn find_first(
        &self,
        class: CK_OBJECT_CLASS,
        key_type: Option<CK_KEY_TYPE>,
    ) -> BenchResult<CK_OBJECT_HANDLE> {
        let f = &self.lib.functions;
        let mut class = class;
        let mut key_type = key_type;
        let mut template = vec![CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: (&raw mut class).cast::<std::ffi::c_void>(),
            ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];
        if let Some(key_type) = key_type.as_mut() {
            template.push(CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&raw mut *key_type).cast::<std::ffi::c_void>(),
                ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
            });
        }

        let c_find_init = f
            .C_FindObjectsInit
            .ok_or_else(|| missing("C_FindObjectsInit"))?;
        // SAFETY: `template` is a valid, correctly-sized `CK_ATTRIBUTE` array, kept
        // alive on the stack for the duration of this call.
        check("C_FindObjectsInit", unsafe {
            c_find_init(
                self.handle,
                template.as_ptr().cast_mut(),
                template.len() as CK_ULONG,
            )
        })?;

        let c_find = f.C_FindObjects.ok_or_else(|| missing("C_FindObjects"))?;
        // The current module-side `SearchOptions` only narrows by ID/profile and
        // may return every object of `class` even when `CKA_KEY_TYPE` is also in the
        // template. Read a bounded batch and verify each returned handle's actual
        // key type below rather than depending on enumeration order.
        let mut handles = [0 as CK_OBJECT_HANDLE; 64];
        let mut found: CK_ULONG = 0;
        // SAFETY: `handles` has room for `handles.len()` entries, matching
        // `ulMaxObjectCount`.
        let find_result = check("C_FindObjects", unsafe {
            c_find(
                self.handle,
                handles.as_mut_ptr(),
                handles.len() as CK_ULONG,
                &raw mut found,
            )
        });

        let c_find_final = f
            .C_FindObjectsFinal
            .ok_or_else(|| missing("C_FindObjectsFinal"))?;
        // SAFETY: closes the search context opened by `C_FindObjectsInit` above.
        check("C_FindObjectsFinal", unsafe { c_find_final(self.handle) })?;

        find_result?;
        let found = usize::try_from(found)
            .map_err(|e| BenchError::Setup(format!("invalid C_FindObjects count: {e}")))?
            .min(handles.len());
        let selected = if let Some(expected_key_type) = key_type {
            handles[..found]
                .iter()
                .copied()
                .find_map(|handle| match self.object_key_type(handle) {
                    Ok(actual_key_type) if actual_key_type == expected_key_type => Some(Ok(handle)),
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                })
                .transpose()?
        } else {
            handles[..found].first().copied()
        };
        let Some(selected) = selected else {
            return Err(BenchError::Setup(format!(
                "no PKCS#11 object of class {class} (key_type {key_type:?}) found — did \
                 benchmark key setup run?"
            )));
        };
        Ok(selected)
    }

    fn object_key_type(&self, handle: CK_OBJECT_HANDLE) -> BenchResult<CK_KEY_TYPE> {
        let c_get_attribute_value = self
            .lib
            .functions
            .C_GetAttributeValue
            .ok_or_else(|| missing("C_GetAttributeValue"))?;
        let mut key_type: CK_KEY_TYPE = 0;
        let mut attribute = CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: (&raw mut key_type).cast::<std::ffi::c_void>(),
            ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
        };
        // SAFETY: `attribute` points to a correctly-sized, writable CK_KEY_TYPE
        // value that remains valid for the duration of the call.
        check("C_GetAttributeValue(CKA_KEY_TYPE)", unsafe {
            c_get_attribute_value(self.handle, handle, &raw mut attribute, 1)
        })?;
        Ok(key_type)
    }

    /// `C_EncryptInit` + `C_Encrypt` with `CKM_AES_CBC_PAD` and a fixed zero IV.
    pub(crate) fn encrypt(&self, key: CK_OBJECT_HANDLE, plaintext: &[u8]) -> BenchResult<Vec<u8>> {
        let f = &self.lib.functions;
        let mut iv = [0_u8; AES_IV_SIZE];
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_CBC_PAD,
            pParameter: iv.as_mut_ptr().cast::<std::ffi::c_void>(),
            ulParameterLen: AES_IV_SIZE as CK_ULONG,
        };

        let c_encrypt_init = f.C_EncryptInit.ok_or_else(|| missing("C_EncryptInit"))?;
        // SAFETY: `mechanism` is a valid, fully-initialized `CK_MECHANISM` on the stack.
        check("C_EncryptInit", unsafe {
            c_encrypt_init(self.handle, &raw mut mechanism, key)
        })?;

        let c_encrypt = f.C_Encrypt.ok_or_else(|| missing("C_Encrypt"))?;
        let mut input = plaintext.to_vec();
        let mut output = vec![0_u8; plaintext.len() + AES_IV_SIZE];
        let mut output_len = output.len() as CK_ULONG;
        // SAFETY: `output` is sized to the worst case (plaintext + one AES block of
        // padding); `output_len` reports the actual length written on success.
        check("C_Encrypt", unsafe {
            c_encrypt(
                self.handle,
                input.as_mut_ptr(),
                input.len() as CK_ULONG,
                output.as_mut_ptr(),
                &raw mut output_len,
            )
        })?;
        output.truncate(output_len as usize);
        Ok(output)
    }

    /// `C_DecryptInit` + `C_Decrypt` with `CKM_AES_CBC_PAD` and a fixed zero IV.
    pub(crate) fn decrypt(&self, key: CK_OBJECT_HANDLE, ciphertext: &[u8]) -> BenchResult<Vec<u8>> {
        let f = &self.lib.functions;
        let mut iv = [0_u8; AES_IV_SIZE];
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_CBC_PAD,
            pParameter: iv.as_mut_ptr().cast::<std::ffi::c_void>(),
            ulParameterLen: AES_IV_SIZE as CK_ULONG,
        };

        let c_decrypt_init = f.C_DecryptInit.ok_or_else(|| missing("C_DecryptInit"))?;
        // SAFETY: `mechanism` is a valid, fully-initialized `CK_MECHANISM` on the stack.
        check("C_DecryptInit", unsafe {
            c_decrypt_init(self.handle, &raw mut mechanism, key)
        })?;

        let c_decrypt = f.C_Decrypt.ok_or_else(|| missing("C_Decrypt"))?;
        let mut input = ciphertext.to_vec();
        let mut output = vec![0_u8; ciphertext.len()];
        let mut output_len = output.len() as CK_ULONG;
        // SAFETY: `output` is sized to at least the plaintext length (removing PKCS#7
        // padding can only shrink it); `output_len` reports the actual length written.
        check("C_Decrypt", unsafe {
            c_decrypt(
                self.handle,
                input.as_mut_ptr(),
                input.len() as CK_ULONG,
                output.as_mut_ptr(),
                &raw mut output_len,
            )
        })?;
        output.truncate(output_len as usize);
        Ok(output)
    }

    /// `C_SignInit` + one `C_Sign` call into a caller-owned, pre-sized buffer.
    ///
    /// The benchmark knows the exact signature sizes of its two configured keys
    /// (64 bytes for Ed25519, 256 bytes for RSA-2048), so a length-query
    /// `C_Sign(NULL)` call would be both unnecessary and actively misleading:
    /// `cosmian_pkcs11_module::Session::sign` currently performs the real remote
    /// KMS Sign even when the output pointer is null. The standard two-call
    /// convention would therefore benchmark *two* HTTP/KMIP Sign requests per
    /// logical signature.
    pub(crate) fn sign_into(
        &self,
        private_key: CK_OBJECT_HANDLE,
        message: &[u8],
        mechanism: CK_MECHANISM_TYPE,
        signature: &mut [u8],
    ) -> BenchResult<usize> {
        let f = &self.lib.functions;
        let mut mechanism = CK_MECHANISM {
            mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let c_sign_init = f.C_SignInit.ok_or_else(|| missing("C_SignInit"))?;
        // SAFETY: `mechanism` is a valid, fully-initialized `CK_MECHANISM` on the stack.
        check("C_SignInit", unsafe {
            c_sign_init(self.handle, &raw mut mechanism, private_key)
        })?;

        let c_sign = f.C_Sign.ok_or_else(|| missing("C_Sign"))?;
        let mut sig_len = signature.len() as CK_ULONG;
        // SAFETY: PKCS#11 declares `pData` as mutable for historical C API reasons,
        // but `C_Sign` treats it as input-only. `message` and `signature` remain
        // valid and correctly sized for the duration of the call.
        check("C_Sign", unsafe {
            c_sign(
                self.handle,
                message.as_ptr().cast_mut(),
                message.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &raw mut sig_len,
            )
        })?;
        Ok(sig_len as usize)
    }

    /// Initializes the PKCS#11 v3 message-signing operation once for a session.
    pub(crate) fn message_sign_init(
        &self,
        private_key: CK_OBJECT_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
    ) -> BenchResult<()> {
        let mut mechanism = CK_MECHANISM {
            mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let init = self
            .lib
            .functions
            .C_MessageSignInit
            .ok_or_else(|| missing("C_MessageSignInit"))?;
        // SAFETY: `mechanism` is fully initialized and valid for the call.
        check("C_MessageSignInit", unsafe {
            init(self.handle, &raw mut mechanism, private_key)
        })
    }

    /// Signs one complete message through the PKCS#11 v3 `C_SignMessage` flow.
    ///
    /// [`Self::message_sign_init`] is called once before the benchmark loop; the
    /// initialized context remains reusable across independent messages.
    pub(crate) fn sign_message_into(
        &self,
        message: &[u8],
        signature: &mut [u8],
    ) -> BenchResult<usize> {
        let sign = self
            .lib
            .functions
            .C_SignMessage
            .ok_or_else(|| missing("C_SignMessage"))?;
        let mut signature_len = signature.len() as CK_ULONG;
        // SAFETY: pure EdDSA uses no per-message parameter; data is input-only
        // despite the mutable C pointer type, and the output buffer is writable.
        check("C_SignMessage", unsafe {
            sign(
                self.handle,
                ptr::null_mut(),
                0,
                message.as_ptr().cast_mut(),
                message.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &raw mut signature_len,
            )
        })?;
        Ok(signature_len as usize)
    }

    /// Finalizes the PKCS#11 v3 message-signing operation for this session.
    pub(crate) fn message_sign_final(&self) -> BenchResult<()> {
        let finalize = self
            .lib
            .functions
            .C_MessageSignFinal
            .ok_or_else(|| missing("C_MessageSignFinal"))?;
        // SAFETY: `self.handle` is an open session owned by this wrapper.
        check("C_MessageSignFinal", unsafe { finalize(self.handle) })
    }

    /// Convenience wrapper around [`Self::sign_into`] for one-time setup calls that
    /// need to retain the signature (e.g. preparing a Verify benchmark).
    pub(crate) fn sign(
        &self,
        private_key: CK_OBJECT_HANDLE,
        message: &[u8],
        mechanism: CK_MECHANISM_TYPE,
        signature_len: usize,
    ) -> BenchResult<Vec<u8>> {
        let mut signature = vec![0_u8; signature_len];
        let actual_len = self.sign_into(private_key, message, mechanism, &mut signature)?;
        signature.truncate(actual_len);
        Ok(signature)
    }

    /// Standard two-call path retained for the differential overhead benchmark.
    /// It verifies that a client which first calls `C_Sign(NULL)` to query the
    /// length is no longer charged for two remote KMS Sign requests after the
    /// module-side fixed-size length-query optimization.
    pub(crate) fn sign_with_length_query(
        &self,
        private_key: CK_OBJECT_HANDLE,
        message: &[u8],
        mechanism: CK_MECHANISM_TYPE,
    ) -> BenchResult<Vec<u8>> {
        let f = &self.lib.functions;
        let mut mechanism = CK_MECHANISM {
            mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let c_sign_init = f.C_SignInit.ok_or_else(|| missing("C_SignInit"))?;
        // SAFETY: `mechanism` is a valid, fully-initialized `CK_MECHANISM` on the stack.
        check("C_SignInit", unsafe {
            c_sign_init(self.handle, &raw mut mechanism, private_key)
        })?;

        let c_sign = f.C_Sign.ok_or_else(|| missing("C_Sign"))?;
        let mut sig_len: CK_ULONG = 0;
        // SAFETY: a null output buffer is the Cryptoki length-query convention;
        // `pData` is input-only despite its mutable C pointer type.
        check("C_Sign(len)", unsafe {
            c_sign(
                self.handle,
                message.as_ptr().cast_mut(),
                message.len() as CK_ULONG,
                ptr::null_mut(),
                &raw mut sig_len,
            )
        })?;

        let mut signature = vec![0_u8; sig_len as usize];
        // SAFETY: `signature` is sized to the length returned by the query call;
        // `pData` is input-only despite its mutable C pointer type.
        check("C_Sign", unsafe {
            c_sign(
                self.handle,
                message.as_ptr().cast_mut(),
                message.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &raw mut sig_len,
            )
        })?;
        signature.truncate(sig_len as usize);
        Ok(signature)
    }

    /// `C_VerifyInit` + `C_Verify` with the given `mechanism` (e.g.
    /// `CKM_SHA256_RSA_PKCS`, `CKM_EDDSA`), both fully implemented (`cryptoki_fn!`,
    /// not `cryptoki_fn_not_supported!`) by `cosmian_pkcs11_module`
    /// (`crate/clients/pkcs11/module/src/pkcs11.rs`). Callers should still check
    /// [`BenchError::is_function_not_supported`] on the returned error and skip the
    /// benchmark rather than treat it as a hard failure, in case a future provider
    /// (or backend configuration) doesn't support `C_Verify` for a given mechanism.
    pub(crate) fn verify(
        &self,
        public_key: CK_OBJECT_HANDLE,
        message: &[u8],
        signature: &[u8],
        mechanism: CK_MECHANISM_TYPE,
    ) -> BenchResult<()> {
        let f = &self.lib.functions;
        let mut mechanism = CK_MECHANISM {
            mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let c_verify_init = f.C_VerifyInit.ok_or_else(|| missing("C_VerifyInit"))?;
        // SAFETY: `mechanism` is a valid, fully-initialized `CK_MECHANISM` on the stack.
        check("C_VerifyInit", unsafe {
            c_verify_init(self.handle, &raw mut mechanism, public_key)
        })?;

        let c_verify = f.C_Verify.ok_or_else(|| missing("C_Verify"))?;
        let mut input = message.to_vec();
        let mut sig = signature.to_vec();
        // SAFETY: `input`/`sig` are valid, correctly-sized buffers for the duration of
        // this call.
        check("C_Verify", unsafe {
            c_verify(
                self.handle,
                input.as_mut_ptr(),
                input.len() as CK_ULONG,
                sig.as_mut_ptr(),
                sig.len() as CK_ULONG,
            )
        })
    }

    /// Generates an ephemeral AES-128 secret key with `C_GenerateKey`
    /// (`CKM_AES_KEY_GEN`) and immediately destroys it with `C_DestroyObject`.
    ///
    /// `C_GenerateKeyPair` is not implemented by this provider (asymmetric key
    /// generation is done via the KMS REST API, not PKCS#11), so `C_GenerateKey`
    /// (symmetric) is the only Cryptoki key-creation path this benchmark can drive.
    pub(crate) fn generate_and_destroy_key(&self) -> BenchResult<()> {
        let f = &self.lib.functions;
        let mut iv = [0_u8; AES_IV_SIZE];
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: iv.as_mut_ptr().cast::<std::ffi::c_void>(),
            ulParameterLen: AES_IV_SIZE as CK_ULONG,
        };

        let mut key_type: CK_KEY_TYPE = CKK_AES;
        let mut sensitive: CK_BBOOL = CK_TRUE as CK_BBOOL;
        let mut extractable: CK_BBOOL = CK_TRUE as CK_BBOOL;
        let mut value_len: CK_ULONG = 16;
        let label = "pkcs11-bench-key-creation";
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&raw mut key_type).cast::<std::ffi::c_void>(),
                ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label.as_ptr().cast_mut().cast::<std::ffi::c_void>(),
                ulValueLen: label.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: (&raw mut sensitive).cast::<std::ffi::c_void>(),
                ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: (&raw mut extractable).cast::<std::ffi::c_void>(),
                ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: (&raw mut value_len).cast::<std::ffi::c_void>(),
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
            },
        ];

        let c_generate_key = f.C_GenerateKey.ok_or_else(|| missing("C_GenerateKey"))?;
        let mut key_handle: CK_OBJECT_HANDLE = 0;
        // SAFETY: `template` is a valid, fully-initialized `CK_ATTRIBUTE` array on the
        // stack for the duration of this call.
        check("C_GenerateKey", unsafe {
            c_generate_key(
                self.handle,
                &raw mut mechanism,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &raw mut key_handle,
            )
        })?;

        let c_destroy = f
            .C_DestroyObject
            .ok_or_else(|| missing("C_DestroyObject"))?;
        // SAFETY: `key_handle` was just returned as valid by `C_GenerateKey` above.
        check("C_DestroyObject", unsafe {
            c_destroy(self.handle, key_handle)
        })
    }
}

impl Drop for Pkcs11Session<'_> {
    fn drop(&mut self) {
        let f = &self.lib.functions;
        if let Some(c_close) = f.C_CloseSession {
            // SAFETY: `self.handle` was opened by `Pkcs11Session::open` and is closed
            // exactly once here.
            let _ = unsafe { c_close(self.handle) };
        }
    }
}

impl Drop for Pkcs11Lib {
    fn drop(&mut self) {
        if let Some(c_finalize) = self.functions.C_Finalize {
            // SAFETY: all sessions borrow `self`, so they have already been dropped
            // before library ownership reaches this point. `pReserved: NULL` is the
            // only valid value per the Cryptoki specification.
            let _ = unsafe { c_finalize(ptr::null_mut()) };
        }
        CRYPTOKI_INITIALIZED.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

fn missing(name: &'static str) -> BenchError {
    BenchError::MissingSymbol(name.to_owned())
}
