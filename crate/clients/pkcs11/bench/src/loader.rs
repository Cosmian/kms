//! Real `dlopen()`-based Cryptoki v2.40 client for the `cosmian_pkcs11` provider.
//!
//! This mirrors exactly how a real PKCS#11 consumer (Oracle TDE, OpenSSH,
//! `VeraCrypt`, ...) drives the module: `dlopen()` the shared library, resolve
//! the single stable `C_GetFunctionList` symbol, and call every other
//! Cryptoki function through the returned function-pointer table.

use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR, CK_KEY_TYPE,
    CK_MECHANISM, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE,
    CK_ULONG, CK_USER_TYPE, CKA_CLASS, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_SENSITIVE,
    CKA_VALUE_LEN, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKK_AES, CKM_AES_CBC_PAD, CKM_AES_KEY_GEN,
    CKM_SHA256_RSA_PKCS, CKR_OK, CKU_USER,
};

use crate::error::{BenchError, BenchResult};

/// A 16-byte all-zero IV used for every `CKM_AES_CBC_PAD` call in this benchmark.
///
/// Reusing a fixed IV across calls is intentionally insecure (never do this in
/// production code); it is only acceptable here because this is a throughput/latency
/// micro-benchmark, not a security-sensitive path.
const AES_IV_SIZE: usize = 16;

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
/// Cryptoki v2.40 function table.
pub(crate) struct Pkcs11Lib {
    // Kept alive for the lifetime of the process: dropping it would unmap the
    // library while `functions`' pointers are still callable.
    _library: libloading::Library,
    functions: CK_FUNCTION_LIST,
}

impl Pkcs11Lib {
    /// Loads the provider library at `path` and resolves its Cryptoki function list.
    pub(crate) fn load(path: &str) -> BenchResult<Self> {
        // SAFETY: `dlopen()`-ing a shared library runs its static initializers; this
        // is the documented, unavoidable risk of loading native code and is exactly
        // what any real PKCS#11 consumer application does with this provider.
        let library = unsafe { libloading::Library::new(path) }?;

        // SAFETY: `C_GetFunctionList` is a stable, per-spec Cryptoki v2.40 symbol with
        // the exact `unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV` ABI. The
        // resolved symbol does not outlive `library`, which is kept alive in `self`.
        let get_function_list: libloading::Symbol<
            '_,
            unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV,
        > = unsafe { library.get(b"C_GetFunctionList\0") }.map_err(|load_err| {
            BenchError::MissingSymbol(format!("C_GetFunctionList ({load_err})"))
        })?;

        let mut list_ptr: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        // SAFETY: `list_ptr` is a valid `*mut CK_FUNCTION_LIST_PTR` out-parameter, as
        // required by the Cryptoki spec for `C_GetFunctionList`.
        let rv = unsafe { get_function_list(&raw mut list_ptr) };
        check("C_GetFunctionList", rv)?;
        if list_ptr.is_null() {
            return Err(BenchError::MissingSymbol(
                "C_GetFunctionList returned a null function list".to_owned(),
            ));
        }
        // SAFETY: `list_ptr` was just validated non-null and `CKR_OK` by the library
        // itself. `CK_FUNCTION_LIST` is `Copy`, so this snapshot stays valid
        // independently of the pointer, as long as `_library` (kept in `self`) is
        // never unloaded.
        let functions = unsafe { *list_ptr };

        Ok(Self {
            _library: library,
            functions,
        })
    }
}

/// A single, shared Cryptoki session opened against the loaded provider.
///
/// Intentionally holds exactly **one** `CK_SESSION_HANDLE`, shared by every worker
/// thread of the load sweep: `crate/clients/pkcs11/module/src/sessions.rs` stores all
/// sessions behind one global `Mutex<SessionMap>`, so concurrent calls against this
/// single handle are already serialized by the module itself — this is what makes the
/// "single shared session" concurrency model meaningful.
pub(crate) struct Pkcs11Session<'lib> {
    lib: &'lib Pkcs11Lib,
    handle: CK_SESSION_HANDLE,
}

impl<'lib> Pkcs11Session<'lib> {
    /// Initializes the Cryptoki library, discovers its (sole) slot, and opens one
    /// read/write serial session, logging in as the normal user (a no-op unless the
    /// provider is configured for OIDC-pin mode, which this benchmark does not use).
    pub(crate) fn open(lib: &'lib Pkcs11Lib) -> BenchResult<Self> {
        let f = &lib.functions;

        let c_initialize = f.C_Initialize.ok_or_else(|| missing("C_Initialize"))?;
        // SAFETY: `pInitArgs` is `NULL`, which is valid per the Cryptoki spec (no
        // application-supplied locking callbacks).
        check("C_Initialize", unsafe { c_initialize(ptr::null_mut()) })?;

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
        let f = &self.lib.functions;
        let mut class = class;
        let template = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: (&raw mut class).cast::<std::ffi::c_void>(),
            ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];

        let c_find_init = f
            .C_FindObjectsInit
            .ok_or_else(|| missing("C_FindObjectsInit"))?;
        // SAFETY: `template` is a valid, correctly-sized `CK_ATTRIBUTE` array on the
        // stack for the duration of this call.
        check("C_FindObjectsInit", unsafe {
            c_find_init(
                self.handle,
                template.as_ptr().cast_mut(),
                template.len() as CK_ULONG,
            )
        })?;

        let c_find = f.C_FindObjects.ok_or_else(|| missing("C_FindObjects"))?;
        let mut handles = [0 as CK_OBJECT_HANDLE; 1];
        let mut found: CK_ULONG = 0;
        // SAFETY: `handles` has room for exactly one handle, matching `ulMaxObjectCount`.
        let find_result = check("C_FindObjects", unsafe {
            c_find(self.handle, handles.as_mut_ptr(), 1, &raw mut found)
        });

        let c_find_final = f
            .C_FindObjectsFinal
            .ok_or_else(|| missing("C_FindObjectsFinal"))?;
        // SAFETY: closes the search context opened by `C_FindObjectsInit` above.
        check("C_FindObjectsFinal", unsafe { c_find_final(self.handle) })?;

        find_result?;
        if found == 0 {
            return Err(BenchError::Setup(format!(
                "no PKCS#11 object of class {class} found — did benchmark key setup run?"
            )));
        }
        Ok(handles[0])
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

    /// `C_SignInit` + `C_Sign` with `CKM_SHA256_RSA_PKCS` (the module hashes the raw
    /// message internally — no pre-hashing needed on the caller side).
    pub(crate) fn sign(
        &self,
        private_key: CK_OBJECT_HANDLE,
        message: &[u8],
    ) -> BenchResult<Vec<u8>> {
        let f = &self.lib.functions;
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let c_sign_init = f.C_SignInit.ok_or_else(|| missing("C_SignInit"))?;
        // SAFETY: `mechanism` is a valid, fully-initialized `CK_MECHANISM` on the stack.
        check("C_SignInit", unsafe {
            c_sign_init(self.handle, &raw mut mechanism, private_key)
        })?;

        let c_sign = f.C_Sign.ok_or_else(|| missing("C_Sign"))?;
        let mut input = message.to_vec();
        // First call with a null signature buffer to learn the required length, per
        // the standard Cryptoki two-call convention. The provider computes the real
        // signature to determine its length but only clears the sign context once the
        // second call copies it out (`crate/clients/pkcs11/module/src/sessions.rs`
        // `Session::sign`), so the context set up by `C_SignInit` above remains valid.
        let mut sig_len: CK_ULONG = 0;
        // SAFETY: `pSignature: NULL` is the documented way to query the required
        // output length before allocating a buffer.
        check("C_Sign(len)", unsafe {
            c_sign(
                self.handle,
                input.as_mut_ptr(),
                input.len() as CK_ULONG,
                ptr::null_mut(),
                &raw mut sig_len,
            )
        })?;

        let mut signature = vec![0_u8; sig_len as usize];
        // SAFETY: `signature` is sized exactly to the length reported by the query
        // call above.
        check("C_Sign", unsafe {
            c_sign(
                self.handle,
                input.as_mut_ptr(),
                input.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &raw mut sig_len,
            )
        })?;
        signature.truncate(sig_len as usize);
        Ok(signature)
    }

    /// `C_VerifyInit` + `C_Verify` with `CKM_SHA256_RSA_PKCS`.
    ///
    /// **Not implemented by `cosmian_pkcs11_module`** — `C_VerifyInit`/`C_Verify` are
    /// registered via its `cryptoki_fn_not_supported!` macro
    /// (`crate/clients/pkcs11/module/src/pkcs11.rs`), always returning
    /// `CKR_FUNCTION_NOT_SUPPORTED`. This method is implemented in full (mirroring
    /// `sign`) so it starts working automatically the day the module gains support,
    /// but callers should check [`BenchError::is_function_not_supported`] on the
    /// returned error and skip the benchmark rather than treat it as a hard failure.
    pub(crate) fn verify(
        &self,
        public_key: CK_OBJECT_HANDLE,
        message: &[u8],
        signature: &[u8],
    ) -> BenchResult<()> {
        let f = &self.lib.functions;
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
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
        if let Some(c_finalize) = f.C_Finalize {
            // SAFETY: `pReserved: NULL` is the only valid value per the Cryptoki spec.
            let _ = unsafe { c_finalize(ptr::null_mut()) };
        }
    }
}

fn missing(name: &'static str) -> BenchError {
    BenchError::MissingSymbol(name.to_owned())
}
