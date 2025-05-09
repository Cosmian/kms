use std::ptr;

use cosmian_pkcs11_sys::*;
use libloading::Library;

use crate::{HError, HResult};

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
#[allow(dead_code)]
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

    pub(crate) C_GetAttributeValue: CK_C_GetAttributeValue,

    pub(crate) C_GetInfo: CK_C_GetInfo,

    pub(crate) C_Login: CK_C_Login,
    pub(crate) C_Logout: CK_C_Logout,

    pub(crate) C_WrapKey: CK_C_WrapKey,
    pub(crate) C_UnwrapKey: CK_C_UnwrapKey,
}

impl HsmLib {
    pub(crate) fn instantiate<P>(path: P) -> HResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        unsafe {
            let library = Library::new(path)?;
            let hsm_lib = HsmLib {
                C_Initialize: Some(*library.get(b"C_Initialize")?),
                C_Finalize: Some(*library.get(b"C_Finalize")?),
                C_OpenSession: Some(*library.get(b"C_OpenSession")?),
                C_CloseSession: Some(*library.get(b"C_CloseSession")?),
                C_Encrypt: Some(*library.get(b"C_Encrypt")?),
                C_EncryptInit: Some(*library.get(b"C_EncryptInit")?),
                C_EncryptUpdate: Some(*library.get(b"C_EncryptUpdate")?),
                C_EncryptFinal: Some(*library.get(b"C_EncryptFinal")?),
                C_Decrypt: Some(*library.get(b"C_Decrypt")?),
                C_DecryptInit: Some(*library.get(b"C_DecryptInit")?),
                C_DecryptUpdate: Some(*library.get(b"C_DecryptUpdate")?),
                C_DecryptFinal: Some(*library.get(b"C_DecryptFinal")?),
                C_DestroyObject: Some(*library.get(b"C_DestroyObject")?),
                C_FindObjectsInit: Some(*library.get(b"C_FindObjectsInit")?),
                C_FindObjects: Some(*library.get(b"C_FindObjects")?),
                C_FindObjectsFinal: Some(*library.get(b"C_FindObjectsFinal")?),
                C_GenerateKey: Some(*library.get(b"C_GenerateKey")?),
                C_GenerateKeyPair: Some(*library.get(b"C_GenerateKeyPair")?),
                C_GenerateRandom: Some(*library.get(b"C_GenerateRandom")?),
                C_GetAttributeValue: Some(*library.get(b"C_GetAttributeValue")?),
                C_GetInfo: Some(*library.get(b"C_GetInfo")?),
                C_Login: Some(*library.get(b"C_Login")?),
                C_Logout: Some(*library.get(b"C_Logout")?),
                C_WrapKey: Some(*library.get(b"C_WrapKey")?),
                C_UnwrapKey: Some(*library.get(b"C_UnwrapKey")?),
                // we need to keep the library alive
                _library: library,
            };
            Self::initialize(&hsm_lib)?;
            Ok(hsm_lib)
        }
    }

    fn initialize(hsm_lib: &HsmLib) -> HResult<()> {
        let pInitArgs = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        unsafe {
            // let rv = self.hsm.C_Initialize.deref()(&pInitArgs);
            let rv = hsm_lib.C_Initialize.ok_or_else(|| {
                HError::Default("C_Initialize not available on library".to_string())
            })?(&pInitArgs as *const CK_C_INITIALIZE_ARGS as CK_VOID_PTR);
            if rv != CKR_OK {
                return Err(HError::Default("Failed initializing the HSM".to_string()));
            }
            Ok(())
        }
    }

    fn finalize(&self) -> HResult<()> {
        unsafe {
            let rv = self.C_Finalize.ok_or_else(|| {
                HError::Default("C_Finalize not available on library".to_string())
            })?(ptr::null_mut());
            if rv != CKR_OK {
                return Err(HError::Default("Failed to finalize the HSM".to_string()));
            }
            Ok(())
        }
    }
}

impl Drop for HsmLib {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}
