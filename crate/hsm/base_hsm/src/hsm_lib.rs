use std::ptr;

use libloading::Library;
use pkcs11_sys::{
    CK_C_CloseSession, CK_C_Decrypt, CK_C_DecryptFinal, CK_C_DecryptInit, CK_C_DecryptUpdate,
    CK_C_DestroyObject, CK_C_Encrypt, CK_C_EncryptFinal, CK_C_EncryptInit, CK_C_EncryptUpdate,
    CK_C_Finalize, CK_C_FindObjects, CK_C_FindObjectsFinal, CK_C_FindObjectsInit, CK_C_GenerateKey,
    CK_C_GenerateKeyPair, CK_C_GenerateRandom, CK_C_GetAttributeValue, CK_C_GetInfo,
    CK_C_GetMechanismInfo, CK_C_GetMechanismList, CK_C_INITIALIZE_ARGS, CK_C_Initialize,
    CK_C_Login, CK_C_Logout, CK_C_OpenSession, CK_C_SeedRandom, CK_C_UnwrapKey, CK_C_WrapKey,
    CKF_OS_LOCKING_OK,
};

use crate::{HResult, hsm_call};

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

    pub(crate) C_GetInfo: CK_C_GetInfo,
    pub(crate) C_GetMechanismList: CK_C_GetMechanismList,
    pub(crate) C_GetMechanismInfo: CK_C_GetMechanismInfo,

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
        #[expect(unsafe_code)]
        unsafe {
            let library = Library::new(path)?;
            let hsm_lib = Self {
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
                C_SeedRandom: Some(*library.get(b"C_SeedRandom")?),
                C_GetAttributeValue: Some(*library.get(b"C_GetAttributeValue")?),
                C_GetInfo: Some(*library.get(b"C_GetInfo")?),
                C_GetMechanismList: Some(*library.get(b"C_GetMechanismList")?),
                C_GetMechanismInfo: Some(*library.get(b"C_GetMechanismInfo")?),
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
        hsm_call!(
            hsm_lib,
            "Failed initializing the HSM",
            C_Initialize,
            (&raw const p_init_args)
                .cast::<std::ffi::c_void>()
                .cast_mut()
        );
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
