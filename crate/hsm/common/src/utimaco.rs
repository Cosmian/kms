use std::{
    collections::HashMap,
    ffi::CStr,
    fmt,
    fmt::{Display, Formatter},
    ptr,
    sync::{Arc, Mutex},
};

use libloading::Library;
use pkcs11_sys::*;

use crate::{PError, PResult, SlotManager};

struct SlotState {
    password: Option<String>,
    slot: Option<Arc<SlotManager>>,
}

pub struct Utimaco {
    hsm_lib: Arc<HsmLib>,
    slots: Mutex<HashMap<usize, SlotState>>,
}

impl Utimaco {
    pub fn instantiate<P>(path: P, passwords: HashMap<usize, Option<String>>) -> PResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        let hsm_lib = Arc::new(HsmLib::instantiate(path)?);
        let mut slots = HashMap::with_capacity(passwords.len());
        for (k, v) in passwords.iter() {
            slots.insert(
                *k,
                SlotState {
                    password: v.clone(),
                    slot: None,
                },
            );
        }
        Ok(Utimaco {
            hsm_lib,
            slots: Mutex::new(slots),
        })
    }

    /// Get a slot
    /// If a slot has already been opened, returns the opened slot.
    /// To close a slot before re-opening it with another password, call `close_slot()` first
    pub fn get_slot(&self, slot_id: usize) -> PResult<Arc<SlotManager>> {
        let mut slots = self.slots.lock().expect("failed to lock slots");
        // check if we are supposed to use that slot
        if let Some(slot_state) = slots.get_mut(&slot_id) {
            if let Some(s) = &slot_state.slot {
                Ok(s.clone())
            } else {
                // instantiate a new slot
                let manager = Arc::new(SlotManager::instantiate(
                    self.hsm_lib.clone(),
                    slot_id,
                    slot_state.password.clone(),
                )?);
                slot_state.slot = Some(manager.clone());
                Ok(manager)
            }
        } else {
            Err(PError::Default(format!("slot {slot_id} is not accessible")))
        }
    }

    pub fn close_slot(&self, slot_id: usize) -> PResult<()> {
        let mut slots = self.slots.lock().expect("failed to lock slots");
        slots.remove(&slot_id);
        Ok(())
    }

    pub fn get_info(&self) -> PResult<Info> {
        unsafe {
            let mut info = CK_INFO::default();
            let rv =
                self.hsm_lib.C_GetInfo.ok_or_else(|| {
                    PError::Default("C_GetInfo not available on library".to_string())
                })?(&mut info);
            if rv != CKR_OK {
                return Err(PError::Default("Failed getting HSM info".to_string()));
            }
            Ok(info.into())
        }
    }
}

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
    fn instantiate<P>(path: P) -> PResult<Self>
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

    fn initialize(hsm_lib: &HsmLib) -> PResult<()> {
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
                PError::Default("C_Initialize not available on library".to_string())
            })?(&pInitArgs as *const CK_C_INITIALIZE_ARGS as CK_VOID_PTR);
            if rv != CKR_OK {
                return Err(PError::Default("Failed initializing the HSM".to_string()));
            }
            Ok(())
        }
    }

    fn finalize(&self) -> PResult<()> {
        unsafe {
            let rv = self.C_Finalize.ok_or_else(|| {
                PError::Default("C_Finalize not available on library".to_string())
            })?(ptr::null_mut());
            if rv != CKR_OK {
                return Err(PError::Default("Failed to finalize the HSM".to_string()));
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

pub struct Info {
    pub cryptokiVersion: (u8, u8),
    pub manufacturerID: String,
    pub flags: u64,
    pub libraryDescription: String,
    pub libraryVersion: (u8, u8),
}

impl From<CK_INFO> for Info {
    fn from(info: CK_INFO) -> Self {
        #[cfg(target_os = "windows")]
        let flags = u64::from(info.flags);
        #[cfg(not(target_os = "windows"))]
        let flags = info.flags;
        Info {
            cryptokiVersion: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
            manufacturerID: CStr::from_bytes_until_nul(&info.manufacturerID)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            flags,
            libraryDescription: CStr::from_bytes_until_nul(&info.libraryDescription)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            libraryVersion: (info.libraryVersion.major, info.libraryVersion.minor),
        }
    }
}

impl Display for Info {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cryptoki Version: {}.{}\nManufacturer ID: {}\nFlags: {}\nLibrary Description: \
             {}\nLibrary Version: {}.{}",
            self.cryptokiVersion.0,
            self.cryptokiVersion.1,
            self.manufacturerID,
            self.flags,
            self.libraryDescription,
            self.libraryVersion.0,
            self.libraryVersion.1
        )
    }
}
