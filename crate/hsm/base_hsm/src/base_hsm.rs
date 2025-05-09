use std::{
    collections::HashMap,
    ffi::CStr,
    fmt,
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
};

use cosmian_pkcs11_sys::{CK_INFO, CKR_OK};

use crate::{HError, HResult, SlotManager, hsm_lib::HsmLib};

struct SlotState {
    password: Option<String>,
    slot: Option<Arc<SlotManager>>,
}

pub struct BaseHsm {
    hsm_lib: Arc<HsmLib>,
    slots: Mutex<HashMap<usize, SlotState>>,
}

impl BaseHsm {
    pub fn instantiate<P>(path: P, passwords: HashMap<usize, Option<String>>) -> HResult<Self>
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
        Ok(BaseHsm {
            hsm_lib,
            slots: Mutex::new(slots),
        })
    }

    /// Get a slot
    /// If a slot has already been opened, returns the opened slot.
    /// To close a slot before re-opening it with another password, call `close_slot()` first
    pub fn get_slot(&self, slot_id: usize) -> HResult<Arc<SlotManager>> {
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
            Err(HError::Default(format!("slot {slot_id} is not accessible")))
        }
    }

    pub fn close_slot(&self, slot_id: usize) -> HResult<()> {
        let mut slots = self.slots.lock().expect("failed to lock slots");
        slots.remove(&slot_id);
        Ok(())
    }

    pub fn get_info(&self) -> HResult<Info> {
        unsafe {
            let mut info = CK_INFO::default();
            let rv =
                self.hsm_lib.C_GetInfo.ok_or_else(|| {
                    HError::Default("C_GetInfo not available on library".to_string())
                })?(&mut info);
            if rv != CKR_OK {
                return Err(HError::Default("Failed getting HSM info".to_string()));
            }
            Ok(info.into())
        }
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
