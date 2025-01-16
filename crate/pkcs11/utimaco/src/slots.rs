use std::{
    num::NonZeroUsize,
    ptr,
    sync::{Arc, Mutex},
};

use lru::LruCache;
use pkcs11_sys::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKR_USER_ALREADY_LOGGED_IN, CKU_USER, CK_FLAGS,
    CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG, CK_UTF8CHAR_PTR,
};
use tracing::warn;

use crate::{utimaco::HsmLib, PError, PResult, Session};

pub struct ObjectHandlesCache(Mutex<LruCache<Vec<u8>, CK_OBJECT_HANDLE>>);

impl Default for ObjectHandlesCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectHandlesCache {
    pub fn new() -> Self {
        #[allow(unsafe_code)]
        let max = unsafe { NonZeroUsize::new_unchecked(100) };
        ObjectHandlesCache(Mutex::new(LruCache::new(max)))
    }

    pub fn get(&self, key: &[u8]) -> Option<CK_OBJECT_HANDLE> {
        self.0
            .lock()
            .expect("Proteccio: failed to lock the handles cache")
            .get(key)
            .copied()
    }

    pub fn insert(&self, key: Vec<u8>, value: CK_OBJECT_HANDLE) {
        self.0
            .lock()
            .expect("Proteccio: failed to lock the handles cache")
            .put(key, value);
    }

    pub fn remove(&self, key: &[u8]) {
        self.0
            .lock()
            .expect("Proteccio: failed to lock the handles cache")
            .pop(key);
    }
}

pub struct SlotManager {
    hsm_lib: Arc<HsmLib>,
    slot_id: usize,
    object_handles_cache: Arc<ObjectHandlesCache>,
    _login_session: Option<Session>,
}

impl SlotManager {
    pub fn instantiate(
        hsm_lib: Arc<HsmLib>,
        slot_id: usize,
        login_password: Option<String>,
    ) -> PResult<Self> {
        let object_handles_cache = Arc::new(ObjectHandlesCache::new());
        if let Some(password) = login_password {
            let login_session = Self::open_session_(
                &hsm_lib,
                slot_id,
                false,
                object_handles_cache.clone(),
                Some(password),
            )?;
            Ok(SlotManager {
                hsm_lib,
                slot_id,
                object_handles_cache,
                _login_session: Some(login_session),
            })
        } else {
            Ok(SlotManager {
                hsm_lib,
                slot_id,
                object_handles_cache,
                _login_session: None,
            })
        }
    }

    pub fn open_session(&self, read_write: bool) -> PResult<Session> {
        Self::open_session_(
            &self.hsm_lib,
            self.slot_id,
            read_write,
            self.object_handles_cache.clone(),
            None,
        )
    }

    fn open_session_(
        hsm_lib: &Arc<HsmLib>,
        slot_id: usize,
        read_write: bool,
        object_handles_cache: Arc<ObjectHandlesCache>,
        login_password: Option<String>,
    ) -> PResult<Session> {
        let slot_id: CK_SLOT_ID = slot_id as CK_SLOT_ID;
        let flags: CK_FLAGS = if read_write {
            CKF_RW_SESSION | CKF_SERIAL_SESSION
        } else {
            CKF_SERIAL_SESSION
        };
        let mut session_handle: CK_SESSION_HANDLE = 0;

        unsafe {
            let rv = hsm_lib.C_OpenSession.ok_or_else(|| {
                PError::Default("C_OpenSession not available on library".to_string())
            })?(slot_id, flags, ptr::null_mut(), None, &mut session_handle);
            if rv != CKR_OK {
                return Err(PError::Default(format!(
                    "Proteccio: Failed opening a session: {rv}å"
                )));
            }
            if let Some(password) = login_password.as_ref() {
                let mut pwd_bytes = password.as_bytes().to_vec();
                let rv = hsm_lib.C_Login.ok_or_else(|| {
                    PError::Default("C_Login not available on library".to_string())
                })?(
                    session_handle,
                    CKU_USER,
                    pwd_bytes.as_mut_ptr() as CK_UTF8CHAR_PTR,
                    pwd_bytes.len() as CK_ULONG,
                );
                if rv == CKR_USER_ALREADY_LOGGED_IN {
                    warn!("user already logged in, ignoring logging");
                } else if rv != CKR_OK {
                    return Err(PError::Default("Failed logging in".to_string()));
                }
            }
            Ok(Session::new(
                hsm_lib.clone(),
                session_handle,
                object_handles_cache,
                login_password.is_some(),
            ))
        }
    }
}
