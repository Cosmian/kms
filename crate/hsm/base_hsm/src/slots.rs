use std::{
    num::NonZeroUsize,
    ptr,
    sync::{Arc, Mutex},
};

use cosmian_logger::{info, warn};
use lru::LruCache;
use pkcs11_sys::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKR_USER_ALREADY_LOGGED_IN, CKU_USER,
    CK_FLAGS, CK_MECHANISM_INFO, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID,
    CK_ULONG,
};

use crate::{
    hsm_call, hsm_capabilities::HsmCapabilities, hsm_lib::HsmLib, HError, HResult, Session,
};

/// A cache structure that maps byte vectors to `CK_OBJECT_HANDLE` values using an LRU (Least Recently Used) strategy.
///
/// This struct wraps a mutex-protected LRU cache that associates object identifiers (as byte vectors)
/// with their corresponding PKCS#11 object handles. The cache helps improve performance by reducing
/// repeated lookups of frequently used objects.
///
/// The LRU cache automatically removes the least recently accessed entries when it reaches its capacity,
/// helping to manage memory usage while maintaining quick access to frequently used handles.
pub struct ObjectHandlesCache(Mutex<LruCache<Vec<u8>, CK_OBJECT_HANDLE>>);

impl Default for ObjectHandlesCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectHandlesCache {
    #[must_use]
    pub fn new() -> Self {
        #[expect(unsafe_code)]
        let max = unsafe { NonZeroUsize::new_unchecked(100) };
        Self(Mutex::new(LruCache::new(max)))
    }

    /// Get the object handle for the specified key.
    pub fn get(&self, key: &[u8]) -> HResult<Option<CK_OBJECT_HANDLE>> {
        Ok(self
            .0
            .lock()
            .map_err(|e| {
                HError::Default(format!(
                    "Failed to acquire lock on object handle cache: {e}"
                ))
            })?
            .get(key)
            .copied())
    }

    /// Insert a new object handle into the cache.
    pub fn insert(&self, key: Vec<u8>, value: CK_OBJECT_HANDLE) -> HResult<()> {
        self.0
            .lock()
            .map_err(|e| {
                HError::Default(format!(
                    "Failed to acquire lock on object handle cache: {e}"
                ))
            })?
            .put(key, value);
        Ok(())
    }

    /// Remove an object handle from the cache.
    pub fn remove(&self, key: &[u8]) -> HResult<()> {
        self.0
            .lock()
            .map_err(|e| {
                HError::Default(format!(
                    "Failed to acquire lock on object handle cache: {e}"
                ))
            })?
            .pop(key);
        Ok(())
    }

    /// Remove all object handles from the cache.
    pub fn clear(&self) -> HResult<()> {
        self.0
            .lock()
            .map_err(|e| {
                HError::Default(format!(
                    "Failed to acquire lock on object handle cache: {e}"
                ))
            })?
            .clear();
        Ok(())
    }
}

/// A manager for a specific PKCS#11 slot in a Hardware Security Module (HSM).
///
/// This structure maintains the connection to a specific slot within an HSM,
/// managing the slot's session and object handles.
///
/// # Fields
///
/// * `hsm_lib` - A thread-safe reference to the HSM library interface
/// * `slot_id` - The unique identifier for this HSM slot
/// * `object_handles_cache` - A thread-safe cache of object handles for this slot
/// * `supported_oaep_hash_cache` - A thread-safe cache of supported hashing algorithms for rsa oaep
/// * `_login_session` - An optional authenticated session with the HSM slot
///
/// The `SlotManager` is responsible for coordinating operations on a specific HSM slot,
/// including session management and object handle caching.
pub struct SlotManager {
    hsm_lib: Arc<HsmLib>,
    slot_id: usize,
    object_handles_cache: Arc<ObjectHandlesCache>,
    supported_oaep_hash_cache: Arc<Mutex<Option<Vec<CK_MECHANISM_TYPE>>>>,
    _login_session: Option<Session>,
    hsm_capabilities: HsmCapabilities,
}

impl SlotManager {
    /// Create a new `SlotManager` instance for the specified slot.
    /// If a login password is provided, the HSM will authenticate the slot.
    ///
    /// # Arguments
    /// * `hsm_lib` - A thread-safe reference to the HSM library interface.
    /// * `slot_id` - The unique identifier for this HSM slot.
    /// * `login_password` - An optional password to authenticate the slot.
    ///
    /// # Returns
    /// * `PResult<SlotManager>` - A result containing the `SlotManager` instance.
    ///
    /// # Errors
    /// * An error is returned if the slot cannot be opened or authenticated.
    /// * An error is returned if the HSM library does not support the necessary functions.
    /// * If the HSM returns an error during session creation or login, an error is returned.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions from the HSM library to open a session and authenticate the slot.
    /// The function is safe to call, but care must be taken when using the resulting `SlotManager` instance.
    pub fn instantiate(
        hsm_lib: Arc<HsmLib>,
        slot_id: usize,
        login_password: Option<String>,
        hsm_capabilities: HsmCapabilities,
    ) -> HResult<Self> {
        let object_handles_cache = Arc::new(ObjectHandlesCache::new());
        let supported_oaep_hash_cache = Arc::new(Mutex::new(None));
        if let Some(password) = login_password {
            let login_session = Self::open_session_(
                &hsm_lib,
                slot_id,
                false,
                object_handles_cache.clone(),
                supported_oaep_hash_cache.clone(),
                if password.is_empty() {
                    None
                } else {
                    Some(&password)
                },
                hsm_capabilities.clone(),
            )?;
            Ok(Self {
                hsm_lib,
                slot_id,
                object_handles_cache,
                supported_oaep_hash_cache,
                _login_session: Some(login_session),
                hsm_capabilities,
            })
        } else {
            Ok(Self {
                hsm_lib,
                slot_id,
                object_handles_cache,
                supported_oaep_hash_cache,
                _login_session: None,
                hsm_capabilities,
            })
        }
    }

    /// Retrieve the list of supported cryptographic mechanisms for this HSM slot.
    ///
    /// This function queries the HSM to determine which mechanisms (such as AES, RSA, or EC algorithms)
    /// are available for cryptographic operations within the specified slot.
    ///
    /// # Returns
    /// * `HResult<Vec<CK_MECHANISM_TYPE>>` - A result containing a vector of mechanism identifiers
    ///   supported by the HSM slot.
    ///
    /// # Errors
    /// * Returns an error if the HSM library does not provide the `C_GetMechanismList` function.
    /// * Returns an error if the HSM call to retrieve the mechanism count fails.
    /// * Returns an error if the HSM call to retrieve the mechanism list fails.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions from the HSM library to query the mechanism list.
    /// The function ensures that memory is correctly allocated and truncated to the number of
    /// mechanisms actually returned by the HSM.
    pub fn get_supported_mechanisms(&self) -> HResult<Vec<CK_MECHANISM_TYPE>> {
        let mut count: CK_ULONG = 0;
        let slot_id: CK_SLOT_ID = CK_SLOT_ID::try_from(self.slot_id)?;
        // Get count of supported mechanisms
        hsm_call!(
            self.hsm_lib,
            "Failed to get mechanism count from HSM",
            C_GetMechanismList,
            slot_id,
            ptr::null_mut(),
            &raw mut count
        );

        // Get mechanism list
        let mut mechanisms = vec![0; usize::try_from(count)?];
        hsm_call!(
            self.hsm_lib,
            "Failed to get mechanism list from HSM",
            C_GetMechanismList,
            slot_id,
            mechanisms.as_mut_ptr(),
            &raw mut count
        );

        mechanisms.truncate(usize::try_from(count)?);
        Ok(mechanisms)
    }

    /// Retrieve detailed information about a specific cryptographic mechanism supported by this HSM slot.
    ///
    /// This function queries the HSM for information about the given mechanisms capabilities, such as
    /// minimum and maximum key sizes, and the supported flags (e.g., whether encryption, decryption,
    /// signing, or verification operations are available).
    ///
    /// # Arguments
    /// * `mech` - The identifier of the mechanism to query.
    ///
    /// # Returns
    /// * `HResult<CK_MECHANISM_INFO>` - A result containing a `CK_MECHANISM_INFO` structure
    ///   with details about the mechanism's capabilities and constraints.
    ///
    /// # Errors
    /// * Returns an error if the HSM library does not provide the `C_GetMechanismInfo` function.
    /// * Returns an error if the HSM call to retrieve the mechanism information fails.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions from the HSM library to query mechanism information.
    pub fn get_mechanism_info(&self, mech: CK_MECHANISM_TYPE) -> HResult<CK_MECHANISM_INFO> {
        let slot_id: CK_SLOT_ID = CK_SLOT_ID::try_from(self.slot_id)?;
        #[expect(unsafe_code)]
        let mut info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
        hsm_call!(
            self.hsm_lib,
            format!("Failed to get mechanism info for {}", mech),
            C_GetMechanismInfo,
            slot_id,
            mech,
            &raw mut info
        );
        Ok(info)
    }

    /// Open a new session with the HSM slot.
    /// The session can be read-only or read-write, depending on the `read_write` parameter.
    /// # Arguments
    /// * `read_write` - A boolean flag indicating whether the session should be read-write.
    ///
    /// # Returns
    /// * `PResult<Session>` - A result containing the new session instance.
    ///
    /// # Errors
    /// * An error is returned if the session cannot be opened.
    /// * An error is returned if the HSM library does not support the necessary functions.
    /// * If the HSM returns an error during session creation, an error is returned.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions from the HSM library to open a session.
    /// The function is safe to call, but care must be taken when using the resulting Session instance.
    /// The session is automatically closed when the Session instance is dropped.
    pub fn open_session(&self, read_write: bool) -> HResult<Session> {
        Self::open_session_(
            &self.hsm_lib,
            self.slot_id,
            read_write,
            self.object_handles_cache.clone(),
            self.supported_oaep_hash_cache.clone(),
            None,
            self.hsm_capabilities.clone(),
        )
    }

    fn open_session_(
        hsm_lib: &Arc<HsmLib>,
        slot_id: usize,
        read_write: bool,
        object_handles_cache: Arc<ObjectHandlesCache>,
        supported_oaep_hash_cache: Arc<Mutex<Option<Vec<CK_MECHANISM_TYPE>>>>,
        login_password: Option<&String>,
        hsm_capabilities: HsmCapabilities,
    ) -> HResult<Session> {
        let slot_id: CK_SLOT_ID = CK_SLOT_ID::try_from(slot_id)?;
        let flags: CK_FLAGS = if read_write {
            CKF_RW_SESSION | CKF_SERIAL_SESSION
        } else {
            CKF_SERIAL_SESSION
        };
        let mut session_handle: CK_SESSION_HANDLE = 0;

        hsm_call!(
            hsm_lib,
            format!("HSM: Failed opening a session on slot: {slot_id}: return code"),
            C_OpenSession,
            slot_id,
            flags,
            ptr::null_mut(),
            None,
            &raw mut session_handle
        );
        let mut pwd_bytes =
            login_password.map_or_else(Vec::new, |password| password.as_bytes().to_vec());

        info!("THE PASSWORD BYTES IS EMPTY? {}", pwd_bytes.is_empty());

        #[expect(unsafe_code)]
        let rv = unsafe {
            hsm_lib
                .C_Login
                .ok_or_else(|| HError::Default("C_Login not available on library".to_owned()))?(
                session_handle,
                CKU_USER,
                if pwd_bytes.is_empty() {
                    ptr::null_mut()
                } else {
                    pwd_bytes.as_mut_ptr()
                },
                CK_ULONG::try_from(pwd_bytes.len())?,
            )
        };
        if rv == CKR_USER_ALREADY_LOGGED_IN {
            warn!("user already logged in, ignoring logging");
        } else if rv != CKR_OK {
            return Err(HError::Default(format!(
                "Failed logging in. Return code: {rv}"
            )));
        }
        Ok(Session::new(
            hsm_lib.clone(),
            session_handle,
            object_handles_cache,
            supported_oaep_hash_cache,
            login_password.is_some(),
            hsm_capabilities,
        ))
    }
}
