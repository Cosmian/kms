use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use cosmian_kms_interfaces::CryptoAlgorithm;
use cosmian_logger::debug;
use pkcs11_sys::{
    CKM_AES_CBC, CKM_AES_GCM, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_SHA_1, CKM_SHA256,
};

use crate::{
    HError, HResult, SlotManager,
    error::HResultHelper,
    hsm_capabilities::{HsmCapabilities, HsmProvider},
    hsm_lib::HsmLib,
};

pub struct DefaultCapabilityProvider;
impl HsmProvider for DefaultCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities::default()
    }
}

struct SlotState {
    password: Option<String>,
    slot: Option<Arc<SlotManager>>,
}

pub struct BaseHsm<P: HsmProvider = DefaultCapabilityProvider> {
    hsm_lib: Arc<HsmLib>,
    slots: Mutex<HashMap<usize, SlotState>>,
    _provider: PhantomData<P>,
}

impl<P: HsmProvider> BaseHsm<P> {
    /// Get a reference to the underlying `HsmLib` for direct PKCS#11 function calls.
    pub const fn hsm_lib(&self) -> &Arc<HsmLib> {
        &self.hsm_lib
    }

    pub fn instantiate<Pth: AsRef<std::ffi::OsStr>>(
        path: Pth,
        passwords: HashMap<usize, Option<String>>,
    ) -> HResult<Self> {
        debug!("Using PKCS#11 library with {:?}", P::capabilities());
        let hsm_lib = Arc::new(HsmLib::instantiate(path)?);
        let mut slots = HashMap::with_capacity(passwords.len());
        for (k, v) in passwords {
            slots.insert(
                k,
                SlotState {
                    password: v,
                    slot: None,
                },
            );
        }
        Ok(Self {
            hsm_lib,
            slots: Mutex::new(slots),
            _provider: PhantomData,
        })
    }

    /// Get a slot
    /// If a slot has already been opened, returns the opened slot.
    /// To close a slot before re-opening it with another password, call `close_slot()` first
    pub fn get_slot(&self, slot_id: usize) -> HResult<Arc<SlotManager>> {
        let mut slots = self
            .slots
            .lock()
            .context("Failed to acquire lock on slots")?;
        // check if we are supposed to use that slot
        if let Some(slot_state) = slots.get_mut(&slot_id) {
            if let Some(s) = &slot_state.slot {
                debug!("Reusing slot {slot_id}");
                Ok(s.clone())
            } else {
                // instantiate a new slot
                let manager = Arc::new(SlotManager::instantiate(
                    self.hsm_lib.clone(),
                    slot_id,
                    slot_state.password.clone(),
                    P::capabilities(),
                )?);
                slot_state.slot = Some(manager.clone());
                Ok(manager)
            }
        } else {
            Err(HError::Default(format!("slot {slot_id} is not accessible")))
        }
    }

    pub fn close_slot(&self, slot_id: usize) -> HResult<()> {
        let mut slots = self
            .slots
            .lock()
            .context("Failed to acquire lock on slots")?;
        slots.remove(&slot_id);
        Ok(())
    }

    /// Retrieve the list of slot identifiers for the HSM.
    ///
    /// This function returns the IDs of all slots that the HSM has been
    /// initialized with, typically from configuration.
    ///
    /// # Returns
    /// * A result containing the available slot identifiers
    ///
    /// # Errors
    /// * Returns an error if the internal slot list cannot be accessed
    ///   due to a locking failure.
    ///
    /// # Notes
    /// This function acquires a lock on the internal slot list to ensure
    /// thread-safe access.
    ///
    /// This function does not return any passwords.
    pub fn get_available_slot_list(&self) -> HResult<Vec<usize>> {
        let slots = self
            .slots
            .lock()
            .context("Failed to acquire lock on slots")?;
        let mut slot_list = Vec::with_capacity(slots.len());
        for (k, _v) in slots.iter() {
            slot_list.push(*k);
        }
        Ok(slot_list)
    }

    /// Retrieve the list of supported cryptographic algorithms for a given HSM slot.
    ///
    /// This function queries the specified slot to determine which algorithms are available
    /// for cryptographic operations. It maps the raw PKCS#11 mechanism identifiers into
    /// the appropriate `CryptoAlgorithm` variants.
    ///
    /// The function checks both general mechanisms (such as AES CBC, AES GCM or RSA PKCS)
    /// and mechanism-specific capabilities (such as supported hash functions for RSA OAEP).
    ///
    /// # Arguments
    /// * `slot_id` - The identifier of the HSM slot to query.
    ///
    /// # Returns
    /// * `HResult<Vec<CryptoAlgorithm>>` - A result containing a vector of supported
    ///   `CryptoAlgorithm` variants.
    ///
    /// # Errors
    /// * Returns an error if the specified slot can't be accessed.
    /// * Returns an error if the list of supported mechanisms can't be retrieved.
    /// * Returns an error if the supported OAEP hashing algorithms can't be determined.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions from the HSM library to query mechanism information.
    pub fn get_algorithms(&self, slot_id: usize) -> HResult<Vec<CryptoAlgorithm>> {
        let slot = self.get_slot(slot_id)?;
        let mechanisms = slot.get_supported_mechanisms()?;
        let session = slot.open_session(true)?;
        let supported_hashes = session.get_supported_oaep_hash()?;
        let mut algorithms = Vec::new();

        for &mechanism in &mechanisms {
            match mechanism {
                CKM_AES_CBC => algorithms.push(CryptoAlgorithm::AesCbc),
                CKM_AES_GCM => algorithms.push(CryptoAlgorithm::AesGcm),
                CKM_RSA_PKCS => algorithms.push(CryptoAlgorithm::RsaPkcsV15),
                CKM_RSA_PKCS_OAEP => {
                    if supported_hashes.contains(&CKM_SHA_1) {
                        algorithms.push(CryptoAlgorithm::RsaOaepSha1);
                    }
                    if supported_hashes.contains(&CKM_SHA256) {
                        algorithms.push(CryptoAlgorithm::RsaOaepSha256);
                    }
                }
                _ => {}
            }
        }

        Ok(algorithms)
    }
}
