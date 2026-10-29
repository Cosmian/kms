use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use cosmian_kms_interfaces::CryptoAlgorithm;
use cosmian_logger::debug;
#[cfg(feature = "non-fips")]
use pkcs11_sys::CKM_SHA_1;
use pkcs11_sys::{
    CK_MECHANISM_TYPE, CKF_DECRYPT, CKF_ENCRYPT, CKF_UNWRAP, CKF_WRAP, CKM_AES_CBC, CKM_AES_GCM,
    CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, CKM_AES_KEY_WRAP_PAD, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
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

#[cfg(not(feature = "non-fips"))]
fn add_supported_oaep_algorithms(
    supported_hashes: &[pkcs11_sys::CK_MECHANISM_TYPE],
    algorithms: &mut Vec<CryptoAlgorithm>,
) {
    if supported_hashes.contains(&CKM_SHA256) {
        algorithms.push(CryptoAlgorithm::RsaOaepSha256);
    }
}

#[cfg(feature = "non-fips")]
fn add_supported_oaep_algorithms(
    supported_hashes: &[pkcs11_sys::CK_MECHANISM_TYPE],
    algorithms: &mut Vec<CryptoAlgorithm>,
) {
    if supported_hashes.contains(&CKM_SHA_1) {
        algorithms.push(CryptoAlgorithm::RsaOaepSha1);
    }
    if supported_hashes.contains(&CKM_SHA256) {
        algorithms.push(CryptoAlgorithm::RsaOaepSha256);
    }
}

/// Query a slot's supported cryptographic algorithms, computed once per slot and cached.
pub(crate) fn algorithms_for_slot(slot: &SlotManager) -> HResult<Vec<CryptoAlgorithm>> {
    if let Some(algorithms) = slot.supported_algorithms.get() {
        return Ok(algorithms.clone());
    }
    let mechanisms = slot.get_supported_mechanisms()?;
    let session = slot.open_session(true)?;
    let supported_hashes = session.get_supported_oaep_hash()?;
    let mut algorithms = Vec::new();
    let kwp_pad_is_rfc5649 = slot.capabilities().aes_key_wrap_pad_is_rfc5649;

    for &mechanism in &mechanisms {
        match mechanism {
            CKM_AES_CBC => algorithms.push(CryptoAlgorithm::AesCbc),
            CKM_AES_GCM => algorithms.push(CryptoAlgorithm::AesGcm),
            CKM_RSA_PKCS => algorithms.push(CryptoAlgorithm::RsaPkcsV15),
            CKM_RSA_PKCS_OAEP => {
                add_supported_oaep_algorithms(&supported_hashes, &mut algorithms);
            }
            CKM_AES_KEY_WRAP => push_once(&mut algorithms, CryptoAlgorithm::AesKeyWrap),
            CKM_AES_KEY_WRAP_KWP => push_once(&mut algorithms, CryptoAlgorithm::AesKeyWrapPad),
            CKM_AES_KEY_WRAP_PAD if kwp_pad_is_rfc5649 => {
                push_once(&mut algorithms, CryptoAlgorithm::AesKeyWrapPad);
            }
            _ => {}
        }
    }

    // A concurrent first call may have filled the cache already: both results are identical.
    Ok(slot.supported_algorithms.get_or_init(|| algorithms).clone())
}

fn push_once(algorithms: &mut Vec<CryptoAlgorithm>, algorithm: CryptoAlgorithm) {
    if !algorithms.contains(&algorithm) {
        algorithms.push(algorithm);
    }
}

/// PKCS#11 mechanism and API used for AES-KW/AES-KWP on a slot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AesKeyWrapMechanism {
    pub(crate) mechanism: CK_MECHANISM_TYPE,
    /// `true`: single-part `C_Encrypt`/`C_Decrypt`; `false`: `C_WrapKey`/`C_UnwrapKey` via an
    /// ephemeral session object.
    pub(crate) single_part: bool,
}

/// Pick the AES-KW/KWP mechanism for `algorithm` on `slot`, preferring single-part
/// encrypt/decrypt and falling back to `C_WrapKey`/`C_UnwrapKey`.
pub(crate) fn aes_key_wrap_mechanism(
    slot: &SlotManager,
    slot_id: usize,
    algorithm: &CryptoAlgorithm,
    unwrap: bool,
) -> HResult<AesKeyWrapMechanism> {
    let candidates: &[CK_MECHANISM_TYPE] = match algorithm {
        CryptoAlgorithm::AesKeyWrap => &[CKM_AES_KEY_WRAP],
        CryptoAlgorithm::AesKeyWrapPad if slot.capabilities().aes_key_wrap_pad_is_rfc5649 => {
            &[CKM_AES_KEY_WRAP_KWP, CKM_AES_KEY_WRAP_PAD]
        }
        CryptoAlgorithm::AesKeyWrapPad => &[CKM_AES_KEY_WRAP_KWP],
        _ => return Err(HError::Default("not an AES key-wrap algorithm".to_owned())),
    };
    let (op_flag, key_flag, op) = if unwrap {
        (CKF_DECRYPT, CKF_UNWRAP, "decrypt/unwrap")
    } else {
        (CKF_ENCRYPT, CKF_WRAP, "encrypt/wrap")
    };
    for &mechanism in candidates {
        let Ok(info) = slot.get_mechanism_info(mechanism) else {
            continue;
        };
        let single_part = info.flags & op_flag != 0;
        if !single_part && info.flags & key_flag == 0 {
            return Err(HError::Default(format!(
                "mechanism {mechanism:#x} supports neither single-part nor key {op} on this slot"
            )));
        }
        return Ok(AesKeyWrapMechanism {
            mechanism,
            single_part,
        });
    }
    Err(HError::Default(format!(
        "{algorithm:?} is not offered by HSM slot {slot_id}"
    )))
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
        let capabilities = P::capabilities();
        let hsm_lib = Arc::new(HsmLib::instantiate_with_options(
            path,
            capabilities.skip_finalize_on_drop,
        )?);
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
        if let Some(slot_state) = slots.get_mut(&slot_id) {
            if let Some(slot) = &slot_state.slot {
                debug!("Reusing slot {slot_id}");
                Ok(slot.clone())
            } else {
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
        for k in slots.keys() {
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
        algorithms_for_slot(&slot)
    }
}
