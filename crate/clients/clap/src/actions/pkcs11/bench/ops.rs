//! Thin wrappers around `cosmian_kms_base_hsm` for the PKCS#11 benchmark's session
//! pool and the one op family (key creation) whose object handle must be torn down
//! inside the same call. Every other op (`encrypt`/`decrypt`/`sign`/`verify`) is
//! driven directly through `cosmian_kms_base_hsm::Session` in `load.rs`.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cosmian_kms_base_hsm::{AesKeySize, HsmLib, SlotManager, hsm_capabilities::HsmCapabilities};
use pkcs11_sys::CK_OBJECT_HANDLE;

use super::error::BenchResult;

/// The provider exposes exactly one slot, `SLOT_ID = 1`
/// (`crate/clients/pkcs11/module/src/pkcs11.rs`).
pub(crate) const PROVIDER_SLOT_ID: usize = 1;

/// Process-wide monotonic counter suffixing every `generate_and_destroy_key` label,
/// so concurrent worker threads never request the same KMIP `unique_identifier` for
/// two simultaneously-live ephemeral keys.
static NEXT_KEY_CREATION_ID: AtomicU64 = AtomicU64::new(0);

/// The benchmark's session pool plus the objects that keep the loaded library alive.
///
/// Field order matters: `sessions` drop before the slot manager, which drops before
/// `_lib` (whose `Drop` calls `C_Finalize`).
pub(crate) struct BenchPool {
    pub(crate) sessions: Vec<cosmian_kms_base_hsm::Session>,
    _slot: SlotManager,
    _lib: Arc<HsmLib>,
}

/// Loads the provider at `dll`, logs in once with an empty PIN, and opens
/// `pool_size` un-logged worker sessions (the provider's login is process-global,
/// so un-logged sessions are authorised after the single `C_Login`).
pub(crate) fn open_pool(
    dll: &Path,
    pool_size: usize,
    hsm_prefix: Option<&Arc<str>>,
) -> BenchResult<BenchPool> {
    let lib = Arc::new(HsmLib::instantiate(dll)?);
    // Reproduces the old split: delegated (`--delegated`) uses v3 message AES-GCM,
    // software keys use classic `C_Encrypt` with `CKM_AES_GCM`
    // (`supports_aes_gcm_caller_iv` stays `true`).
    let caps = HsmCapabilities {
        supports_aes_gcm_message: hsm_prefix.is_some(),
        ..HsmCapabilities::default()
    };
    let slot = SlotManager::instantiate(lib.clone(), PROVIDER_SLOT_ID, Some(String::new()), caps)?;
    let sessions = (0..pool_size)
        .map(|_| slot.open_session(true))
        .collect::<cosmian_kms_base_hsm::HResult<Vec<_>>>()?;
    Ok(BenchPool {
        sessions,
        _slot: slot,
        _lib: lib,
    })
}

/// Resolves a benchmark key by its KMIP unique identifier (`CKA_ID` then
/// `CKA_LABEL`; KMIP uids are unique per object, so no class filter is needed).
pub(crate) fn find(
    session: &cosmian_kms_base_hsm::Session,
    id: &str,
) -> BenchResult<CK_OBJECT_HANDLE> {
    Ok(session.get_object_handle(id.as_bytes())?)
}

/// Generates an ephemeral AES-128 secret key and immediately destroys it, removing
/// its cached handle so the provider's object store does not grow unboundedly.
pub(crate) fn generate_and_destroy_key(
    session: &cosmian_kms_base_hsm::Session,
    hsm_prefix: Option<&str>,
) -> BenchResult<()> {
    let key_name = format!(
        "pkcs11-bench-key-creation-{}",
        NEXT_KEY_CREATION_ID.fetch_add(1, Ordering::Relaxed)
    );
    let label = match hsm_prefix {
        Some(prefix) => format!("{prefix}::{key_name}"),
        None => key_name,
    };
    let handle = session.generate_aes_key(label.as_bytes(), AesKeySize::Aes128, true, None)?;
    session.destroy_object(handle)?;
    session.delete_object_handle(label.as_bytes())?;
    Ok(())
}
