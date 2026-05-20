/// Key context and per-key CNG KSP operations.
///
/// A `CngKeyCtx` is heap-allocated and its address is cast to an
/// `NCRYPT_KEY_HANDLE` (opaque `isize`) returned to Windows CNG.
/// The provider validates the handle before dereferencing it.
use std::sync::Arc;

use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kms_client::KmsClient;
use cosmian_logger::debug;

use crate::{
    backend,
    blob::{EcCurve, ec_public_blob_from_spki_der, rsa_public_blob_from_spki_der},
    error::{KspError, KspResult},
};

// ─── Key algorithm ────────────────────────────────────────────────────────────

/// Algorithm families supported by this KSP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa { bits: u32 },
    Ec { curve: EcCurve },
}

impl KeyAlgorithm {
    /// Return the CNG algorithm identifier wide string (e.g. `"RSA"`, `"ECDSA_P256"`).
    #[must_use]
    pub fn cng_alg_id(&self) -> &'static str {
        match self {
            Self::Rsa { .. } => "RSA",
            Self::Ec { curve } => match curve {
                EcCurve::P256 => "ECDSA_P256",
                EcCurve::P384 => "ECDSA_P384",
                EcCurve::P521 => "ECDSA_P521",
            },
        }
    }

    /// Parse from the CNG algorithm name supplied to `CreatePersistedKey`.
    pub fn from_cng_name(name: &str, bits: u32) -> KspResult<Self> {
        match name.to_ascii_uppercase().as_str() {
            "RSA" => {
                let bits = if bits == 0 { 2048 } else { bits };
                Ok(Self::Rsa { bits })
            }
            "ECDSA_P256" | "ECDH_P256" => Ok(Self::Ec {
                curve: EcCurve::P256,
            }),
            "ECDSA_P384" | "ECDH_P384" => Ok(Self::Ec {
                curve: EcCurve::P384,
            }),
            "ECDSA_P521" | "ECDH_P521" => Ok(Self::Ec {
                curve: EcCurve::P521,
            }),
            other => Err(KspError::AlgorithmNotSupported(other.to_owned())),
        }
    }
}

// ─── Key usage flags ─────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Key usage flags as defined by `NCRYPT_KEY_USAGE_PROPERTY`.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct KeyUsage: u32 {
        const DECRYPT      = 0x0000_0001;
        const SIGN         = 0x0000_0002;
        const KEY_AGREEMENT= 0x0000_0004;
    }
}

/// Export policy flags (NCRYPT_EXPORT_POLICY_PROPERTY).
#[derive(Clone, Copy, Debug, Default)]
pub struct ExportPolicy {
    pub allow_export: bool,
    pub allow_plaintext_export: bool,
}

// ─── Pending creation parameters (before FinalizeKey) ────────────────────────

/// Parameters accumulated during `CreatePersistedKey` / `SetKeyProperty` and
/// consumed by `FinalizeKey` to actually create the key in the KMS.
#[derive(Clone, Debug)]
pub struct PendingCreation {
    pub algorithm: KeyAlgorithm,
    pub key_name: String,
    pub usage: KeyUsage,
    pub export_policy: ExportPolicy,
}

// ─── Key state ───────────────────────────────────────────────────────────────

/// State of a key context.
#[derive(Debug)]
pub enum KeyState {
    /// Key has been created on the KMS; `priv_uid` is the KMS UUID of the
    /// private key, `pub_uid` the public key's UUID.
    Persisted {
        priv_uid: String,
        pub_uid: Option<String>,
        algorithm: KeyAlgorithm,
        key_name: String,
        usage: KeyUsage,
        export_policy: ExportPolicy,
    },
    /// Key was requested via `CreatePersistedKey` but `FinalizeKey` has not
    /// yet been called.
    Pending(PendingCreation),
}

// ─── Key context ─────────────────────────────────────────────────────────────

/// Magic number stored in `CngKeyCtx` so we can validate handles before use.
pub const KEY_CTX_MAGIC: u32 = 0x0C05_1AAC; // "COSMIANAC"

/// Heap-allocated key context.  Its address is used as `NCRYPT_KEY_HANDLE`.
pub struct CngKeyCtx {
    /// Guard against stale / bogus handles.
    pub magic: u32,
    /// Shared KMS client (owned by the provider context).
    pub client: Arc<KmsClient>,
    /// The key state.
    pub state: KeyState,
}

impl CngKeyCtx {
    /// Create a new context for a key that is already persisted in the KMS.
    // Box is intentional: the context is passed to Windows as a raw handle via Box::into_raw.
    #[allow(clippy::unnecessary_box_returns)]
    pub fn new_persisted(
        client: Arc<KmsClient>,
        priv_uid: String,
        pub_uid: Option<String>,
        algorithm: KeyAlgorithm,
        key_name: String,
        usage: KeyUsage,
        export_policy: ExportPolicy,
    ) -> Box<Self> {
        #[allow(clippy::box_default)]
        Box::new(Self {
            magic: KEY_CTX_MAGIC,
            client,
            state: KeyState::Persisted {
                priv_uid,
                pub_uid,
                algorithm,
                key_name,
                usage,
                export_policy,
            },
        })
    }

    /// Create a new context for a key that is pending creation.
    // Box is intentional: the context is passed to Windows as a raw handle via Box::into_raw.
    #[allow(clippy::unnecessary_box_returns)]
    pub fn new_pending(client: Arc<KmsClient>, pending: PendingCreation) -> Box<Self> {
        #[allow(clippy::box_default)]
        Box::new(Self {
            magic: KEY_CTX_MAGIC,
            client,
            state: KeyState::Pending(pending),
        })
    }

    /// Validate that a raw pointer is a valid `CngKeyCtx`.
    ///
    /// # Safety
    /// The caller must ensure the pointer was produced by `Box::into_raw` and
    /// has not been freed.
    pub unsafe fn from_handle(handle: usize) -> KspResult<&'static mut Self> {
        if handle == 0 {
            return Err(KspError::InvalidHandle);
        }
        #[allow(clippy::as_conversions)]
        let ptr = handle as *mut Self;
        // SAFETY: caller guarantees this came from Box::into_raw
        let ctx = unsafe { &mut *ptr };
        if ctx.magic != KEY_CTX_MAGIC {
            return Err(KspError::InvalidHandle);
        }
        Ok(ctx)
    }

    /// Consume the context and free it.
    ///
    /// # Safety
    /// The caller must ensure the handle was produced by `Box::into_raw`
    /// and that no other reference to it exists.
    pub unsafe fn free(handle: usize) {
        if handle == 0 {
            return;
        }
        #[allow(clippy::as_conversions)]
        let ptr = handle as *mut Self;
        // SAFETY: caller guarantees this came from Box::into_raw
        let mut ctx = unsafe { Box::from_raw(ptr) };
        ctx.magic = 0; // invalidate before drop
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    pub fn priv_uid(&self) -> KspResult<&str> {
        match &self.state {
            KeyState::Persisted { priv_uid, .. } => Ok(priv_uid.as_str()),
            KeyState::Pending(_) => Err(KspError::InvalidParameter(
                "Key not yet finalized".to_owned(),
            )),
        }
    }

    /// Returns the public key UID (falls back to private key UID).
    pub fn pub_uid(&self) -> KspResult<&str> {
        match &self.state {
            KeyState::Persisted {
                pub_uid: Some(uid), ..
            } => Ok(uid.as_str()),
            KeyState::Persisted { priv_uid, .. } => Ok(priv_uid.as_str()),
            KeyState::Pending(_) => Err(KspError::InvalidParameter(
                "Key not yet finalized".to_owned(),
            )),
        }
    }

    pub fn key_name(&self) -> &str {
        match &self.state {
            KeyState::Persisted { key_name, .. }
            | KeyState::Pending(PendingCreation { key_name, .. }) => key_name.as_str(),
        }
    }

    pub fn algorithm(&self) -> &KeyAlgorithm {
        match &self.state {
            KeyState::Persisted { algorithm, .. }
            | KeyState::Pending(PendingCreation { algorithm, .. }) => algorithm,
        }
    }

    pub fn usage(&self) -> KeyUsage {
        match &self.state {
            KeyState::Persisted { usage, .. }
            | KeyState::Pending(PendingCreation { usage, .. }) => *usage,
        }
    }

    pub fn export_policy(&self) -> ExportPolicy {
        match &self.state {
            KeyState::Persisted { export_policy, .. }
            | KeyState::Pending(PendingCreation { export_policy, .. }) => *export_policy,
        }
    }

    // ── Operations ────────────────────────────────────────────────────────

    /// Finalize key creation: create the key pair in the KMS and transition
    /// from `Pending` to `Persisted`.
    pub fn finalize(&mut self) -> KspResult<()> {
        let pending = match &self.state {
            KeyState::Persisted { .. } => {
                // Already finalized — idempotent
                return Ok(());
            }
            KeyState::Pending(p) => p.clone(),
        };

        let (priv_uid, pub_uid) = match &pending.algorithm {
            KeyAlgorithm::Rsa { bits } => {
                let use_sign = pending.usage.contains(KeyUsage::SIGN);
                backend::create_rsa_key_pair(&self.client, &pending.key_name, *bits, use_sign)?
            }
            KeyAlgorithm::Ec { curve } => {
                use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_types::RecommendedCurve;
                let kms_curve = match curve {
                    EcCurve::P256 => RecommendedCurve::P256,
                    EcCurve::P384 => RecommendedCurve::P384,
                    EcCurve::P521 => RecommendedCurve::P521,
                };
                backend::create_ec_key_pair(&self.client, &pending.key_name, kms_curve)?
            }
        };

        debug!(
            "CNG KSP: finalized key '{}' → priv={}, pub={}",
            pending.key_name, priv_uid, pub_uid
        );

        self.state = KeyState::Persisted {
            priv_uid,
            pub_uid: Some(pub_uid),
            algorithm: pending.algorithm,
            key_name: pending.key_name,
            usage: pending.usage,
            export_policy: pending.export_policy,
        };
        Ok(())
    }

    /// Export the public key as a `BCRYPT_RSAKEY_BLOB` or `BCRYPT_ECCKEY_BLOB`.
    pub fn export_public_blob(&self) -> KspResult<Vec<u8>> {
        let (pub_uid, alg) = match &self.state {
            KeyState::Persisted {
                pub_uid: Some(uid),
                algorithm,
                ..
            } => (uid.as_str(), algorithm),
            KeyState::Persisted {
                pub_uid: None,
                priv_uid,
                algorithm,
                ..
            } => (priv_uid.as_str(), algorithm),
            KeyState::Pending(_) => {
                return Err(KspError::InvalidParameter(
                    "Key not yet finalized".to_owned(),
                ));
            }
        };

        let spki_der = backend::export_public_key_spki(&self.client, pub_uid)?;
        match alg {
            KeyAlgorithm::Rsa { .. } => rsa_public_blob_from_spki_der(&spki_der),
            KeyAlgorithm::Ec { .. } => ec_public_blob_from_spki_der(&spki_der, true),
        }
    }
}
