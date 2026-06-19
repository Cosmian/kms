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
    blob::{
        EcCurve, ec_public_blob_from_spki_der, ec_public_blob_from_uncompressed,
        rsa_public_blob_from_pkcs1_der, rsa_public_blob_from_spki_der,
    },
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
    /// If set, contains a raw CNG key blob (e.g. `RSAFULLPRIVATEBLOB`) to be
    /// imported into the KMS instead of generating a new key pair.
    pub import_blob: Option<Vec<u8>>,
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
    /// Vendor identification string for KMIP tag operations.
    pub vendor_id: String,
    /// The key state.
    pub state: KeyState,
}

impl CngKeyCtx {
    /// Create a new context for a key that is already persisted in the KMS.
    // Box is intentional: the context is passed to Windows as a raw handle via Box::into_raw.
    #[allow(clippy::unnecessary_box_returns, clippy::too_many_arguments)]
    pub fn new_persisted(
        client: Arc<KmsClient>,
        vendor_id: String,
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
            vendor_id,
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
    pub fn new_pending(
        client: Arc<KmsClient>,
        vendor_id: String,
        pending: PendingCreation,
    ) -> Box<Self> {
        #[allow(clippy::box_default)]
        Box::new(Self {
            magic: KEY_CTX_MAGIC,
            client,
            vendor_id,
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

        let (priv_uid, pub_uid) = if let Some(blob) = &pending.import_blob {
            // Import key material: detect format and convert to PKCS#8 DER.
            // The blob may be:
            //  - PEM text (from Export-IntunePrivateKey: "-----BEGIN PRIVATE KEY-----")
            //  - Raw PKCS#8 DER (starts with SEQUENCE tag 0x30)
            //  - CNG RSAFULLPRIVATEBLOB (starts with magic "RSA3")
            debug!(
                "CNG KSP: finalize import blob len={}, first_bytes={:?}",
                blob.len(),
                &blob[..blob.len().min(20)]
            );
            let pkcs8_der = if blob.starts_with(b"-----") {
                // PEM: strip headers and base64-decode
                let der = decode_pem_to_der(blob)?;
                debug!("CNG KSP: decoded PEM to {} bytes DER", der.len());
                der
            } else if blob.len() > 4 && &blob[0..4] == b"RSA3" {
                // CNG RSAFULLPRIVATEBLOB binary format
                crate::blob::pkcs8_from_rsa_full_private_blob(blob)?
            } else {
                // Assume raw PKCS#8 DER
                blob.clone()
            };
            backend::import_rsa_private_key(
                &self.client,
                &self.vendor_id,
                &pending.key_name,
                &pkcs8_der,
            )?
        } else {
            // Generate a new key pair in the KMS
            match &pending.algorithm {
                KeyAlgorithm::Rsa { bits } => backend::create_rsa_key_pair(
                    &self.client,
                    &self.vendor_id,
                    &pending.key_name,
                    *bits,
                )?,
                KeyAlgorithm::Ec { curve } => {
                    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_types::RecommendedCurve;
                    let kms_curve = match curve {
                        EcCurve::P256 => RecommendedCurve::P256,
                        EcCurve::P384 => RecommendedCurve::P384,
                        EcCurve::P521 => RecommendedCurve::P521,
                    };
                    backend::create_ec_key_pair(
                        &self.client,
                        &self.vendor_id,
                        &pending.key_name,
                        kms_curve,
                    )?
                }
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

        let key_der = backend::export_public_key_spki(&self.client, pub_uid)?;
        match alg {
            KeyAlgorithm::Rsa { .. } => {
                // The KMS may return either SPKI (SEQUENCE { AlgorithmId, BIT STRING })
                // or raw PKCS#1 (SEQUENCE { INTEGER, INTEGER }) depending on
                // how the key was stored. Try SPKI first, fall back to PKCS#1.
                rsa_public_blob_from_spki_der(&key_der)
                    .or_else(|_| rsa_public_blob_from_pkcs1_der(&key_der))
            }
            KeyAlgorithm::Ec { curve } => {
                // Similarly for EC: try SPKI first, fall back to raw uncompressed point.
                ec_public_blob_from_spki_der(&key_der, true)
                    .or_else(|_| ec_public_blob_from_uncompressed(*curve, &key_der, true))
            }
        }
    }

    /// Export the private key as PKCS#8 DER bytes from the KMS.
    ///
    /// Used by `NCryptExportKey` with the `PKCS8_PRIVATEKEY` blob type.
    pub fn export_private_pkcs8(&self) -> KspResult<Vec<u8>> {
        let priv_uid = match &self.state {
            KeyState::Persisted { priv_uid, .. } => priv_uid.as_str(),
            KeyState::Pending(_) => {
                return Err(KspError::InvalidParameter(
                    "Key not yet finalized".to_owned(),
                ));
            }
        };
        backend::export_private_key_pkcs8(&self.client, priv_uid)
    }
}

/// Decode a PEM-encoded private key to raw DER bytes.
/// Strips `-----BEGIN ... -----` and `-----END ... -----` headers and base64-decodes.
fn decode_pem_to_der(pem_bytes: &[u8]) -> KspResult<Vec<u8>> {
    use base64::Engine;

    let pem_str = std::str::from_utf8(pem_bytes)
        .map_err(|_e| KspError::InvalidParameter("PEM is not valid UTF-8".into()))?;

    // Collect all lines that are not headers/footers
    let b64: String = pem_str
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| KspError::InvalidParameter(format!("PEM base64 decode failed: {e}")))
}
