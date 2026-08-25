use std::fmt;

use clap::Args;
use serde::{Deserialize, Serialize};

/// RBAC role assignments.
///
/// Configures which users hold the `CryptoOfficer` role.
/// Users not listed default to `Operator` (minimum privilege) when
/// role enforcement is active.
///
/// In TOML, these fields live under the `[roles]` section:
///
/// ```toml
/// [roles]
/// crypto_officer_users = ["key-mgr@example.com"]
/// ```
#[derive(Args, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct RolesConfig {
    /// Users with the Crypto Officer role (ISO/IEC 19790 "Crypto Officer" / PKCS#11 `CKU_SO`).
    ///
    /// May manage key lifecycle (create, import, certify, rekey, activate, revoke, destroy)
    /// and access raw key material (get, export — "key output" per ISO/IEC 19790 §7.4.3).
    /// When active, gains ownership bypass on all Managed Objects.
    /// When set, only listed users (plus those explicitly granted the `Create` right) can
    /// create and import objects.
    #[clap(long, verbatim_doc_comment)]
    pub crypto_officer_users: Option<Vec<String>>,

    /// Require a split-key ceremony to activate the Crypto Officer role.
    ///
    /// When `true`, users listed in `crypto_officer_users` are candidates only —
    /// the role is inactive until a KMIP `JoinSplitKey` with all shares tagged
    /// `x-cosmian-crypto-officer-ceremony` completes
    /// (NIST SP 800-57 Part 2 Rev 1 §4.6 split knowledge, XOR n-of-n).
    #[clap(long, verbatim_doc_comment, default_value = "false")]
    pub crypto_officer_require_ceremony: bool,

    /// Hex-encoded 32-byte secret for ceremony record encryption.
    ///
    /// Required when any role has `require_ceremony = true`.
    /// All ceremony activation records are AES-256-GCM encrypted with keys
    /// derived from this secret, preventing forgery via direct database writes
    /// and protecting participant identities at rest.
    ///
    /// Generate with: `openssl rand -hex 32`
    #[clap(long, env = "KMS_CEREMONY_SECRET", verbatim_doc_comment)]
    pub ceremony_secret: Option<String>,

    /// UID of a KMS symmetric key to use as the ceremony record sealing key.
    ///
    /// When set, key material is fetched from the KMS object store after database
    /// initialization and used in place of `ceremony_secret`. This enables:
    ///   - Key rotation via standard KMIP `ReKey` / `Rotate` operations.
    ///   - HSM-backed sealing when the referenced key is HSM-resident.
    ///   - Audit trail: each retrieval of the ceremony key is logged.
    ///
    /// If both `ceremony_secret` and `ceremony_key_id` are set, `ceremony_key_id` takes precedence.
    ///
    /// **Bootstrap constraint**: the ceremony sealing key must be created before
    /// enabling `crypto_officer_require_ceremony = true`. Create it while the server
    /// is in config-only CO mode (no ceremony required), then enable ceremony mode:
    ///
    /// ```bash
    /// # 1. Start server with require_ceremony = false
    /// # 2. Create the sealing key:
    /// ckms sym keys create --id ceremony-seal-2026 --number-of-bits 256
    /// # 3. Set ceremony_key_id = "ceremony-seal-2026" in kms.toml
    /// # 4. Enable require_ceremony = true and restart
    /// ```
    #[clap(long, env = "KMS_CEREMONY_KEY_ID", verbatim_doc_comment)]
    pub ceremony_key_id: Option<String>,

    /// UID of a KMS symmetric key to use for AES-KW (RFC 5649) wrapping of split-key shares.
    ///
    /// When set, `CreateSplitKey` encrypts each share's raw bytes with this key (AES-128/192/256-KWP)
    /// before storing in the database.  `JoinSplitKey` automatically detects the
    /// `x-cosmian-share-wrapping-key` vendor attribute on each share and unwraps the bytes before
    /// XOR reconstruction.
    ///
    /// The wrapping key must already exist in the KMS object store and must be an AES symmetric key.
    /// When the KMS is HSM-backed, this key can be HSM-resident, providing hardware boundary
    /// protection equivalent to purpose-built HSM split-key solutions.
    ///
    /// Generate a suitable key before enabling ceremony mode:
    /// ```bash
    /// ckms sym keys create --id ceremony-wrap-2026 --number-of-bits 256
    /// ```
    ///
    /// Rotate by creating a new key, updating this value, and re-running the ceremony
    /// (existing wrapped shares require the original key; re-ceremony is mandatory on rotation).
    #[clap(long, env = "KMS_CEREMONY_WRAP_KEY_ID", verbatim_doc_comment)]
    pub ceremony_wrapping_key_id: Option<String>,
}

impl fmt::Debug for RolesConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RolesConfig")
            .field("crypto_officer_users", &self.crypto_officer_users)
            .field(
                "crypto_officer_require_ceremony",
                &self.crypto_officer_require_ceremony,
            )
            .field(
                "ceremony_secret",
                &self.ceremony_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("ceremony_key_id", &self.ceremony_key_id)
            .field("ceremony_wrapping_key_id", &self.ceremony_wrapping_key_id)
            .finish()
    }
}
