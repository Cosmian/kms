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
            .finish()
    }
}
