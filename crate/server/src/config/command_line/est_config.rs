// Field names intentionally share an `est_` prefix for disambiguation in
// flat CLI / env-var / TOML namespaces.
#![allow(clippy::struct_field_names)]

use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for the EST (Enrollment over Secure Transport, RFC 7030) endpoints.
///
/// When `est_enabled = true` the KMS exposes `/.well-known/est/cacerts`,
/// `/.well-known/est/csrattrs`, `/.well-known/est/simpleenroll` and
/// `/.well-known/est/simplereenroll`.
///
/// In `kms.toml` these keys live under the `[est]` section:
/// ```toml
/// [est]
/// est_enabled = false
/// est_ca_uid = "..."
/// est_require_client_cert = true
/// est_template = "iot_device"
/// ```
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct EstConfig {
    /// Enable the EST endpoints under `/.well-known/est/`.
    ///
    /// When `false` (default) all `/.well-known/est/` routes return 404.
    #[clap(long, default_value = "false", verbatim_doc_comment)]
    pub est_enabled: bool,

    /// UID of the CA certificate object in the KMS that signs EST-enrolled certificates.
    ///
    /// The CA private key must be linked to this certificate. Must be set when
    /// `est_enabled = true`.
    #[clap(long, verbatim_doc_comment)]
    pub est_ca_uid: Option<String>,

    /// Require TLS client-certificate authentication for `/simpleenroll` (RFC 7030 §3.3.2).
    ///
    /// When `true` (default) initial enrollment is only accepted over mutual TLS.
    /// When `false`, HTTP Basic authentication (RFC 7030 §3.2.3) with
    /// `est_bootstrap_username` / `est_bootstrap_password` is accepted as a fallback for
    /// devices that have no certificate yet. `/simplereenroll` always requires a client
    /// certificate (RFC 7030 §4.2.2).
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set, verbatim_doc_comment)]
    pub est_require_client_cert: bool,

    /// Username accepted for HTTP Basic bootstrap authentication on `/simpleenroll`.
    #[clap(long, verbatim_doc_comment)]
    pub est_bootstrap_username: Option<String>,

    /// Password accepted for HTTP Basic bootstrap authentication on `/simpleenroll`.
    #[clap(long, verbatim_doc_comment)]
    pub est_bootstrap_password: Option<String>,

    /// Name of the `[templates.<name>]` section whose issuance policy (key type and size,
    /// EKU, Subject/SAN patterns, validity) is enforced on EST enrollments.
    ///
    /// When unset, a baseline policy applies: RSA keys of at least 2048 bits, no
    /// `basicConstraints` `CA:TRUE`, and a validity of at most 365 days.
    #[clap(long, verbatim_doc_comment)]
    pub est_template: Option<String>,
}

impl Default for EstConfig {
    fn default() -> Self {
        Self {
            est_enabled: false,
            est_ca_uid: None,
            est_require_client_cert: true,
            est_bootstrap_username: None,
            est_bootstrap_password: None,
            est_template: None,
        }
    }
}
