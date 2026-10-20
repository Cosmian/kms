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
#[derive(Args, Clone, Deserialize, Serialize)]
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
    /// `est_enabled = true`. Certificates are issued as the reserved `[enrollment-service]`
    /// identity: the CA owner must grant it `certify` on this certificate and on its private
    /// key. Issued certificates are owned by the CA owner.
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
    ///
    /// At least 8 characters. Prefer the `KMS_EST_BOOTSTRAP_PASSWORD` environment variable (or
    /// the configuration file) to the command line, where it is visible in the process list.
    #[clap(
        long,
        env = "KMS_EST_BOOTSTRAP_PASSWORD",
        hide_env_values = true,
        verbatim_doc_comment
    )]
    pub est_bootstrap_password: Option<String>,

    /// Name of the `[templates.<name>]` section whose issuance policy (key type and size,
    /// EKU, Subject/SAN patterns, validity) is enforced on EST enrollments.
    ///
    /// Required when `est_enabled = true`. The template must set `subject_cn_regex` (or
    /// `allow_any_identity = true`): the enrollment secret authenticates a class of devices,
    /// not the name a device asks for.
    #[clap(long, verbatim_doc_comment)]
    pub est_template: Option<String>,
}

// Manual impl: `est_bootstrap_password` must never reach a log line.
impl std::fmt::Debug for EstConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstConfig")
            .field("est_enabled", &self.est_enabled)
            .field("est_ca_uid", &self.est_ca_uid)
            .field("est_require_client_cert", &self.est_require_client_cert)
            .field("est_bootstrap_username", &self.est_bootstrap_username)
            .field(
                "est_bootstrap_password",
                &self.est_bootstrap_password.as_ref().map(|_| "[****]"),
            )
            .field("est_template", &self.est_template)
            .finish()
    }
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
