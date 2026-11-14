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
    #[clap(
        long = "est-enabled",
        id = "est_enabled",
        value_name = "EST_ENABLED",
        default_value = "false",
        verbatim_doc_comment
    )]
    #[serde(rename = "est_enabled")]
    pub enabled: bool,

    /// UID of the CA certificate object in the KMS that signs EST-enrolled certificates.
    ///
    /// The CA private key must be linked to this certificate. Must be set when
    /// `est_enabled = true`. Certificates are issued as the reserved `[enrollment-service]`
    /// identity: the CA owner must grant it `certify` on this certificate and on its private
    /// key (plus `create` when `crypto_officer_users` is set). Issued certificates are owned by
    /// the CA owner.
    #[clap(
        long = "est-ca-uid",
        id = "est_ca_uid",
        value_name = "EST_CA_UID",
        verbatim_doc_comment
    )]
    #[serde(rename = "est_ca_uid")]
    pub ca_uid: Option<String>,

    /// Require TLS client-certificate authentication for `/simpleenroll` (RFC 7030 §3.3.2).
    ///
    /// When `true` (default) initial enrollment is only accepted over mutual TLS.
    /// When `false`, HTTP Basic authentication (RFC 7030 §3.2.3) with
    /// `est_bootstrap_username` / `est_bootstrap_password` is accepted as a fallback for
    /// devices that have no certificate yet. `/simplereenroll` always requires a client
    /// certificate (RFC 7030 §4.2.2).
    #[clap(long = "est-require-client-cert", id = "est_require_client_cert", value_name = "EST_REQUIRE_CLIENT_CERT", default_value_t = true, action = clap::ArgAction::Set, verbatim_doc_comment)]
    #[serde(rename = "est_require_client_cert")]
    pub require_client_cert: bool,

    /// Username accepted for HTTP Basic bootstrap authentication on `/simpleenroll`.
    #[clap(
        long = "est-bootstrap-username",
        id = "est_bootstrap_username",
        value_name = "EST_BOOTSTRAP_USERNAME",
        verbatim_doc_comment
    )]
    #[serde(rename = "est_bootstrap_username")]
    pub bootstrap_username: Option<String>,

    /// Password accepted for HTTP Basic bootstrap authentication on `/simpleenroll`.
    ///
    /// At least 8 characters. Prefer the `KMS_EST_BOOTSTRAP_PASSWORD` environment variable (or
    /// the configuration file) to the command line, where it is visible in the process list.
    #[clap(
        long = "est-bootstrap-password",
        id = "est_bootstrap_password",
        value_name = "EST_BOOTSTRAP_PASSWORD",
        env = "KMS_EST_BOOTSTRAP_PASSWORD",
        hide_env_values = true,
        verbatim_doc_comment
    )]
    #[serde(rename = "est_bootstrap_password")]
    pub bootstrap_password: Option<String>,

    /// Name of the `[templates.<name>]` section whose issuance policy (key type and size,
    /// EKU, Subject/SAN patterns, validity) is enforced on EST enrollments.
    ///
    /// Required when `est_enabled = true`. The template must set `subject_cn_regex` (or
    /// `allow_any_identity = true`): the enrollment secret authenticates a class of devices,
    /// not the name a device asks for.
    #[clap(
        long = "est-template",
        id = "est_template",
        value_name = "EST_TEMPLATE",
        verbatim_doc_comment
    )]
    #[serde(rename = "est_template")]
    pub template: Option<String>,
}

// Manual impl: `est_bootstrap_password` must never reach a log line.
impl std::fmt::Debug for EstConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstConfig")
            .field("est_enabled", &self.enabled)
            .field("est_ca_uid", &self.ca_uid)
            .field("est_require_client_cert", &self.require_client_cert)
            .field("est_bootstrap_username", &self.bootstrap_username)
            .field(
                "est_bootstrap_password",
                &self.bootstrap_password.as_ref().map(|_| "[****]"),
            )
            .field("est_template", &self.template)
            .finish()
    }
}

impl Default for EstConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_uid: None,
            require_client_cert: true,
            bootstrap_username: None,
            bootstrap_password: None,
            template: None,
        }
    }
}
