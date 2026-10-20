// Field names intentionally share a `scep_` prefix for disambiguation in
// flat CLI / env-var / TOML namespaces.
#![allow(clippy::struct_field_names)]

use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for the SCEP (Simple Certificate Enrollment Protocol, RFC 8894) endpoint.
///
/// When `scep_enabled = true` the KMS exposes `GET|POST /scep?operation=...`
/// (`GetCACaps`, `GetCACert`, `PKIOperation`). The advertised capabilities are fixed to
/// `POSTPKIOperation`, `SHA-256`, `AES` and `Renewal`; the historical `DES3` and `SHA-1`
/// are never offered (not approved by FIPS 140-3 / SP 800-131A).
///
/// In `kms.toml` these keys live under the `[scep]` section:
/// ```toml
/// [scep]
/// scep_enabled = false
/// scep_ca_uid = "..."
/// scep_allow_renewal_without_challenge = true
/// scep_template = "iot_device"
/// ```
#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ScepConfig {
    /// Enable the SCEP endpoint at `/scep`.
    ///
    /// When `false` (default) the `/scep` route returns 404.
    #[clap(long, default_value = "false", verbatim_doc_comment)]
    pub scep_enabled: bool,

    /// UID of the CA certificate object in the KMS that signs SCEP-enrolled certificates.
    ///
    /// SCEP encrypts requests to the CA public key, so this MUST be an RSA CA whose private
    /// key is linked to the certificate. Must be set when `scep_enabled = true`.
    /// Certificates are issued as the reserved `[enrollment-service]` identity: the CA owner
    /// must grant it `certify` on this certificate and on its private key. Issued certificates
    /// are owned by the CA owner.
    #[clap(long, verbatim_doc_comment)]
    pub scep_ca_uid: Option<String>,

    /// Shared secret a device must put in the PKCS#10 `challengePassword` attribute for an
    /// initial enrollment (`PKCSReq`). Must be set when `scep_enabled = true`.
    ///
    /// At least 8 characters. Prefer the `KMS_SCEP_CHALLENGE_PASSWORD` environment variable (or
    /// the configuration file) to the command line, where it is visible in the process list.
    #[clap(
        long,
        env = "KMS_SCEP_CHALLENGE_PASSWORD",
        hide_env_values = true,
        verbatim_doc_comment
    )]
    pub scep_challenge_password: Option<String>,

    /// Accept `RenewalReq` messages signed with a still-valid certificate issued by the SCEP
    /// CA without requiring the challenge password (RFC 8894 §2.3, §2.4).
    ///
    /// When `false`, renewal requests are rejected with `badRequest`.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set, verbatim_doc_comment)]
    pub scep_allow_renewal_without_challenge: bool,

    /// Name of the `[templates.<name>]` section whose issuance policy (key type and size,
    /// EKU, Subject/SAN patterns, validity) is enforced on SCEP enrollments.
    ///
    /// Required when `scep_enabled = true`. The template must set `subject_cn_regex` (or
    /// `allow_any_identity = true`): the enrollment secret authenticates a class of devices,
    /// not the name a device asks for.
    #[clap(long, verbatim_doc_comment)]
    pub scep_template: Option<String>,
}

// Manual impl: `scep_challenge_password` must never reach a log line.
impl std::fmt::Debug for ScepConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScepConfig")
            .field("scep_enabled", &self.scep_enabled)
            .field("scep_ca_uid", &self.scep_ca_uid)
            .field(
                "scep_challenge_password",
                &self.scep_challenge_password.as_ref().map(|_| "[****]"),
            )
            .field(
                "scep_allow_renewal_without_challenge",
                &self.scep_allow_renewal_without_challenge,
            )
            .field("scep_template", &self.scep_template)
            .finish()
    }
}

impl Default for ScepConfig {
    fn default() -> Self {
        Self {
            scep_enabled: false,
            scep_ca_uid: None,
            scep_challenge_password: None,
            scep_allow_renewal_without_challenge: true,
            scep_template: None,
        }
    }
}
