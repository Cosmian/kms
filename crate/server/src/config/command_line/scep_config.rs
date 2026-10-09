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
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
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
    #[clap(long, verbatim_doc_comment)]
    pub scep_ca_uid: Option<String>,

    /// Shared secret a device must put in the PKCS#10 `challengePassword` attribute for an
    /// initial enrollment (`PKCSReq`). Must be set when `scep_enabled = true`.
    #[clap(long, verbatim_doc_comment)]
    pub scep_challenge_password: Option<String>,

    /// Accept `RenewalReq` messages signed with a still-valid certificate issued by the SCEP
    /// CA without requiring the challenge password (RFC 8894 §2.3, §2.4).
    ///
    /// When `false`, renewal requests are rejected with `badRequest`.
    #[clap(long, default_value = "true", verbatim_doc_comment)]
    pub scep_allow_renewal_without_challenge: bool,

    /// Name of the `[templates.<name>]` section whose issuance policy (key type and size,
    /// EKU, Subject/SAN patterns, validity) is enforced on SCEP enrollments.
    ///
    /// When unset, a baseline policy applies: RSA keys of at least 2048 bits, no
    /// `basicConstraints` `CA:TRUE`, and a validity of at most 365 days.
    #[clap(long, verbatim_doc_comment)]
    pub scep_template: Option<String>,
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
