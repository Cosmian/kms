// Field names intentionally share an `ocsp_` prefix for disambiguation in
// flat CLI / env-var / TOML namespaces.
#![allow(clippy::struct_field_names)]

use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for the OCSP (Online Certificate Status Protocol) responder.
///
/// When `ocsp_enabled = true` the KMS exposes a public `GET/POST /ocsp/` endpoint
/// that relying parties can query for real-time certificate revocation status,
/// fully compliant with RFC 6960, RFC 9654 (nonce), and RFC 5019 (HTTP caching).
///
/// In `kms.toml` these keys live under a flat top-level section:
/// ```toml
/// ocsp_enabled          = false
/// ocsp_ca_uid           = "..."
/// ocsp_responder_cert_uid = "..."   # optional delegated signer
/// ocsp_cache_ttl_secs   = 86400
/// ocsp_nonce_policy     = "optional"
/// ocsp_include_cert_chain = true
/// ocsp_archive_cutoff_secs = 0
/// ```
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct OcspConfig {
    /// Enable the OCSP responder endpoint at `GET/POST /ocsp/`.
    ///
    /// When `false` (default) all `/ocsp/` routes return 404.
    #[clap(long, default_value = "false", verbatim_doc_comment)]
    pub ocsp_enabled: bool,

    /// UID of the CA certificate object in the KMS.
    ///
    /// Used to verify that incoming OCSP requests are for certificates issued by
    /// this CA (by comparing issuer name hash and key hash), and to retrieve
    /// certificate states for revocation lookup.
    ///
    /// Must be set when `ocsp_enabled = true`.
    #[clap(long, verbatim_doc_comment)]
    pub ocsp_ca_uid: Option<String>,

    /// UID of the dedicated OCSP signing certificate (RFC 6960 §4.2.2.2 authorized responder).
    ///
    /// When set, OCSP responses are signed by this delegated key+certificate rather
    /// than the CA's own private key.  The referenced certificate MUST have:
    /// - `extKeyUsage: OCSPSigning` (OID 1.3.6.1.5.5.7.3.9)
    /// - `id-pkix-ocsp-nocheck` extension (OID 1.3.6.1.5.5.7.48.1.5)
    ///
    /// Both requirements are enforced at request time: the server rejects the
    /// delegated certificate (and refuses to sign) if either is missing.
    ///
    /// The referenced key may be backed by an HSM via the existing PKCS#11 routing —
    /// no additional configuration is required.
    ///
    /// When unset, the CA's own private key is used (acceptable for small deployments;
    /// not recommended for production CAs where the signing key must stay offline).
    #[clap(long, verbatim_doc_comment)]
    pub ocsp_responder_cert_uid: Option<String>,

    /// OCSP response validity period in seconds (`thisUpdate` → `nextUpdate`).
    ///
    /// Determines how long a signed response may be cached by relying parties and
    /// CDN/proxy intermediaries per RFC 5019 §5.  Shorter values increase freshness;
    /// longer values reduce load on the KMS (and HSM) signing key.
    ///
    /// Default: 86400 (24 hours).
    #[clap(long, default_value = "86400", verbatim_doc_comment)]
    pub ocsp_cache_ttl_secs: u64,

    /// Nonce handling policy for OCSP responses (RFC 9654 §2.1).
    ///
    /// - `optional` (default): echo the nonce if present, proceed without one if absent.
    /// - `required`: reject requests that carry no nonce (returns `malformedRequest`).
    /// - `ignore`: never include a nonce in responses (suitable for pre-produced/cached responses).
    ///
    /// Per RFC 9654 §2.1, the responder MUST accept nonces of 16–128 octets and echo
    /// them verbatim.  Nonces shorter than 16 octets are silently ignored.
    #[clap(long, default_value = "optional", verbatim_doc_comment)]
    pub ocsp_nonce_policy: NoncePolicyConfig,

    /// Include the signing certificate chain in OCSP `BasicResponse`s.
    ///
    /// Set to `true` (default) when `ocsp_responder_cert_uid` is configured so that
    /// clients can verify the delegated responder's authorization without additional
    /// fetches.  Safe to set `false` when the CA signs responses directly.
    #[clap(long, default_value = "true", verbatim_doc_comment)]
    pub ocsp_include_cert_chain: bool,

    /// Archive-cutoff extension value in seconds (RFC 6960 §4.4.4).
    ///
    /// When non-zero, the `id-pkix-ocsp-archive-cutoff` extension is added to each
    /// `BasicResponse` with value = now − `ocsp_archive_cutoff_secs`. This tells clients
    /// how far back the responder maintains revocation records.
    ///
    /// Set to 0 (default) to disable the extension.
    /// Typical values: 365 days = 31536000.
    #[clap(long, default_value = "0", verbatim_doc_comment)]
    pub ocsp_archive_cutoff_secs: u64,
}

/// OCSP nonce handling policy (RFC 9654 §2.1).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NoncePolicyConfig {
    /// Echo the nonce if present; proceed without one if absent.  *(default)*
    #[default]
    Optional,
    /// Reject requests that carry no nonce.
    Required,
    /// Never include a nonce in responses.
    Ignore,
}

impl std::str::FromStr for NoncePolicyConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            "ignore" => Ok(Self::Ignore),
            other => Err(format!(
                "Invalid nonce policy '{other}'; valid values are: optional, required, ignore"
            )),
        }
    }
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            ocsp_enabled: false,
            ocsp_ca_uid: None,
            ocsp_responder_cert_uid: None,
            ocsp_cache_ttl_secs: 86400,
            ocsp_nonce_policy: NoncePolicyConfig::Optional,
            ocsp_include_cert_chain: true,
            ocsp_archive_cutoff_secs: 0,
        }
    }
}
