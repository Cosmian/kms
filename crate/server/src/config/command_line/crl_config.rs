// Field names intentionally share a `crl_` prefix for disambiguation in
// flat CLI / env-var / TOML namespaces.
#![allow(clippy::struct_field_names)]

use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for X.509 CRL (Certificate Revocation List) lifecycle management.
///
/// These settings control how the KMS generates, caches, and automatically refreshes
/// CRLs for CA certificates it manages.  The default values are appropriate for
/// enterprise PKI scenarios; adjust them to match the CA's revocation policy.
///
/// In `kms.toml`, these keys are at the top level:
/// ```toml
/// crl_default_validity_days = 7
/// crl_refresh_check_hours   = 1
/// crl_refresh_overlap_hours = 24
/// ```
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct CrlConfig {
    /// Default CRL validity period in days for CA certificates managed by this server.
    ///
    /// When a CRL is generated without an explicit validity override (e.g., via
    /// `GET /certificates/{id}/crl?validity_days=N`), this value is used.
    ///
    /// This value is in whole days (minimum 1 day / 24 h); enterprise PKIs commonly
    /// use 7–28 days. Avoid the practical minimum of 1 day unless
    /// `crl_refresh_overlap_hours` is also lowered below 24: a 1-day CRL satisfies
    /// the default 24-hour refresh-overlap condition immediately after creation,
    /// causing the hourly scheduler to continuously re-sign it.
    ///
    /// Valid range: 1–365 when set via the CLI flag or an environment variable.
    /// Default: 7.
    ///
    /// This range is enforced by clap's argument parser only; it is not
    /// currently re-validated when the value comes from a TOML config file, so
    /// a value outside 1–365 in `kms.toml` is silently accepted.
    #[clap(
        long,
        default_value = "7",
        value_parser = clap::value_parser!(u32).range(1..=365),
        verbatim_doc_comment
    )]
    pub crl_default_validity_days: u32,

    /// How often (in hours) the background CRL refresh scheduler wakes up to
    /// check whether any stored CRL needs to be regenerated.
    ///
    /// Set to 0 to disable the background scheduler entirely.
    /// When disabled, CRLs are only refreshed on certificate revocation events.
    ///
    /// The scheduler is only spawned when `kms_public_url` is ALSO configured
    /// (the CDP endpoint must be active); with `kms_public_url` unset, this
    /// setting has no effect and CRLs are only refreshed on revocation events,
    /// which can allow an expired CRL to be served in the meantime.
    ///
    /// Default: 1 (wake up hourly).
    #[clap(long, default_value = "1", verbatim_doc_comment)]
    pub crl_refresh_check_hours: u32,

    /// CRL overlap window in hours.
    ///
    /// The background scheduler regenerates a CRL when its `nextUpdate` timestamp
    /// is within this many hours of the current time.  This prevents relying parties
    /// from seeing an expired CRL during the window between expiry and the next
    /// revocation-triggered regeneration.
    ///
    /// Analogy: EJBCA "CRL Overlap Time" (default 10 % of validity); AWS PCA uses
    /// a 1-day overlap by default.
    ///
    /// Default: 24 (regenerate 24 hours before expiry).
    #[clap(long, default_value = "24", verbatim_doc_comment)]
    pub crl_refresh_overlap_hours: u32,
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            crl_default_validity_days: 7,
            crl_refresh_check_hours: 1,
            crl_refresh_overlap_hours: 24,
        }
    }
}
