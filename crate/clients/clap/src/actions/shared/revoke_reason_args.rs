use clap::Parser;
use cosmian_kms_client::cosmian_kmip::kmip_0::kmip_types::RevocationReasonCode;

use super::utils::parse_revocation_reason_code;

/// Common revocation reason arguments shared by all revoke actions.
///
/// Embed via `#[clap(flatten)]` in domain-specific revoke structs.
#[derive(Parser, Debug, Clone)]
pub struct RevokeReasonArgs {
    /// The reason for the revocation as a string
    #[clap(required = true)]
    pub revocation_reason: String,

    /// The revocation reason code [default: unspecified]
    ///
    /// Valid values: unspecified, key-compromise, ca-compromise,
    /// affiliation-changed, superseded, cessation-of-operation,
    /// privilege-withdrawn
    #[clap(long = "reason-code", short = 'r', default_value = "unspecified",
           value_parser = parse_revocation_reason_code)]
    pub reason_code: RevocationReasonCode,
}
