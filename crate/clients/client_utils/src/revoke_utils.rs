use cosmian_kmip::kmip_0::kmip_types::RevocationReasonCode;

/// Parse a revocation reason code string (kebab-case, `snake_case`, or `PascalCase`)
/// into a [`RevocationReasonCode`]. Case-insensitive; hyphens and underscores are
/// normalised away before matching.
///
/// Returns `Ok(code)` on success or `Err(message)` for unknown values.
pub fn try_parse_revocation_reason_code(s: &str) -> Result<RevocationReasonCode, String> {
    match s.to_lowercase().replace(['-', '_'], "").as_str() {
        "unspecified" => Ok(RevocationReasonCode::Unspecified),
        "keycompromise" => Ok(RevocationReasonCode::KeyCompromise),
        "cacompromise" => Ok(RevocationReasonCode::CACompromise),
        "affiliationchanged" => Ok(RevocationReasonCode::AffiliationChanged),
        "superseded" => Ok(RevocationReasonCode::Superseded),
        "cessationofoperation" => Ok(RevocationReasonCode::CessationOfOperation),
        "privilegewithdrawn" => Ok(RevocationReasonCode::PrivilegeWithdrawn),
        other => Err(format!(
            "unknown revocation reason code: '{other}'. Valid values: unspecified, \
             key-compromise, ca-compromise, affiliation-changed, superseded, \
             cessation-of-operation, privilege-withdrawn"
        )),
    }
}
