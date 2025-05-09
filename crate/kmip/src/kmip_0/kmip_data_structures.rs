use serde::{Deserialize, Serialize};

use crate::kmip_0::kmip_types::{ValidationAuthorityType, ValidationType};

/// Validation Information contains details about the validation of a cryptographic
/// module, including the validation authority, version information and validation
/// profiles.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ValidationInformation {
    pub validation_authority_type: ValidationAuthorityType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_authority_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_authority_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_version_major: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_version_minor: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_type: Option<ValidationType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_level: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_certificate_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_certificate_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_vendor_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_profile: Option<String>,
}
