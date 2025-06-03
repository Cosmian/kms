use std::{fmt, fmt::Display};

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

/// Server Information contains optional fields that describe server information.
/// Where a server supports returning information in a vendor-specific field for which
/// there is an equivalent field within the structure; the server SHALL provide
/// the standardized version of the field.
///
/// Not this is 2.1 specific, but the 1.4 spec only specifies this must be a structure;
/// so we use the same structure for both versions.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ServerInformation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_load: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_failover_endpoints: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_specific: Option<Vec<String>>,
}

impl Display for ServerInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strings = vec![];
        if let Some(server_name) = &self.server_name {
            strings.push(format!("server_name: {server_name}"));
        }
        if let Some(server_serial_number) = &self.server_serial_number {
            strings.push(format!("server_serial_number: {server_serial_number}"));
        }
        if let Some(server_version) = &self.server_version {
            strings.push(format!("server_version: {server_version}"));
        }
        if let Some(server_load) = &self.server_load {
            strings.push(format!("server_load: {server_load}"));
        }
        if let Some(product_name) = &self.product_name {
            strings.push(format!("product_name: {product_name}"));
        }
        if let Some(build_level) = &self.build_level {
            strings.push(format!("build_level: {build_level}"));
        }
        if let Some(build_date) = &self.build_date {
            strings.push(format!("build_date: {build_date}"));
        }
        if let Some(cluster_info) = &self.cluster_info {
            strings.push(format!("cluster_info: {cluster_info}"));
        }
        if let Some(alternative_failover_endpoints) = &self.alternative_failover_endpoints {
            strings.push(format!(
                "alternative_failover_endpoints: {alternative_failover_endpoints:?}"
            ));
        }
        write!(f, "{}", strings.join(", "))
    }
}
