use serde::{self, Deserialize, Serialize};

use crate::kmip_0::kmip_types::ProtocolVersion;

/// 4.26 Discover Versions
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DiscoverVersions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<Vec<ProtocolVersion>>,
}

/// Response to a Discover Versions request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DiscoverVersionsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<Vec<ProtocolVersion>>,
}
