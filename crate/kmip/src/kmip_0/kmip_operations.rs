use std::fmt::Display;

use serde::{self, Deserialize, Serialize};

use crate::kmip_0::kmip_types::ProtocolVersion;

/// 4.26 Discover Versions
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DiscoverVersions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<Vec<ProtocolVersion>>,
}

impl Display for DiscoverVersions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DiscoverVersions {{ protocol_version: {:?} }}",
            self.protocol_version
        )
    }
}

/// Response to a Discover Versions request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DiscoverVersionsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<Vec<ProtocolVersion>>,
}

impl Display for DiscoverVersionsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DiscoverVersionsResponse {{ protocol_version: {:#?} }}",
            self.protocol_version
        )
    }
}
