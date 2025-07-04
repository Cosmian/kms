use std::{
    collections::{BTreeSet, HashSet},
    fmt,
};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_types::UniqueIdentifier},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Access {
    /// Determines the object being requested. If omitted, then the ID
    /// Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// User identifier, beneficiary of the access
    pub user_id: String,
    /// Operation types for the access
    pub operation_types: Vec<KmipOperation>,
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {:?}",
            self.user_id,
            self.unique_identifier
                .as_ref()
                .map_or_else(|| "[N/A]".to_owned(), std::string::ToString::to_string),
            self.operation_types
        )
    }
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)] // Debug is required by ok_json()
pub struct UserAccessResponse {
    pub user_id: String,
    /// A `BTreeSet` is used to keep results sorted
    pub operations: BTreeSet<KmipOperation>,
}
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)] // Debug is required by ok_json()
pub struct ObjectOwnedResponse {
    pub object_id: UniqueIdentifier,
    pub state: State,
    pub attributes: Attributes,
}
impl fmt::Display for ObjectOwnedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}] {} - {}",
            self.state,
            self.object_id,
            self.attributes
                .key_format_type
                .map_or_else(String::new, |format| format.to_string())
        )
    }
}
impl From<(String, State, Attributes)> for ObjectOwnedResponse {
    fn from(e: (String, State, Attributes)) -> Self {
        Self {
            object_id: UniqueIdentifier::TextString(e.0),
            state: e.1,
            attributes: e.2,
        }
    }
}
#[derive(Deserialize, Serialize, Clone, Debug)] // Debug is required by ok_json()
pub struct AccessRightsObtainedResponse {
    pub object_id: UniqueIdentifier,
    pub owner_id: String,
    pub state: State,
    pub operations: HashSet<KmipOperation>,
}
impl fmt::Display for AccessRightsObtainedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}][{}]{} {:?} - comments",
            self.state, self.owner_id, self.object_id, self.operations
        )
    }
}
impl From<(String, (String, State, HashSet<KmipOperation>))> for AccessRightsObtainedResponse {
    fn from(e: (String, (String, State, HashSet<KmipOperation>))) -> Self {
        Self {
            object_id: UniqueIdentifier::TextString(e.0),
            owner_id: e.1.0,
            state: e.1.1,
            operations: e.1.2,
        }
    }
}
// Response for success
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct SuccessResponse {
    pub success: String,
}

#[derive(Serialize)]
pub struct CreatePermissionResponse {
    pub has_create_permission: bool,
}

#[derive(Serialize)]
pub struct PrivilegedAccessResponse {
    pub has_privileged_access: bool,
}
