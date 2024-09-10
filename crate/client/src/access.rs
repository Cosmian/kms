use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    str::FromStr,
};

use cosmian_kmip::kmip::kmip_types::{Attributes, StateEnumeration, UniqueIdentifier};
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
    pub operation_types: Vec<ObjectOperationType>,
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

/// Operation types that can get or create objects
/// These operations use `retrieve` or `get` methods.
#[derive(Eq, PartialEq, Serialize, Deserialize, Copy, Clone, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ObjectOperationType {
    Create,
    Certify,
    Decrypt,
    Destroy,
    Encrypt,
    Export,
    Get,
    GetAttributes,
    Import,
    Locate,
    Revoke,
    Rekey,
    Validate,
}

impl fmt::Debug for ObjectOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for ObjectOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            Self::Create => "create",
            Self::Certify => "certify",
            Self::Decrypt => "decrypt",
            Self::Destroy => "destroy",
            Self::Encrypt => "encrypt",
            Self::Export => "export",
            Self::Get => "get",
            Self::GetAttributes => "get_attributes",
            Self::Import => "import",
            Self::Locate => "locate",
            Self::Revoke => "revoke",
            Self::Rekey => "rekey",
            Self::Validate => "validate",
        };
        write!(f, "{str}")
    }
}

// any error type implementing Display is acceptable.
type ParseError = &'static str;

impl FromStr for ObjectOperationType {
    type Err = ParseError;

    fn from_str(op: &str) -> Result<Self, Self::Err> {
        match op {
            "create" => Ok(Self::Create),
            "certify" => Ok(Self::Certify),
            "decrypt" => Ok(Self::Decrypt),
            "destroy" => Ok(Self::Destroy),
            "encrypt" => Ok(Self::Encrypt),
            "get_attributes" => Ok(Self::GetAttributes),
            "export" => Ok(Self::Export),
            "get" => Ok(Self::Get),
            "import" => Ok(Self::Import),
            "locate" => Ok(Self::Locate),
            "rekey" => Ok(Self::Rekey),
            "revoke" => Ok(Self::Revoke),
            _ => Err("Could not parse an operation {op}"),
        }
    }
}
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct UserAccessResponse {
    pub user_id: String,
    /// A `BTreeSet` is used to keep results sorted
    pub operations: BTreeSet<ObjectOperationType>,
}
pub type IsWrapped = bool;
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct ObjectOwnedResponse {
    pub object_id: UniqueIdentifier,
    pub state: StateEnumeration,
    pub attributes: Attributes,
    pub is_wrapped: IsWrapped,
}
impl fmt::Display for ObjectOwnedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}]{} {} - {}",
            self.state,
            if self.is_wrapped { "[Wrapped]" } else { "" },
            self.object_id,
            self.attributes
                .key_format_type
                .map_or_else(String::new, |format| format.to_string())
        )
    }
}
impl From<(String, StateEnumeration, Attributes, IsWrapped)> for ObjectOwnedResponse {
    fn from(e: (String, StateEnumeration, Attributes, IsWrapped)) -> Self {
        Self {
            object_id: UniqueIdentifier::TextString(e.0),
            state: e.1,
            attributes: e.2,
            is_wrapped: e.3,
        }
    }
}
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct AccessRightsObtainedResponse {
    pub object_id: UniqueIdentifier,
    pub owner_id: String,
    pub state: StateEnumeration,
    pub operations: HashSet<ObjectOperationType>,
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
impl
    From<(
        String,
        (String, StateEnumeration, HashSet<ObjectOperationType>),
    )> for AccessRightsObtainedResponse
{
    fn from(
        e: (
            String,
            (String, StateEnumeration, HashSet<ObjectOperationType>),
        ),
    ) -> Self {
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
