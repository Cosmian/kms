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
    /// Operation type for the access
    pub operation_type: ObjectOperationTypes,
}

/// Operation types that can get or create objects
/// These operations use `retrieve` or `get` methods.
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum ObjectOperationTypes {
    Create,
    Get,
    Encrypt,
    Decrypt,
    Import,
    Revoke,
    Locate,
    Rekey,
    Destroy,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ExtraDatabaseParams {
    pub group_id: u128,
    pub key: String,
}

use std::{fmt, str::FromStr};

// any error type implementing Display is acceptable.
type ParseError = &'static str;

impl FromStr for ObjectOperationTypes {
    type Err = ParseError;

    fn from_str(op: &str) -> Result<Self, Self::Err> {
        match op {
            "create" => Ok(Self::Create),
            "get" => Ok(Self::Get),
            "encrypt" => Ok(Self::Encrypt),
            "decrypt" => Ok(Self::Decrypt),
            "import" => Ok(Self::Import),
            "revoke" => Ok(Self::Revoke),
            "locate" => Ok(Self::Locate),
            "rekey" => Ok(Self::Rekey),
            "destroy" => Ok(Self::Destroy),
            _ => Err("Could not parse an operation {op}"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct UserAccessResponse {
    pub user_id: String,
    pub operations: Vec<ObjectOperationTypes>,
}

impl From<(String, Vec<ObjectOperationTypes>)> for UserAccessResponse {
    fn from(e: (String, Vec<ObjectOperationTypes>)) -> Self {
        Self {
            user_id: e.0,
            operations: e.1,
        }
    }
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
            if let Some(format) = self.attributes.key_format_type {
                format.to_string()
            } else {
                String::new()
            }
        )
    }
}

impl From<(String, StateEnumeration, Attributes, IsWrapped)> for ObjectOwnedResponse {
    fn from(e: (String, StateEnumeration, Attributes, IsWrapped)) -> Self {
        Self {
            object_id: e.0,
            state: e.1,
            attributes: e.2,
            is_wrapped: e.3,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct ObjectSharedResponse {
    pub object_id: UniqueIdentifier,
    pub owner_id: String,
    pub state: StateEnumeration,
    pub operations: Vec<ObjectOperationTypes>,
    pub is_wrapped: IsWrapped,
}

impl fmt::Display for ObjectSharedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}][{}]{} {} {:?} - comments",
            self.state,
            self.owner_id,
            if self.is_wrapped { "[Wrapped]" } else { "" },
            self.object_id,
            self.operations
        )
    } // TODO (@T.G): replace comments by attributes.KeyFormatType
}

impl
    From<(
        UniqueIdentifier,
        String,
        StateEnumeration,
        Vec<ObjectOperationTypes>,
        IsWrapped,
    )> for ObjectSharedResponse
{
    fn from(
        e: (
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationTypes>,
            IsWrapped,
        ),
    ) -> Self {
        Self {
            object_id: e.0,
            owner_id: e.1,
            state: e.2,
            operations: e.3,
            is_wrapped: e.4,
        }
    }
}

// Response for success
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct SuccessResponse {
    pub success: String,
}

// Response when querying the KMS certificates
#[derive(Deserialize, Serialize, Debug)]
pub struct CertificatesResponse {
    pub certificate: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteParams {
    pub nonce: String,
}
