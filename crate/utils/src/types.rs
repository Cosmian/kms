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
#[derive(PartialEq, Serialize, Deserialize, Debug, Copy, Clone)]
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

use std::str::FromStr;

// any error type implementing Display is acceptable.
type ParseError = &'static str;

impl FromStr for ObjectOperationTypes {
    type Err = ParseError;

    fn from_str(op: &str) -> Result<Self, Self::Err> {
        match op {
            "create" => Ok(ObjectOperationTypes::Create),
            "get" => Ok(ObjectOperationTypes::Get),
            "encrypt" => Ok(ObjectOperationTypes::Encrypt),
            "decrypt" => Ok(ObjectOperationTypes::Decrypt),
            "import" => Ok(ObjectOperationTypes::Import),
            "revoke" => Ok(ObjectOperationTypes::Revoke),
            "locate" => Ok(ObjectOperationTypes::Locate),
            "rekey" => Ok(ObjectOperationTypes::Rekey),
            "destroy" => Ok(ObjectOperationTypes::Destroy),
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
    fn from(e: (String, Vec<ObjectOperationTypes>)) -> UserAccessResponse {
        UserAccessResponse {
            user_id: e.0,
            operations: e.1,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct ObjectOwnedResponse {
    pub object_id: UniqueIdentifier,
    pub state: StateEnumeration,
    pub attributes: Attributes,
}

impl From<(String, StateEnumeration, Attributes)> for ObjectOwnedResponse {
    fn from(e: (String, StateEnumeration, Attributes)) -> ObjectOwnedResponse {
        ObjectOwnedResponse {
            object_id: e.0,
            state: e.1,
            attributes: e.2,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct ObjectSharedResponse {
    pub object_id: UniqueIdentifier,
    pub owner_id: String,
    pub state: StateEnumeration,
    pub operations: Vec<ObjectOperationTypes>,
}

impl
    From<(
        UniqueIdentifier,
        String,
        StateEnumeration,
        Vec<ObjectOperationTypes>,
    )> for ObjectSharedResponse
{
    fn from(
        e: (
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationTypes>,
        ),
    ) -> ObjectSharedResponse {
        ObjectSharedResponse {
            object_id: e.0,
            owner_id: e.1,
            state: e.2,
            operations: e.3,
        }
    }
}

// Response for success
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct SuccessResponse {
    pub success: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteParams {
    pub nonce: String,
}
