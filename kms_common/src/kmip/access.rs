use serde::{Deserialize, Serialize};

use crate::kmip::kmip_types::UniqueIdentifier;

// Response for success
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct ResponseSuccess {
    pub success: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Access {
    /// Determines the object being requested. If omitted, then the ID
    /// Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// User identifier, beneficiary of the access
    pub userid: String,
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
