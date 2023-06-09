use cloudproof::reexport::crypto_core::symmetric_crypto::{key::Key, SymKey};
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
#[derive(Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ObjectOperationTypes {
    Create,
    Decrypt,
    Destroy,
    Encrypt,
    Export,
    Get,
    Import,
    Locate,
    Revoke,
    Rekey,
}

impl std::fmt::Debug for ObjectOperationTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for ObjectOperationTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            ObjectOperationTypes::Create => "create",
            ObjectOperationTypes::Decrypt => "decrypt",
            ObjectOperationTypes::Destroy => "destroy",
            ObjectOperationTypes::Encrypt => "encrypt",
            ObjectOperationTypes::Export => "export",
            ObjectOperationTypes::Get => "get",
            ObjectOperationTypes::Import => "import",
            ObjectOperationTypes::Locate => "locate",
            ObjectOperationTypes::Revoke => "revoke",
            ObjectOperationTypes::Rekey => "rekey",
        };
        write!(f, "{str}")
    }
}

#[derive(Clone)]
pub struct ExtraDatabaseParams {
    pub group_id: u128,
    pub key: Key<32>,
}

impl Serialize for ExtraDatabaseParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(
            vec![
                self.group_id.to_be_bytes().to_vec(),
                self.key.as_bytes().to_vec(),
            ]
            .concat()
            .as_slice(),
        )
    }
}

impl<'de> Deserialize<'de> for ExtraDatabaseParams {
    fn deserialize<D>(deserializer: D) -> Result<ExtraDatabaseParams, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let group_id = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
        let key = SymKey::from_bytes(bytes[16..48].try_into().unwrap());
        Ok(ExtraDatabaseParams { group_id, key })
    }
}

use std::{fmt, str::FromStr};

// any error type implementing Display is acceptable.
type ParseError = &'static str;

impl FromStr for ObjectOperationTypes {
    type Err = ParseError;

    fn from_str(op: &str) -> Result<Self, Self::Err> {
        match op {
            "create" => Ok(Self::Create),
            "decrypt" => Ok(Self::Decrypt),
            "destroy" => Ok(Self::Destroy),
            "encrypt" => Ok(Self::Encrypt),
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
pub struct AccessRightsObtainedResponse {
    pub object_id: UniqueIdentifier,
    pub owner_id: String,
    pub state: StateEnumeration,
    pub operations: Vec<ObjectOperationTypes>,
    pub is_wrapped: IsWrapped,
}

impl fmt::Display for AccessRightsObtainedResponse {
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
    )> for AccessRightsObtainedResponse
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
