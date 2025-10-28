use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use strum::{EnumCount, FromRepr};

pub mod extra;
pub mod kmip_attributes;
pub mod kmip_data_structures;
pub mod kmip_messages;
pub mod kmip_objects;
pub mod kmip_operations;
pub mod kmip_types;
pub mod requests;

/// Operation types that can get or create objects
/// These operations use `retrieve` or `get` methods.
#[derive(
    Eq, PartialEq, Serialize, Deserialize, Copy, Clone, Hash, PartialOrd, Ord, FromRepr, EnumCount,
)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum KmipOperation {
    Create = 0,
    Certify = 1,
    Decrypt = 2,
    DeriveKey = 3,
    Destroy = 4,
    Encrypt = 5,
    Export = 6,
    Get = 7,
    GetAttributes = 8,
    Hash = 9,
    Import = 10,
    Locate = 11,
    MAC = 12,
    Revoke = 13,
    Rekey = 14,
    Sign = 15,
    SignatureVerify = 16,
    Validate = 17,
    // This enum gets serialized, so new variants must be added at the end
    // If it's imperative to change their order, consider a migration for Redis's DB
}

impl From<KmipOperation> for u8 {
    #[allow(clippy::as_conversions)] // the discriminants are defined as u8
    fn from(op: KmipOperation) -> Self {
        op as Self
    }
}

impl fmt::Debug for KmipOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for KmipOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            Self::Create => "create",
            Self::Certify => "certify",
            Self::Decrypt => "decrypt",
            Self::DeriveKey => "derive_key",
            Self::Destroy => "destroy",
            Self::Encrypt => "encrypt",
            Self::Export => "export",
            Self::Get => "get",
            Self::GetAttributes => "get_attributes",
            Self::Hash => "hash",
            Self::Import => "import",
            Self::Locate => "locate",
            Self::MAC => "mac",
            Self::Revoke => "revoke",
            Self::Rekey => "rekey",
            Self::Sign => "sign",
            Self::SignatureVerify => "signature_verify",
            Self::Validate => "validate",
        };
        write!(f, "{str}")
    }
}

// any error type implementing Display is acceptable.
type ParseError = &'static str;

impl FromStr for KmipOperation {
    type Err = ParseError;

    fn from_str(op: &str) -> Result<Self, Self::Err> {
        match op {
            "create" => Ok(Self::Create),
            "certify" => Ok(Self::Certify),
            "decrypt" => Ok(Self::Decrypt),
            "derive_key" => Ok(Self::DeriveKey),
            "destroy" => Ok(Self::Destroy),
            "encrypt" => Ok(Self::Encrypt),
            "get_attributes" => Ok(Self::GetAttributes),
            "export" => Ok(Self::Export),
            "get" => Ok(Self::Get),
            "hash" => Ok(Self::Hash),
            "import" => Ok(Self::Import),
            "locate" => Ok(Self::Locate),
            "mac" => Ok(Self::MAC),
            "rekey" => Ok(Self::Rekey),
            "revoke" => Ok(Self::Revoke),
            "sign" => Ok(Self::Sign),
            "signature_verify" => Ok(Self::SignatureVerify),
            "validate" => Ok(Self::Validate),
            _ => Err("Could not parse an operation"),
        }
    }
}
