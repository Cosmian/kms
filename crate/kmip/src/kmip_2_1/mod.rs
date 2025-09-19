use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

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
#[derive(Eq, PartialEq, Serialize, Deserialize, Copy, Clone, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum KmipOperation {
    Create,
    Certify,
    Decrypt,
    DeriveKey,
    Destroy,
    Encrypt,
    Export,
    Get,
    GetAttributes,
    Hash,
    Import,
    Locate,
    MAC,
    Revoke,
    Rekey,
    Sign,
    SignatureVerify,
    Validate,
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
