use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use strum::{EnumCount, FromRepr};

pub mod attribute_policy;
pub mod extra;
pub mod kmip_attributes;
pub mod kmip_data_structures;
pub mod kmip_messages;
pub mod kmip_objects;
pub mod kmip_operations;
pub mod kmip_types;
pub mod requests;

/// Per-object access right: what a user may be granted on a Managed Object
/// (`Grant`/`Revoke` access, ownership checks in operation handlers).
///
/// Deliberately a subset of the KMIP operations and **not** the role policy: role checks
/// cover every KMIP operation through `cosmian_kms_access::access::Role::decide` over
/// [`kmip_types::OperationEnumeration`]. Add a variant only for a new grantable right.
///
/// Persisted, never change or reuse: the `u8` discriminant (Redis-findex permission
/// triples, via `FromRepr`) and the lowercase serde name (SQL permission JSON, REST access
/// API). A new variant takes the next unused discriminant; declaration order is irrelevant.
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
    SetAttribute = 18,
    ModifyAttribute = 19,
    AddAttribute = 20,
    DeleteAttribute = 21,
    Activate = 22,
}

impl From<KmipOperation> for u8 {
    fn from(op: KmipOperation) -> Self {
        match op {
            KmipOperation::Create => 0,
            KmipOperation::Certify => 1,
            KmipOperation::Decrypt => 2,
            KmipOperation::DeriveKey => 3,
            KmipOperation::Destroy => 4,
            KmipOperation::Encrypt => 5,
            KmipOperation::Export => 6,
            KmipOperation::Get => 7,
            KmipOperation::GetAttributes => 8,
            KmipOperation::Hash => 9,
            KmipOperation::Import => 10,
            KmipOperation::Locate => 11,
            KmipOperation::MAC => 12,
            KmipOperation::Revoke => 13,
            KmipOperation::Rekey => 14,
            KmipOperation::Sign => 15,
            KmipOperation::SignatureVerify => 16,
            KmipOperation::Validate => 17,
            KmipOperation::SetAttribute => 18,
            KmipOperation::ModifyAttribute => 19,
            KmipOperation::AddAttribute => 20,
            KmipOperation::DeleteAttribute => 21,
            KmipOperation::Activate => 22,
        }
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
            Self::SetAttribute => "set_attribute",
            Self::ModifyAttribute => "modify_attribute",
            Self::AddAttribute => "add_attribute",
            Self::DeleteAttribute => "delete_attribute",
            Self::Activate => "activate",
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
            "set_attribute" => Ok(Self::SetAttribute),
            "modify_attribute" => Ok(Self::ModifyAttribute),
            "add_attribute" => Ok(Self::AddAttribute),
            "delete_attribute" => Ok(Self::DeleteAttribute),
            "activate" => Ok(Self::Activate),
            _ => Err("Could not parse an operation"),
        }
    }
}
