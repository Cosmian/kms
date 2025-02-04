use std::{
    convert::TryFrom,
    fmt::Display,
    hash::{DefaultHasher, Hash, Hasher},
};

use serde::{Deserialize, Serialize};
use strum::EnumIter;

#[allow(clippy::wildcard_imports)]
use super::{kmip_data_structures::KeyBlock, kmip_types::*};
use crate::error::KmipError;

/// Object Types
/// Section 2 of KMIP 1.4 Specification
///
/// A KMIP Object. The top level structure
/// Serialization is carried out internally tagged
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(untagged)]
pub enum Object {
    /// A Managed Cryptographic Object that is a digital certificate.
    /// It is a DER-encoded X.509 public key certificate.
    #[serde(rename_all = "PascalCase")]
    Certificate {
        certificate_type: CertificateType,
        certificate_value: Vec<u8>,
    },

    /// A Managed Cryptographic Object containing a shared secret value that is not
    /// a key or certificate (e.g., a password).
    #[serde(rename_all = "PascalCase")]
    SecretData {
        secret_data_type: SecretDataType,
        key_block: KeyBlock,
    },

    /// A Managed Cryptographic Object that is a Split Key.
    #[serde(rename_all = "PascalCase")]
    SplitKey {
        split_key_parts: u32,
        key_part_identifier: u32,
        split_key_threshold: u32,
        split_key_method: SplitKeyMethod,
        key_block: KeyBlock,
    },

    /// A Managed Cryptographic Object that is a symmetric key.
    SymmetricKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },

    /// A Managed Cryptographic Object that is the private portion of an asymmetric key pair.
    PrivateKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },

    /// A Managed Cryptographic Object that is the public portion of an asymmetric key pair.
    PublicKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },

    /// A Managed Object that is possibly not interpretable by the key management system.
    OpaqueObject {
        opaque_data_type: OpaqueDataType,
        opaque_data_value: Vec<u8>,
    },

    /// A Managed Cryptographic Object that is a PGP key.
    PGPKey {
        #[serde(rename = "PGPKeyVersion")]
        pgp_key_version: u32,
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },
}

impl Display for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate {
                certificate_type,
                certificate_value,
            } => {
                write!(
                    f,
                    "Certificate(certificate_type: {certificate_type:?}, certificate_value: \
                     {certificate_value:?})"
                )
            }
            Self::SecretData {
                secret_data_type,
                key_block,
            } => {
                write!(
                    f,
                    "SecretData(secret_data_type: {secret_data_type:?}, key_block: {key_block:?})"
                )
            }
            Self::SplitKey {
                split_key_parts,
                key_part_identifier,
                split_key_threshold,
                split_key_method,
                key_block,
            } => {
                write!(
                    f,
                    "SplitKey(split_key_parts: {split_key_parts}, key_part_identifier: \
                     {key_part_identifier}, split_key_threshold: {split_key_threshold}, \
                     split_key_method: {split_key_method:?}, key_block: {key_block:?})"
                )
            }
            Self::SymmetricKey { key_block } => write!(f, "SymmetricKey(key_block: {key_block:?})"),
            Self::PrivateKey { key_block } => write!(f, "PrivateKey(key_block: {key_block:?})"),
            Self::PublicKey { key_block } => write!(f, "PublicKey(key_block: {key_block:?})"),
            Self::OpaqueObject {
                opaque_data_type,
                opaque_data_value,
            } => {
                write!(
                    f,
                    "OpaqueObject(opaque_data_type: {opaque_data_type:?}, opaque_data_value: \
                     {opaque_data_value:?})"
                )
            }
            Self::PGPKey {
                pgp_key_version,
                key_block,
            } => {
                write!(
                    f,
                    "PGPKey(pgp_key_version: {pgp_key_version}, key_block: {key_block:?})"
                )
            }
        }
    }
}

impl Object {
    /// Returns the corresponding `ObjectType` for that object
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        match self {
            Self::Certificate { .. } => ObjectType::Certificate,
            Self::SecretData { .. } => ObjectType::SecretData,
            Self::SplitKey { .. } => ObjectType::SplitKey,
            Self::SymmetricKey { .. } => ObjectType::SymmetricKey,
            Self::PrivateKey { .. } => ObjectType::PrivateKey,
            Self::PublicKey { .. } => ObjectType::PublicKey,
            Self::OpaqueObject { .. } => ObjectType::OpaqueObject,
            Self::PGPKey { .. } => ObjectType::PGPKey,
        }
    }

    /// Returns the `KeyBlock` of that object if any, an error otherwise
    pub fn key_block(&self) -> Result<&KeyBlock, KmipError> {
        match self {
            Self::SymmetricKey { key_block }
            | Self::PrivateKey { key_block }
            | Self::PublicKey { key_block }
            | Self::SecretData { key_block, .. }
            | Self::PGPKey { key_block, .. }
            | Self::SplitKey { key_block, .. } => Ok(key_block),
            _ => Err(KmipError::InvalidKmip14Object(
                ResultReason::InvalidField,
                "This object does not have a key block".to_owned(),
            )),
        }
    }

    /// Returns a mutable reference to the `KeyBlock` of that object if any, an error otherwise
    pub fn key_block_mut(&mut self) -> Result<&mut KeyBlock, KmipError> {
        match self {
            Self::SymmetricKey { key_block }
            | Self::PrivateKey { key_block }
            | Self::PublicKey { key_block }
            | Self::SecretData { key_block, .. }
            | Self::PGPKey { key_block, .. }
            | Self::SplitKey { key_block, .. } => Ok(key_block),
            _ => Err(KmipError::InvalidKmip14Object(
                ResultReason::InvalidField,
                "This object does not have a key block".to_owned(),
            )),
        }
    }

    /// Gets a hash value for the object
    #[must_use]
    pub fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        match self {
            Self::Certificate {
                certificate_type,
                certificate_value,
            } => {
                certificate_type.hash(&mut hasher);
                certificate_value.hash(&mut hasher);
            }
            Self::SecretData {
                secret_data_type,
                key_block,
            } => {
                secret_data_type.hash(&mut hasher);
                key_block.hash(&mut hasher);
            }
            Self::SplitKey {
                split_key_parts,
                key_part_identifier,
                split_key_threshold,
                split_key_method,
                key_block,
            } => {
                split_key_parts.hash(&mut hasher);
                key_part_identifier.hash(&mut hasher);
                split_key_threshold.hash(&mut hasher);
                split_key_method.hash(&mut hasher);
                key_block.hash(&mut hasher);
            }
            Self::SymmetricKey { key_block }
            | Self::PrivateKey { key_block }
            | Self::PublicKey { key_block } => {
                key_block.hash(&mut hasher);
            }
            Self::OpaqueObject {
                opaque_data_type,
                opaque_data_value,
            } => {
                opaque_data_type.hash(&mut hasher);
                opaque_data_value.hash(&mut hasher);
            }
            Self::PGPKey {
                pgp_key_version,
                key_block,
            } => {
                pgp_key_version.hash(&mut hasher);
                key_block.hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}

/// The type of a KMIP 1.4 Objects
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
#[serde(rename_all = "PascalCase")]
#[repr(u32)]
pub enum ObjectType {
    Certificate = 0x01,
    SymmetricKey = 0x02,
    PublicKey = 0x03,
    PrivateKey = 0x04,
    SplitKey = 0x05,
    Template = 0x06,
    SecretData = 0x07,
    OpaqueObject = 0x08,
    PGPKey = 0x09,
}

impl From<ObjectType> for u32 {
    fn from(object_type: ObjectType) -> Self {
        match object_type {
            ObjectType::Certificate => 0x01,
            ObjectType::SymmetricKey => 0x02,
            ObjectType::PublicKey => 0x03,
            ObjectType::PrivateKey => 0x04,
            ObjectType::SplitKey => 0x05,
            ObjectType::Template => 0x06,
            ObjectType::SecretData => 0x07,
            ObjectType::OpaqueObject => 0x08,
            ObjectType::PGPKey => 0x09,
        }
    }
}

impl TryFrom<u32> for ObjectType {
    type Error = KmipError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Certificate),
            0x02 => Ok(Self::SymmetricKey),
            0x03 => Ok(Self::PublicKey),
            0x04 => Ok(Self::PrivateKey),
            0x05 => Ok(Self::SplitKey),
            0x06 => Ok(Self::Template),
            0x07 => Ok(Self::SecretData),
            0x08 => Ok(Self::OpaqueObject),
            0x09 => Ok(Self::PGPKey),
            _ => Err(KmipError::InvalidKmip14Value(
                ResultReason::InvalidField,
                format!("Invalid Object Type value: {value}"),
            )),
        }
    }
}

impl Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate => write!(f, "Certificate"),
            Self::SymmetricKey => write!(f, "Symmetric Key"),
            Self::PublicKey => write!(f, "Public Key"),
            Self::PrivateKey => write!(f, "Private Key"),
            Self::SplitKey => write!(f, "Split Key"),
            Self::Template => write!(f, "Template"),
            Self::SecretData => write!(f, "Secret Data"),
            Self::OpaqueObject => write!(f, "Opaque Object"),
            Self::PGPKey => write!(f, "PGP Key"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_display() {
        assert_eq!(ObjectType::Certificate.to_string(), "Certificate");
        assert_eq!(ObjectType::SymmetricKey.to_string(), "Symmetric Key");
        assert_eq!(ObjectType::PublicKey.to_string(), "Public Key");
        assert_eq!(ObjectType::PrivateKey.to_string(), "Private Key");
        assert_eq!(ObjectType::SplitKey.to_string(), "Split Key");
        assert_eq!(ObjectType::Template.to_string(), "Template");
        assert_eq!(ObjectType::SecretData.to_string(), "Secret Data");
        assert_eq!(ObjectType::OpaqueObject.to_string(), "Opaque Object");
        assert_eq!(ObjectType::PGPKey.to_string(), "PGP Key");
    }

    #[test]
    fn test_object_type_try_from() {
        assert_eq!(ObjectType::try_from(0x01).unwrap(), ObjectType::Certificate);
        assert_eq!(
            ObjectType::try_from(0x02).unwrap(),
            ObjectType::SymmetricKey
        );
        assert_eq!(ObjectType::try_from(0x03).unwrap(), ObjectType::PublicKey);
        assert_eq!(ObjectType::try_from(0x04).unwrap(), ObjectType::PrivateKey);
        assert_eq!(ObjectType::try_from(0x05).unwrap(), ObjectType::SplitKey);
        assert_eq!(ObjectType::try_from(0x06).unwrap(), ObjectType::Template);
        assert_eq!(ObjectType::try_from(0x07).unwrap(), ObjectType::SecretData);
        assert_eq!(
            ObjectType::try_from(0x08).unwrap(),
            ObjectType::OpaqueObject
        );
        assert_eq!(ObjectType::try_from(0x09).unwrap(), ObjectType::PGPKey);
        ObjectType::try_from(0x0A).unwrap_err();
    }

    #[test]
    fn test_object_type_from() {
        assert_eq!(u32::from(ObjectType::Certificate), 0x01);
        assert_eq!(u32::from(ObjectType::SymmetricKey), 0x02);
        assert_eq!(u32::from(ObjectType::PublicKey), 0x03);
        assert_eq!(u32::from(ObjectType::PrivateKey), 0x04);
        assert_eq!(u32::from(ObjectType::SplitKey), 0x05);
        assert_eq!(u32::from(ObjectType::Template), 0x06);
        assert_eq!(u32::from(ObjectType::SecretData), 0x07);
        assert_eq!(u32::from(ObjectType::OpaqueObject), 0x08);
        assert_eq!(u32::from(ObjectType::PGPKey), 0x09);
    }
}
