use std::{
    convert::TryFrom,
    fmt::Display,
    hash::{DefaultHasher, Hash, Hasher},
};

use serde::{Deserialize, Serialize};
use strum::{EnumIter, VariantNames};

#[allow(clippy::wildcard_imports)]
use super::{kmip_data_structures::KeyBlock, kmip_types::*};
use crate::{error::KmipError, kmip_2_1};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Certificate {
    pub certificate_type: CertificateType,
    pub certificate_value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SecretData {
    pub secret_data_type: SecretDataType,
    pub key_block: KeyBlock,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SplitKey {
    pub split_key_parts: u32,
    pub key_part_identifier: u32,
    pub split_key_threshold: u32,
    pub split_key_method: SplitKeyMethod,
    pub key_block: KeyBlock,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SymmetricKey {
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PrivateKey {
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PublicKey {
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct OpaqueObject {
    pub opaque_data_type: OpaqueDataType,
    pub opaque_data_value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PGPKey {
    #[serde(rename = "PGPKeyVersion")]
    pub pgp_key_version: u32,
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, VariantNames)]
#[serde(untagged)]
pub enum Object {
    Certificate(Certificate),
    SecretData(SecretData),
    SplitKey(SplitKey),
    SymmetricKey(SymmetricKey),
    PrivateKey(PrivateKey),
    PublicKey(PublicKey),
    OpaqueObject(OpaqueObject),
    PGPKey(PGPKey),
}

impl Display for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate(Certificate {
                certificate_type,
                certificate_value,
            }) => {
                write!(
                    f,
                    "Certificate(certificate_type: {certificate_type:?}, certificate_value: \
                     {certificate_value:?})"
                )
            }
            Self::SecretData(SecretData {
                secret_data_type,
                key_block,
            }) => {
                write!(
                    f,
                    "SecretData(secret_data_type: {secret_data_type:?}, key_block: {key_block:?})"
                )
            }
            Self::SplitKey(SplitKey {
                split_key_parts,
                key_part_identifier,
                split_key_threshold,
                split_key_method,
                key_block,
            }) => {
                write!(
                    f,
                    "SplitKey(split_key_parts: {split_key_parts}, key_part_identifier: \
                     {key_part_identifier}, split_key_threshold: {split_key_threshold}, \
                     split_key_method: {split_key_method:?}, key_block: {key_block:?})"
                )
            }
            Self::SymmetricKey(SymmetricKey { key_block }) => {
                write!(f, "SymmetricKey(key_block: {key_block:?})")
            }
            Self::PrivateKey(PrivateKey { key_block }) => {
                write!(f, "PrivateKey(key_block: {key_block:?})")
            }
            Self::PublicKey(PublicKey { key_block }) => {
                write!(f, "PublicKey(key_block: {key_block:?})")
            }
            Self::OpaqueObject(OpaqueObject {
                opaque_data_type,
                opaque_data_value,
            }) => {
                write!(
                    f,
                    "OpaqueObject(opaque_data_type: {opaque_data_type:?}, opaque_data_value: \
                     {opaque_data_value:?})"
                )
            }
            Self::PGPKey(PGPKey {
                pgp_key_version,
                key_block,
            }) => {
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
            Self::SymmetricKey(SymmetricKey { key_block })
            | Self::PrivateKey(PrivateKey { key_block })
            | Self::PublicKey(PublicKey { key_block })
            | Self::SecretData(SecretData { key_block, .. })
            | Self::PGPKey(PGPKey { key_block, .. })
            | Self::SplitKey(SplitKey { key_block, .. }) => Ok(key_block),
            _ => Err(KmipError::InvalidKmip14Object(
                ResultReason::InvalidField,
                "This object does not have a key block".to_owned(),
            )),
        }
    }

    pub fn key_block_mut(&mut self) -> Result<&mut KeyBlock, KmipError> {
        match self {
            Self::SymmetricKey(SymmetricKey { key_block })
            | Self::PrivateKey(PrivateKey { key_block })
            | Self::PublicKey(PublicKey { key_block })
            | Self::SecretData(SecretData { key_block, .. })
            | Self::PGPKey(PGPKey { key_block, .. })
            | Self::SplitKey(SplitKey { key_block, .. }) => Ok(key_block),
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
            Self::Certificate(Certificate {
                certificate_type,
                certificate_value,
            }) => {
                certificate_type.hash(&mut hasher);
                certificate_value.hash(&mut hasher);
            }
            Self::SecretData(SecretData {
                secret_data_type,
                key_block,
            }) => {
                secret_data_type.hash(&mut hasher);
                key_block.hash(&mut hasher);
            }
            Self::SplitKey(SplitKey {
                split_key_parts,
                key_part_identifier,
                split_key_threshold,
                split_key_method,
                key_block,
            }) => {
                split_key_parts.hash(&mut hasher);
                key_part_identifier.hash(&mut hasher);
                split_key_threshold.hash(&mut hasher);
                split_key_method.hash(&mut hasher);
                key_block.hash(&mut hasher);
            }
            Self::SymmetricKey(SymmetricKey { key_block })
            | Self::PrivateKey(PrivateKey { key_block })
            | Self::PublicKey(PublicKey { key_block }) => {
                key_block.hash(&mut hasher);
            }
            Self::OpaqueObject(OpaqueObject {
                opaque_data_type,
                opaque_data_value,
            }) => {
                opaque_data_type.hash(&mut hasher);
                opaque_data_value.hash(&mut hasher);
            }
            Self::PGPKey(PGPKey {
                pgp_key_version,
                key_block,
            }) => {
                pgp_key_version.hash(&mut hasher);
                key_block.hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}

impl Object {
    fn to_kmip_2_1(&self) -> kmip_2_1::kmip_objects::Object {
        match self {
            Self::Certificate(cert) => {
                let certificate_2_1 = kmip_2_1::kmip_objects::Certificate {
                    certificate_type: cert.certificate_type.to_kmip_2_1(),
                    certificate_value: cert.certificate_value.clone(),
                };
                kmip_2_1::kmip_objects::Object::Certificate(certificate_2_1)
            }
            Self::SecretData(secret) => {
                let secret_data_2_1 = kmip_2_1::kmip_objects::SecretData {
                    secret_data_type: secret.secret_data_type.to_kmip_2_1(),
                    key_block: secret.key_block.to_kmip_2_1(),
                };
                kmip_2_1::kmip_objects::Object::SecretData(secret_data_2_1)
            }
            Self::SplitKey(split) => {
                let split_key_2_1 = kmip_2_1::kmip_objects::SplitKey {
                    split_key_parts: split.split_key_parts,
                    key_part_identifier: split.key_part_identifier,
                    split_key_threshold: split.split_key_threshold,
                    split_key_method: convert_split_key_method(&split.split_key_method),
                    prime_field_size: None, // Not present in KMIP 1.4
                    key_block: convert_key_block(&split.key_block),
                };
                kmip_2_1::kmip_objects::Object::SplitKey(split_key_2_1)
            }
            Self::SymmetricKey(symmetric) => {
                let symmetric_key_2_1 = kmip_2_1::kmip_objects::SymmetricKey {
                    key_block: convert_key_block(&symmetric.key_block),
                };
                kmip_2_1::kmip_objects::Object::SymmetricKey(symmetric_key_2_1)
            }
            Self::PrivateKey(private) => {
                let private_key_2_1 = kmip_2_1::kmip_objects::PrivateKey {
                    key_block: convert_key_block(&private.key_block),
                };
                kmip_2_1::kmip_objects::Object::PrivateKey(private_key_2_1)
            }
            Self::PublicKey(public) => {
                let public_key_2_1 = kmip_2_1::kmip_objects::PublicKey {
                    key_block: convert_key_block(&public.key_block),
                };
                kmip_2_1::kmip_objects::Object::PublicKey(public_key_2_1)
            }
            Self::OpaqueObject(opaque) => {
                let opaque_object_2_1 = kmip_2_1::kmip_objects::OpaqueObject {
                    opaque_data_type: convert_opaque_data_type(&opaque.opaque_data_type),
                    opaque_data_value: opaque.opaque_data_value.clone(),
                };
                kmip_2_1::kmip_objects::Object::OpaqueObject(opaque_object_2_1)
            }
            Self::PGPKey(pgp) => {
                let pgp_key_2_1 = kmip_2_1::kmip_objects::PGPKey {
                    pgp_key_version: pgp.pgp_key_version,
                    key_block: convert_key_block(&pgp.key_block),
                };
                kmip_2_1::kmip_objects::Object::PGPKey(pgp_key_2_1)
            }
        }
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
