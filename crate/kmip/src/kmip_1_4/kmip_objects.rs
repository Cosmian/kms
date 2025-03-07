use std::{convert::TryFrom, fmt::Display};

use num_bigint_dig::BigInt;
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

impl From<Certificate> for kmip_2_1::kmip_objects::Certificate {
    fn from(val: Certificate) -> Self {
        Self {
            certificate_type: val.certificate_type.clone().into(),
            certificate_value: val.certificate_value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SecretData {
    pub secret_data_type: SecretDataType,
    pub key_block: KeyBlock,
}

impl From<SecretData> for kmip_2_1::kmip_objects::SecretData {
    fn from(val: SecretData) -> Self {
        Self {
            secret_data_type: val.secret_data_type.clone().into(),
            key_block: val.key_block.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SplitKey {
    pub split_key_parts: i32,
    pub key_part_identifier: i32,
    pub split_key_threshold: i32,
    pub split_key_method: SplitKeyMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prime_field_size: Option<BigInt>,
    pub key_block: KeyBlock,
}

impl From<SplitKey> for kmip_2_1::kmip_objects::SplitKey {
    fn from(val: SplitKey) -> Self {
        Self {
            split_key_parts: val.split_key_parts,
            key_part_identifier: val.key_part_identifier,
            split_key_threshold: val.split_key_threshold,
            split_key_method: val.split_key_method.into(),
            key_block: val.key_block.clone().into(),
            prime_field_size: val.prime_field_size,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SymmetricKey {
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

impl From<SymmetricKey> for kmip_2_1::kmip_objects::SymmetricKey {
    fn from(val: SymmetricKey) -> Self {
        Self {
            key_block: val.key_block.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PrivateKey {
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

impl From<PrivateKey> for kmip_2_1::kmip_objects::PrivateKey {
    fn from(val: PrivateKey) -> Self {
        Self {
            key_block: val.key_block.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PublicKey {
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

impl From<PublicKey> for kmip_2_1::kmip_objects::PublicKey {
    fn from(val: PublicKey) -> Self {
        Self {
            key_block: val.key_block.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct OpaqueObject {
    pub opaque_data_type: OpaqueDataType,
    pub opaque_data_value: Vec<u8>,
}

impl From<OpaqueObject> for kmip_2_1::kmip_objects::OpaqueObject {
    fn from(val: OpaqueObject) -> Self {
        Self {
            opaque_data_type: val.opaque_data_type.into(),
            opaque_data_value: val.opaque_data_value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PGPKey {
    #[serde(rename = "PGPKeyVersion")]
    pub pgp_key_version: u32,
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

impl From<PGPKey> for kmip_2_1::kmip_objects::PGPKey {
    fn from(val: PGPKey) -> Self {
        Self {
            pgp_key_version: val.pgp_key_version,
            key_block: val.key_block.into(),
        }
    }
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
                prime_field_size,
            }) => {
                write!(
                    f,
                    "SplitKey(split_key_parts: {split_key_parts}, key_part_identifier: \
                     {key_part_identifier}, split_key_threshold: {split_key_threshold}, \
                     split_key_method: {split_key_method:?}, key_block: {key_block:?}, prime \
                     field size: {prime_field_size:?})"
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
}

impl From<Object> for kmip_2_1::kmip_objects::Object {
    fn from(val: Object) -> Self {
        match val {
            Object::Certificate(cert) => Self::Certificate(cert.into()),
            Object::SecretData(secret) => Self::SecretData(secret.into()),
            Object::SplitKey(split) => Self::SplitKey(split.into()),
            Object::SymmetricKey(symmetric) => Self::SymmetricKey(symmetric.into()),
            Object::PrivateKey(private) => Self::PrivateKey(private.into()),
            Object::PublicKey(public) => Self::PublicKey(public.into()),
            Object::OpaqueObject(opaque) => Self::OpaqueObject(opaque.into()),
            Object::PGPKey(pgp) => Self::PGPKey(pgp.into()),
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
    // Unsupported in KMIP 2.1 and deactivated in KMIP 1.4
    // Template = 0x06,
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
            // ObjectType::Template => 0x06,
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
            0x06 => Err(KmipError::InvalidKmip14Value(
                ResultReason::InvalidField,
                "Template is not supported in this version of KMIP 1.4".to_owned(),
            )),
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
        assert_eq!(u32::from(ObjectType::SecretData), 0x07);
        assert_eq!(u32::from(ObjectType::OpaqueObject), 0x08);
        assert_eq!(u32::from(ObjectType::PGPKey), 0x09);
    }
}
