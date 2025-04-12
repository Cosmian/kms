use std::fmt::{self, Display};

use num_bigint_dig::BigInt;
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Serialize,
};
use strum::VariantNames;
use tracing::trace;

#[allow(clippy::wildcard_imports)]
use super::{kmip_data_structures::KeyBlock, kmip_types::*};
use crate::{
    error::KmipError,
    kmip_0::kmip_types::{CertificateType, SecretDataType},
    kmip_2_1,
};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Certificate {
    pub certificate_type: CertificateType,
    pub certificate_value: Vec<u8>,
}

impl From<Certificate> for kmip_2_1::kmip_objects::Certificate {
    fn from(val: Certificate) -> Self {
        Self {
            certificate_type: val.certificate_type,
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
            secret_data_type: val.secret_data_type,
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
#[serde(rename_all = "PascalCase")]
pub struct SymmetricKey {
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
#[serde(rename_all = "PascalCase")]
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
#[serde(rename_all = "PascalCase")]
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
#[serde(rename_all = "PascalCase")]
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
#[serde(rename_all = "PascalCase")]
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

#[derive(Debug, Serialize, Clone, Eq, PartialEq, VariantNames)]
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

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Object;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an Object enumeration")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                // let mut object_type: Option<ObjectType> = None;
                if let Some(key) = map.next_key::<String>()? {
                    trace!("Object Visitor: visit_map: key: {key:?}, ");
                    if !Object::VARIANTS.contains(&key.as_str()) {
                        return Err(serde::de::Error::custom(format!(
                            "Unknown Object to deserialize: {key}. Known Objects are: {:?}",
                            Object::VARIANTS
                        )));
                    }
                    return match key.as_str() {
                        "SymmetricKey" => {
                            let key = map.next_value::<SymmetricKey>()?;
                            Ok(Object::SymmetricKey(key))
                        }
                        "PublicKey" => {
                            let key = map.next_value::<PublicKey>()?;
                            Ok(Object::PublicKey(key))
                        }
                        "PrivateKey" => {
                            let key = map.next_value::<PrivateKey>()?;
                            Ok(Object::PrivateKey(key))
                        }
                        "SplitKey" => {
                            let key = map.next_value::<SplitKey>()?;
                            Ok(Object::SplitKey(key))
                        }
                        "SecretData" => {
                            let key = map.next_value::<SecretData>()?;
                            Ok(Object::SecretData(key))
                        }
                        "PGPKey" => {
                            let key = map.next_value::<PGPKey>()?;
                            Ok(Object::PGPKey(key))
                        }
                        "OpaqueObject" => {
                            let key = map.next_value::<OpaqueObject>()?;
                            Ok(Object::OpaqueObject(key))
                        }
                        "Certificate" => {
                            let key = map.next_value::<Certificate>()?;
                            Ok(Object::Certificate(key))
                        }
                        x => Err(serde::de::Error::custom(format!(
                            "Invalid Object: {x}. One of the following is expected: {:?}",
                            Object::VARIANTS
                        ))),
                    };
                }
                Err(serde::de::Error::custom("Invalid Object"))
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
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
