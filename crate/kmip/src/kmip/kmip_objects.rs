use std::convert::{TryFrom, TryInto};

use num_bigint::BigUint;
use paperclip::actix::Apiv2Schema;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use super::kmip_types::Attributes;
use crate::{
    error::KmipError,
    kmip::{
        kmip_data_structures::KeyBlock,
        kmip_operations::ErrorReason,
        kmip_types::{
            CertificateRequestType, CertificateType, OpaqueDataType, SecretDataType, SplitKeyMethod,
        },
    },
};

/// Object Types
/// Section 2 of KMIP Reference 2.1
///
/// A KMIP Object. The top level structure
/// Serialization is carried out internally tagged :
/// https://serde.rs/enum-representations.html#internally-tagged
/// This is likely not KMIP compliant therefore
/// some JSON gimmicks may be required in and out
///
/// Deserialization is untagged and the `ObjectType` is not at
/// an adjacent level in the structure. Correction code needs to be
/// run post-serialization: for instance `PrivateKey` and `SymmetricKey`
/// share the same internal structure a `SingleKeyBlock`; since `PrivateKey`
/// appears first, a `SymmetricKey` will be deserialized as a `PrivateKey`
///
/// Order matters: `SecretData` will be deserialized as a `PrivateKey` if it
/// appears after despite the presence of `secret_data_type`
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Display, Apiv2Schema)]
#[serde(untagged)]
#[openapi(empty)]
pub enum Object {
    #[serde(rename_all = "PascalCase")]
    Certificate {
        certificate_type: CertificateType,
        certificate_value: Vec<u8>,
    },
    #[serde(rename_all = "PascalCase")]
    CertificateRequest {
        certificate_request_type: CertificateRequestType,
        certificate_request_value: Vec<u8>,
    },
    /// A Managed Object that the key management server is possibly not able to
    /// interpret. The context information for this object MAY be stored and
    /// retrieved using Custom Attributes. An Opaque Object MAY be a Managed
    /// Cryptographic Object depending on the client context of usage and as
    /// such is treated in the same manner as a Managed Cryptographic Object
    /// for handling of attributes.
    OpaqueObject {
        opaque_data_type: OpaqueDataType,
        opaque_data_value: Vec<u8>,
    },
    /// A Managed Cryptographic Object that is a text-based representation of a
    /// PGP key. The Key Block field, indicated below, will contain the
    /// ASCII-armored export of a PGP key in the format as specified in RFC
    /// 4880. It MAY contain only a public key block, or both a public and
    /// private key block. Two different versions of PGP keys, version 3 and
    /// version 4, MAY be stored in this Managed Cryptographic Object.
    /// kmip-spec-v2.1-cs01 07 May 2020 Standards Track Work Product
    /// Copyright © OASIS Open 2020. All Rights Reserved. Page 20 of 240
    /// KMIP implementers SHOULD treat the Key Block field as an opaque
    /// blob. PGP-aware KMIP clients SHOULD take on the responsibility
    /// of decomposing the Key Block into other Managed Cryptographic
    /// Objects (Public Keys, Private Keys, etc.).
    PGPKey {
        #[serde(rename = "PGPKeyVersion")]
        pgp_key_version: u32,
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },
    #[serde(rename_all = "PascalCase")]
    SecretData {
        secret_data_type: SecretDataType,
        key_block: KeyBlock,
    },
    /// A Managed Cryptographic Object that is a Split Key. A split key is a
    /// secret, usually a symmetric key or a private key that has been split
    /// into a number of parts, each of which MAY then be distributed to
    /// several key holders, for additional security. The Split Key Parts
    /// field indicates the total number of parts, and the
    /// kmip-spec-v2.1-cs01 07 May 2020 Standards Track Work Product
    /// Copyright © OASIS Open 2020. All Rights Reserved. Page 21 of 240
    /// Split Key Threshold field indicates the minimum number of parts
    /// needed to reconstruct the entire key. The Key Part Identifier
    /// indicates which key part is contained in the cryptographic
    /// object, and SHALL be at least 1 and SHALL be less than or equal to Split
    /// Key Parts.
    #[serde(rename_all = "PascalCase")]
    SplitKey {
        split_key_parts: u32,
        key_part_identifier: u32,
        split_key_threshold: u32,
        split_key_method: SplitKeyMethod,
        /// REQUIRED only if Split Key Method is Polynomial Sharing Prime Field.
        #[serde(skip_serializing_if = "Option::is_none")]
        prime_field_size: Option<BigUint>,
        key_block: KeyBlock,
    },
    PrivateKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },
    PublicKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },
    SymmetricKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },
}

impl Object {
    /// Returns the corresponding `ObjectType` for that object
    #[must_use]
    pub fn object_type(&self) -> ObjectType {
        match self {
            Object::Certificate { .. } => ObjectType::Certificate,
            Object::CertificateRequest { .. } => ObjectType::CertificateRequest,
            Object::OpaqueObject { .. } => ObjectType::OpaqueObject,
            Object::PGPKey { .. } => ObjectType::PGPKey,
            Object::PrivateKey { .. } => ObjectType::PrivateKey,
            Object::PublicKey { .. } => ObjectType::PublicKey,
            Object::SecretData { .. } => ObjectType::SecretData,
            Object::SplitKey { .. } => ObjectType::SplitKey,
            Object::SymmetricKey { .. } => ObjectType::SymmetricKey,
        }
    }

    /// Returns the `KeyBlock` of that object if any, an error otherwise
    pub fn key_block(&self) -> Result<&KeyBlock, KmipError> {
        match self {
            Object::PublicKey { key_block }
            | Object::PrivateKey { key_block }
            | Object::SecretData { key_block, .. }
            | Object::PGPKey { key_block, .. }
            | Object::SymmetricKey { key_block }
            | Object::SplitKey { key_block, .. } => Ok(key_block),
            _ => Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "This object does not have a key block".to_string(),
            )),
        }
    }

    /// Check if the key is wrapped
    pub fn is_wrapped(&self) -> Result<bool, KmipError> {
        Ok(self.key_block()?.key_wrapping_data.as_ref().is_some())
    }

    /// Returns the `Attributes` of that object if any, an error otherwise
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        self.key_block()?.key_value.attributes()
    }

    /// Returns the `Attributes` of that object if any, an error otherwise
    pub fn attributes_mut(&mut self) -> Result<&mut Attributes, KmipError> {
        self.key_block_mut()?.key_value.attributes_mut()
    }

    /// Returns the `KeyBlock` of that object if any, an error otherwise
    pub fn key_block_mut(&mut self) -> Result<&mut KeyBlock, KmipError> {
        match self {
            Object::PublicKey { key_block }
            | Object::PrivateKey { key_block }
            | Object::SecretData { key_block, .. }
            | Object::PGPKey { key_block, .. }
            | Object::SymmetricKey { key_block }
            | Object::SplitKey { key_block, .. } => Ok(key_block),
            _ => Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "This object does not have a key block".to_string(),
            )),
        }
    }

    /// Deserialization is untagged and the `ObjectType` is not at
    /// an adjacent level in the structure. Correction code needs to be
    /// run post-serialization
    /// see `Object` for details
    #[must_use]
    pub fn post_fix(object_type: ObjectType, object: Object) -> Object {
        match object_type {
            ObjectType::SymmetricKey => match object {
                Object::PrivateKey { key_block } | Object::PublicKey { key_block } => {
                    Object::SymmetricKey { key_block }
                }
                _ => object,
            },
            ObjectType::PublicKey => match object {
                Object::SymmetricKey { key_block } | Object::PrivateKey { key_block } => {
                    Object::PublicKey { key_block }
                }
                _ => object,
            },
            ObjectType::PrivateKey => match object {
                Object::SymmetricKey { key_block } | Object::PublicKey { key_block } => {
                    Object::PrivateKey { key_block }
                }
                _ => object,
            },
            _ => object,
        }
    }
}

impl TryFrom<&[u8]> for Object {
    type Error = KmipError;

    fn try_from(object_bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(object_bytes).map_err(|_e| {
            Self::Error::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing to an Object".to_string(),
            )
        })
    }
}

impl TryInto<Vec<u8>> for Object {
    type Error = KmipError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&self).map_err(|_e| {
            Self::Error::InvalidKmipObject(
                ErrorReason::Invalid_Attribute_Value,
                "failed serializing Object to bytes".to_string(),
            )
        })
    }
}

/// The type of a KMIP Objects
#[allow(non_camel_case_types)]
#[allow(clippy::enum_clike_unportable_variant)]
#[derive(
    Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, EnumString, Display, Apiv2Schema,
)]
#[serde(rename_all = "PascalCase")]
pub enum ObjectType {
    Certificate = 0x0000_0001,
    SymmetricKey = 0x0000_0002,
    PublicKey = 0x0000_0003,
    PrivateKey = 0x0000_0004,
    SplitKey = 0x0000_0005,
    SecretData = 0x0000_0007,
    OpaqueObject = 0x0000_0008,
    PGPKey = 0x0000_0009,
    CertificateRequest = 0x0000_000A,
}
