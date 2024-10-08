use std::{convert::TryFrom, fmt::Display};

use clap::ValueEnum;
use num_bigint_dig::BigUint;
use serde::{Deserialize, Serialize};
use strum::EnumIter;

use super::{kmip_data_structures::KeyWrappingData, kmip_types::Attributes};
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
/// `https://serde.rs/enum-representations.html#internally-tagged`
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
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(untagged)]
pub enum Object {
    /// A Managed Cryptographic Object that is a digital certificate.
    /// It is a DER-encoded X.509 public key certificate.
    #[serde(rename_all = "PascalCase")]
    Certificate {
        certificate_type: CertificateType,
        /// A Managed Cryptographic Object that is a digital certificate.
        /// It is a DER-encoded X.509 public key certificate.
        certificate_value: Vec<u8>,
    },
    /// A Managed Cryptographic Object containing the Certificate Request.
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
    /// A Managed Cryptographic Object containing a shared secret value that is not
    /// a key or certificate (e.g., a password).
    /// The Key Block of the Secret Data object contains a Key Value of the Secret Data Type.
    /// The Key Value MAY be wrapped.
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
    /// A Managed Cryptographic Object that is the private portion of an asymmetric key pair.
    PrivateKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },
    /// A Managed Cryptographic Object that is the public portion of an asymmetric key pair.
    /// This is only a public key, not a certificate.
    PublicKey {
        #[serde(rename = "KeyBlock")]
        key_block: KeyBlock,
    },
    /// A Managed Cryptographic Object that is a symmetric key.
    SymmetricKey {
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
            } => write!(
                f,
                "Certificate(certificate_type: {certificate_type:?}, certificate_value: \
                 {certificate_value:?})"
            ),
            Self::CertificateRequest {
                certificate_request_type,
                certificate_request_value,
            } => write!(
                f,
                "CertificateRequest(certificate_request_type: {certificate_request_type:?}, \
                 certificate_request_value: {certificate_request_value:?})"
            ),
            Self::OpaqueObject {
                opaque_data_type,
                opaque_data_value,
            } => write!(
                f,
                "OpaqueObject(opaque_data_type: {opaque_data_type:?}, opaque_data_value: \
                 {opaque_data_value:?})"
            ),
            Self::PGPKey {
                pgp_key_version,
                key_block,
            } => write!(
                f,
                "PGPKey(pgp_key_version: {pgp_key_version:?}, key_block: {key_block})"
            ),
            Self::SecretData {
                secret_data_type,
                key_block,
            } => write!(
                f,
                "SecretData(secret_data_type: {secret_data_type:?}, key_block: {key_block})"
            ),
            Self::SplitKey {
                split_key_parts,
                key_part_identifier,
                split_key_threshold,
                split_key_method,
                prime_field_size,
                key_block,
            } => write!(
                f,
                "SplitKey(split_key_parts: {split_key_parts:?}, key_part_identifier: \
                 {key_part_identifier:?}, split_key_threshold: {split_key_threshold:?}, \
                 split_key_method: {split_key_method:?}, prime_field_size: {prime_field_size:?}, \
                 key_block: {key_block})"
            ),
            Self::PrivateKey { key_block } => write!(f, "PrivateKey(key_block: {key_block})"),
            Self::PublicKey { key_block } => write!(f, "PublicKey(key_block: {key_block})"),
            Self::SymmetricKey { key_block } => {
                write!(f, "SymmetricKey(key_block: {key_block})")
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
            Self::CertificateRequest { .. } => ObjectType::CertificateRequest,
            Self::OpaqueObject { .. } => ObjectType::OpaqueObject,
            Self::PGPKey { .. } => ObjectType::PGPKey,
            Self::PrivateKey { .. } => ObjectType::PrivateKey,
            Self::PublicKey { .. } => ObjectType::PublicKey,
            Self::SecretData { .. } => ObjectType::SecretData,
            Self::SplitKey { .. } => ObjectType::SplitKey,
            Self::SymmetricKey { .. } => ObjectType::SymmetricKey,
        }
    }

    /// Returns the `KeyBlock` of that object if any, an error otherwise
    pub fn key_block(&self) -> Result<&KeyBlock, KmipError> {
        match self {
            Self::PublicKey { key_block }
            | Self::PrivateKey { key_block }
            | Self::SecretData { key_block, .. }
            | Self::PGPKey { key_block, .. }
            | Self::SymmetricKey { key_block }
            | Self::SplitKey { key_block, .. } => Ok(key_block),
            _ => Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "This object does not have a key block".to_owned(),
            )),
        }
    }

    /// Return the `KeyWrappingData` of that object if any
    #[must_use]
    pub fn key_wrapping_data(&self) -> Option<&KeyWrappingData> {
        match self.key_block() {
            Ok(kb) => kb.key_wrapping_data.as_deref(),
            // only keys can be wrapped
            Err(_e) => None,
        }
    }

    /// Returns the `Attributes` of that object if any, an error otherwise
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        self.key_block()?.attributes()
    }

    /// Returns the `Attributes` of that object if any, an error otherwise
    pub fn attributes_mut(&mut self) -> Result<&mut Attributes, KmipError> {
        self.key_block_mut()?.attributes_mut()
    }

    /// Returns the `KeyBlock` of that object if any, an error otherwise
    pub fn key_block_mut(&mut self) -> Result<&mut KeyBlock, KmipError> {
        match self {
            Self::PublicKey { key_block }
            | Self::PrivateKey { key_block }
            | Self::SecretData { key_block, .. }
            | Self::PGPKey { key_block, .. }
            | Self::SymmetricKey { key_block }
            | Self::SplitKey { key_block, .. } => Ok(key_block),
            _ => Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "This object does not have a key block (function `key_block_mut`)".to_owned(),
            )),
        }
    }

    /// Deserialization is untagged and the `ObjectType` is not at
    /// an adjacent level in the structure. Correction code needs to be
    /// run post-serialization
    /// see `Object` for details
    #[must_use]
    pub fn post_fix(object_type: ObjectType, object: Self) -> Self {
        match object_type {
            ObjectType::SymmetricKey => match object {
                Self::PrivateKey { key_block } | Self::PublicKey { key_block } => {
                    Self::SymmetricKey { key_block }
                }
                _ => object,
            },
            ObjectType::PublicKey => match object {
                Self::SymmetricKey { key_block } | Self::PrivateKey { key_block } => {
                    Self::PublicKey { key_block }
                }
                _ => object,
            },
            ObjectType::PrivateKey => match object {
                Self::SymmetricKey { key_block } | Self::PublicKey { key_block } => {
                    Self::PrivateKey { key_block }
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
                "failed deserializing to an Object".to_owned(),
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
                "failed serializing Object to bytes".to_owned(),
            )
        })
    }
}

/// The type of a KMIP Objects
#[allow(non_camel_case_types)]
#[allow(clippy::enum_clike_unportable_variant)]
#[derive(ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
#[serde(rename_all = "PascalCase")]
pub enum ObjectType {
    #[value(name = "Certificate")]
    Certificate = 0x0000_0001,
    #[value(name = "SymmetricKey")]
    SymmetricKey = 0x0000_0002,
    #[value(name = "PublicKey")]
    PublicKey = 0x0000_0003,
    #[value(name = "PrivateKey")]
    PrivateKey = 0x0000_0004,
    #[value(name = "SplitKey")]
    SplitKey = 0x0000_0005,
    #[value(name = "SecretData")]
    SecretData = 0x0000_0007,
    #[value(name = "OpaqueObject")]
    OpaqueObject = 0x0000_0008,
    #[value(name = "PGPKey")]
    PGPKey = 0x0000_0009,
    #[value(name = "CertificateRequest")]
    CertificateRequest = 0x0000_000A,
}

impl TryFrom<&str> for ObjectType {
    type Error = KmipError;

    fn try_from(object_type: &str) -> Result<Self, Self::Error> {
        match object_type {
            "Certificate" => Ok(Self::Certificate),
            "SymmetricKey" => Ok(Self::SymmetricKey),
            "PublicKey" => Ok(Self::PublicKey),
            "PrivateKey" => Ok(Self::PrivateKey),
            "SplitKey" => Ok(Self::SplitKey),
            "SecretData" => Ok(Self::SecretData),
            "OpaqueObject" => Ok(Self::OpaqueObject),
            "PGPKey" => Ok(Self::PGPKey),
            "CertificateRequest" => Ok(Self::CertificateRequest),
            _ => Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                format!("{object_type} is not a valid ObjectType"),
            )),
        }
    }
}

impl From<ObjectType> for String {
    fn from(object_type: ObjectType) -> Self {
        match object_type {
            ObjectType::Certificate => "Certificate".to_owned(),
            ObjectType::SymmetricKey => "SymmetricKey".to_owned(),
            ObjectType::PublicKey => "PublicKey".to_owned(),
            ObjectType::PrivateKey => "PrivateKey".to_owned(),
            ObjectType::SplitKey => "SplitKey".to_owned(),
            ObjectType::SecretData => "SecretData".to_owned(),
            ObjectType::OpaqueObject => "OpaqueObject".to_owned(),
            ObjectType::PGPKey => "PGPKey".to_owned(),
            ObjectType::CertificateRequest => "CertificateRequest".to_owned(),
        }
    }
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = (*self).into();
        write!(f, "{s}")
    }
}
