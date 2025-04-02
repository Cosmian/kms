use std::{
    clone::Clone,
    fmt,
    fmt::{Display, Formatter},
};

use num_bigint_dig::BigInt;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use zeroize::Zeroizing;

use super::{
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_types::{
        ClientRegistrationMethod, CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation,
        KeyCompressionType, KeyFormatType, LinkType, LinkedObjectIdentifier,
        MacSignatureKeyInformation, ProfileName, RNGMode, RecommendedCurve, WrappingMethod,
    },
};
use crate::{
    error::KmipError,
    kmip_0::kmip_types::{DRBGAlgorithm, ErrorReason, FIPS186Variation, HashingAlgorithm},
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_types::{ItemType, RNGAlgorithm},
    },
    pad_be_bytes, SafeBigInt,
};

/// A Key Block object is a structure used to encapsulate all of the information
/// that is closely associated with a cryptographic key.
/// Section 3 of KMIP Reference 2.1
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    /// Indicates the format of the elliptic curve public key. By default, the public key is uncompressed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,
    /// Byte String: for wrapped Key Value; Structure: for plaintext Key Value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_value: Option<KeyValue>,
    /// MAY be omitted only if this information is available from the Key Value.
    /// Does not apply to Secret Data  or Opaque.
    /// If present, the Cryptographic Length SHALL also be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    /// MAY be omitted only if this information is available from the Key Value.
    /// Does not apply to Secret Data (or Opaque.
    /// If present, the Cryptographic Algorithm SHALL also be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,
    /// SHALL only be present if the key is wrapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_data: Option<KeyWrappingData>,
}

impl Display for KeyBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyBlock {{ key_format_type: {}, key_compression_type: {:?}, key_value: {:?}, \
             cryptographic_algorithm: {:?}, cryptographic_length: {:?}, key_wrapping_data: {:?} }}",
            self.key_format_type,
            self.key_compression_type,
            self.key_value,
            self.cryptographic_algorithm,
            self.cryptographic_length,
            self.key_wrapping_data
        )
    }
}

impl KeyBlock {
    /// Give a slice view on the key bytes (which may be wrapped)
    /// Returns an error if there is no valid key material
    /// For a transparent symmetric key, this is the key itself
    /// For a wrapped key, this is the wrapped key
    /// For a Transparent EC Private key it is big endian representation
    /// of the scalar of the private key which is also the .
    /// For a Transparent EC Public key it is the raw bytes of Q string (the EC point)
    /// Other keys are not supported.
    pub fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        let key_value = self.key_value.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "key is missing its key value".to_owned(),
            )
        })?;

        match &key_value.key_material {
            KeyMaterial::ByteString(v) => Ok(v.clone()),
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
            KeyMaterial::TransparentECPrivateKey {
                d,
                recommended_curve,
            } => {
                let mut d_vec = d.to_bytes_be().1;
                let privkey_size = match recommended_curve {
                    RecommendedCurve::P192 => 24,
                    RecommendedCurve::P224 => 28,
                    RecommendedCurve::P256
                    | RecommendedCurve::CURVE25519
                    | RecommendedCurve::CURVEED25519 => 32,
                    RecommendedCurve::P384 => 48,
                    RecommendedCurve::P521 => 66,
                    RecommendedCurve::CURVE448 => 56,
                    RecommendedCurve::CURVEED448 => 57,
                    _ => d_vec.len(),
                };
                pad_be_bytes(&mut d_vec, privkey_size);
                Ok(Zeroizing::new(d_vec))
            }
            KeyMaterial::TransparentECPublicKey { q_string, .. } => {
                Ok(Zeroizing::new(q_string.clone()))
            }
            _ => Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Data_Type,
                "Key bytes can only be recovered from ByteString or TransparentSymmetricKey key \
                 material."
                    .to_owned(),
            )),
        }
    }

    /// Extract the Key bytes from the given `KeyBlock`
    /// and give an optional reference to `Attributes`
    /// Returns an error if there is no valid key material
    pub fn key_bytes_and_attributes(
        &self,
    ) -> Result<(Zeroizing<Vec<u8>>, Option<&Attributes>), KmipError> {
        let key = self.key_bytes().map_err(|e| {
            KmipError::InvalidKmip21Value(ErrorReason::Invalid_Data_Type, e.to_string())
        })?;
        let attributes = self
            .key_value
            .as_ref()
            .and_then(|kv| kv.attributes.as_ref());
        Ok((key, attributes))
    }

    /// Returns the `Attributes` of that key block if any, an error otherwise
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        self.key_value
            .as_ref()
            .ok_or_else(|| {
                KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Attribute_Value,
                    "key is missing its key value".to_owned(),
                )
            })?
            .attributes()
    }

    /// Returns the `Attributes` of that key block if any, an error otherwise
    pub fn attributes_mut(&mut self) -> Result<&mut Attributes, KmipError> {
        self.key_value
            .as_mut()
            .ok_or_else(|| {
                KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Attribute_Value,
                    "key is missing its key value".to_owned(),
                )
            })?
            .attributes_mut()
    }

    /// Returns the identifier of a linked object of a certain type, if it exists in the attributes
    /// of this object.
    ///
    /// # Arguments
    ///
    /// * `link_type` - The type of link to look for
    ///
    /// # Errors
    ///
    /// Returns a `KmipError` if the attribute value is invalid or unsupported.
    ///
    /// # Returns
    ///
    /// Returns an `Option<String>` with the identifier of the linked object, or `None` if there
    /// is no such link.
    pub fn get_linked_object_id(&self, link_type: LinkType) -> Result<Option<String>, KmipError> {
        // Retrieve the attributes of this object
        let attributes = self
            .key_value
            .as_ref()
            .ok_or_else(|| {
                KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Attribute_Value,
                    "key is missing its key value".to_owned(),
                )
            })?
            .attributes()?;

        // Retrieve the links attribute from the object attributes, if it exists
        let Some(links) = &attributes.link else {
            return Ok(None)
        };

        // If there are no links, return None
        if links.is_empty() {
            return Ok(None)
        }

        // Find the link of the requested type in the list of links, if it exists
        links
            .iter()
            .find(|&link| link.link_type == link_type)
            .map_or(Ok(None), |link| match &link.linked_object_identifier {
                // If the linked object identifier is a text string, return it
                LinkedObjectIdentifier::TextString(s) => Ok(Some(s.clone())),
                // Enumeration and index identifiers are not yet supported
                LinkedObjectIdentifier::Enumeration(_) => Err(KmipError::NotSupported(
                    "Link Enumeration not yet supported".to_owned(),
                )),
                LinkedObjectIdentifier::Index(_) => Err(KmipError::NotSupported(
                    "Link Index not yet supported".to_owned(),
                )),
            })
    }

    /// Recover the cryptographic algorithm.
    /// If the cryptographic algorithm is not present in the key block, it will
    /// be recovered from the key value attributes.
    #[must_use]
    pub fn cryptographic_algorithm(&self) -> Option<&CryptographicAlgorithm> {
        self.cryptographic_algorithm.as_ref().or_else(|| {
            self.key_value
                .as_ref()
                .and_then(|kv| kv.attributes.as_ref())
                .and_then(|attributes| attributes.cryptographic_algorithm.as_ref())
        })
    }
}

/// The Key Value is used only inside a Key Block and is either a Byte String or
/// a:
///
/// • The Key Value structure contains the key material, either as a byte string
/// or as a Transparent Key structure, and OPTIONAL attribute information that
/// is associated and encapsulated with the key material. This attribute
/// information differs from the attributes associated with Managed Objects, and
/// is obtained via the Get Attributes operation, only by the fact that it is
/// encapsulated with (and possibly wrapped with) the key material itself.
///
/// • The Key Value Byte String is either the wrapped TTLV-encoded Key Value
/// structure, or the wrapped un-encoded value of the Byte String Key Material
/// field.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
#[allow(clippy::large_enum_variant)]
pub struct KeyValue {
    pub key_material: KeyMaterial,
    #[serde(skip_serializing_if = "attributes_is_default_or_none")]
    pub attributes: Option<Attributes>,
}

impl Display for KeyValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyValue {{ key_material: {}, attributes: {:?} }}",
            self.key_material, self.attributes
        )
    }
}

// This is required since its signature must match what serde
// skip_serializing_if is expecting.
#[allow(clippy::ref_option)]
// Attributes is default is a fix for https://github.com/Cosmian/kms/issues/92
#[allow(clippy::ref_option)]
fn attributes_is_default_or_none<T: Default + PartialEq + Serialize>(val: &Option<T>) -> bool {
    val.as_ref().map_or(true, |v| *v == T::default())
}

impl KeyValue {
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        self.attributes.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "key is missing its attributes".to_owned(),
            )
        })
    }

    pub fn attributes_mut(&mut self) -> Result<&mut Attributes, KmipError> {
        self.attributes.as_mut().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "key is missing its mutable attributes".to_owned(),
            )
        })
    }

    pub fn raw_bytes(&self) -> Result<&[u8], KmipError> {
        match &self.key_material {
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key),
            KeyMaterial::ByteString(v) => Ok(v),
            other => Err(KmipError::Kmip21NotSupported(
                ErrorReason::Invalid_Data_Type,
                format!("The key has an invalid key material: {other}"),
            )),
        }
    }
}

/// Key wrapping data
///
/// The Key Block MAY also supply OPTIONAL information about a cryptographic key
/// wrapping mechanism used to wrap the Key Value. This consists of a Key
/// Wrapping Data structure. It is only used inside a Key Block.
/// This structure contains fields for:
///
/// Value Description
///
/// Wrapping Method Indicates the method used to wrap the Key Value.
///
/// Encryption Key Information Contains the Unique Identifier value of the
/// encryption key and associated cryptographic parameters.
///
/// MAC/Signature Key Information
/// Contains the Unique Identifier value of the MAC/signature key and
/// associated cryptographic parameters.
///
/// MAC/Signature Contains a MAC or signature of the Key Value
///
/// IV/Counter/Nonce If REQUIRED by the wrapping method.
///
/// Encoding Option Specifies the encoding of the Key Material within the Key
/// Value structure of the Key Block that has been wrapped. If No Encoding is
/// specified, then the Key Value structure SHALL NOT contain any
/// attributes.
///
/// If wrapping is used, then the whole Key Value structure is wrapped unless
/// otherwise specified by the Wrapping Method. The algorithms used for wrapping
/// are given by the Cryptographic Algorithm attributes of the encryption key
/// and/or MAC/signature key; the block-cipher mode, padding method, and hashing
/// algorithm used for wrapping are given by the Cryptographic Parameters in the
/// Encryption Key Information and/or MAC/Signature Key Information, or, if not
/// present, from the Cryptographic Parameters attribute of the respective
/// key(s). Either the Encryption Key Information or the MAC/Signature Key
/// Information (or both) in the Key Wrapping Data structure SHALL be specified.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct KeyWrappingData {
    pub wrapping_method: WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_signature: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "IVCounterNonce")]
    pub iv_counter_nonce: Option<Vec<u8>>,
    /// Specifies the encoding of the Key Value Byte String. If not present, the
    /// wrapped Key Value structure SHALL be TTLV encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_option: Option<EncodingOption>,
}

impl KeyWrappingData {
    /// Returns the encoding option for the key wrapping data
    /// If not present, the wrapped Key Value structure SHALL not have any encoding.
    #[must_use]
    pub fn get_encoding(&self) -> EncodingOption {
        self.encoding_option.unwrap_or(EncodingOption::NoEncoding)
    }
}

impl Default for KeyWrappingData {
    fn default() -> Self {
        Self {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: None,
            mac_signature_key_information: None,
            mac_signature: None,
            iv_counter_nonce: None,
            encoding_option: Some(EncodingOption::NoEncoding),
        }
    }
}

/// This is a separate structure that is defined for operations that provide the
/// option to return wrapped keys.
///
/// The Key Wrapping Specification SHALL be included inside the operation request
/// if clients request the server to return a wrapped key.
///
/// If Cryptographic Parameters are specified in the Encryption Key Information
/// and/or the MAC/Signature Key Information of the Key Wrapping Specification,
/// then the server SHALL verify that they match one of the instances of the
/// Cryptographic Parameters attribute of the corresponding key..
///
/// If the corresponding key does not have any Cryptographic Parameters attribute, or if no match is found, then an error is returned.
///
/// This structure contains:
///
/// ·         A Wrapping Method that indicates the method used to wrap the Key Value.
///
/// ·         Encryption Key Information with the Unique Identifier value of the encryption key and associated cryptographic parameters.
///
/// ·         MAC/Signature Key Information with the Unique Identifier value of the MAC/signature key and associated cryptographic parameters.
///
/// ·         Zero or more Attribute Names to indicate the attributes to be wrapped with the key material.
///
/// ·         An Encoding Option, specifying the encoding of the Key Value before wrapping. If No Encoding is specified, then the Key Value SHALL NOT contain any attributes
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct KeyWrappingSpecification {
    pub wrapping_method: WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_or_signature_key_information: Option<MacSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_name: Option<Vec<String>>,
    /// Specifies the encoding of the Key Value Byte String. If not present, the
    /// wrapped Key Value structure SHALL be TTLV encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_option: Option<EncodingOption>,
}

impl Default for KeyWrappingSpecification {
    fn default() -> Self {
        Self {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: None,
            mac_or_signature_key_information: None,
            attribute_name: None,
            encoding_option: Some(EncodingOption::NoEncoding),
        }
    }
}

impl KeyWrappingSpecification {
    /// Returns the encoding option for the key wrapping specification
    /// If not present, the wrapped Key Value structure SHALL be TTLV encoded.
    #[must_use]
    pub fn get_encoding(&self) -> EncodingOption {
        self.encoding_option.unwrap_or(EncodingOption::NoEncoding)
    }

    /// Returns the key wrapping data from the key wrapping specification
    #[must_use]
    pub fn get_key_wrapping_data(&self) -> KeyWrappingData {
        KeyWrappingData {
            wrapping_method: self.wrapping_method,
            encryption_key_information: self.encryption_key_information.clone(),
            mac_signature_key_information: self.mac_or_signature_key_information.clone(),
            encoding_option: Some(self.get_encoding()),
            ..KeyWrappingData::default()
        }
    }

    /// Returns the additional authenticated data from the key wrapping specification
    pub fn get_additional_authenticated_data(&self) -> Option<&[u8]> {
        self.attribute_name
            .as_ref()
            .and_then(|attributes| attributes.first())
            .map(String::as_bytes)
    }
}

/// Private fields are represented using a Zeroizing object: either array of
/// bytes, or `SafeBigInt` type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeyMaterial {
    ByteString(Zeroizing<Vec<u8>>),
    TransparentDHPrivateKey {
        p: Box<BigInt>,
        q: Option<Box<BigInt>>,
        g: Box<BigInt>,
        j: Option<Box<BigInt>>,
        x: Box<SafeBigInt>,
    },
    TransparentDHPublicKey {
        p: Box<BigInt>,
        q: Option<Box<BigInt>>,
        g: Box<BigInt>,
        j: Option<Box<BigInt>>,
        y: Box<BigInt>,
    },
    TransparentDSAPrivateKey {
        p: Box<BigInt>,
        q: Box<BigInt>,
        g: Box<BigInt>,
        x: Box<SafeBigInt>,
    },
    TransparentDSAPublicKey {
        p: Box<BigInt>,
        q: Box<BigInt>,
        g: Box<BigInt>,
        y: Box<BigInt>,
    },
    TransparentSymmetricKey {
        key: Zeroizing<Vec<u8>>,
    },
    TransparentRSAPublicKey {
        modulus: Box<BigInt>,
        public_exponent: Box<BigInt>,
    },
    TransparentRSAPrivateKey {
        modulus: Box<BigInt>,
        private_exponent: Option<Box<SafeBigInt>>,
        public_exponent: Option<Box<BigInt>>,
        p: Option<Box<SafeBigInt>>,
        q: Option<Box<SafeBigInt>>,
        prime_exponent_p: Option<Box<SafeBigInt>>,
        prime_exponent_q: Option<Box<SafeBigInt>>,
        crt_coefficient: Option<Box<SafeBigInt>>,
    },
    TransparentECPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigInt>,
    },
    TransparentECPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
}

impl Display for KeyMaterial {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ByteString(_) => write!(f, "ByteString. Not displaying key content"),
            Self::TransparentDHPrivateKey { .. } => {
                write!(f, "DH Private Key. Not displaying key content")
            }
            Self::TransparentDHPublicKey { .. } => {
                write!(f, "DH Public Key. Not displaying key content")
            }
            Self::TransparentDSAPrivateKey { .. } => {
                write!(f, "DSA Private Key. Not displaying key content")
            }
            Self::TransparentDSAPublicKey { .. } => {
                write!(f, "DSA Public Key. Not displaying key content")
            }
            Self::TransparentSymmetricKey { .. } => {
                write!(f, "Symmetric Key. Not displaying key content")
            }
            Self::TransparentRSAPublicKey { .. } => {
                write!(f, "RSA Public Key. Not displaying key content")
            }
            Self::TransparentRSAPrivateKey { .. } => {
                write!(f, "RSA Private Key. Not displaying key content")
            }
            Self::TransparentECPrivateKey { .. } => {
                write!(f, "EC Private Key. Not displaying key content")
            }
            Self::TransparentECPublicKey { .. } => {
                write!(f, "EC Public Key. Not displaying key content")
            }
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Clone, Copy)]
enum KeyTypeSer {
    DH,
    DSA,
    RsaPublic,
    RsaPrivate,
    EC,
}

// Unfortunately, default serialization does not play well
// for ByteString, so we have to do it by hand. Deserialization is OK though
impl Serialize for KeyMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ByteString(bytes) => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("ByteString", &**bytes)?;
                st.end()
            }
            Self::TransparentSymmetricKey { key } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("Key", &**key)?;
                st.end()
            }
            Self::TransparentDHPrivateKey { p, q, g, j, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DH)?;
                st.serialize_field("P", &**p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", &**q)?;
                }
                st.serialize_field("G", &**g)?;
                if let Some(j) = j {
                    st.serialize_field("J", &**j)?;
                }
                st.serialize_field("X", &***x)?;
                st.end()
            }
            Self::TransparentDHPublicKey { p, q, g, j, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DH)?;
                st.serialize_field("P", &**p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", &**q)?;
                }
                st.serialize_field("G", &**g)?;
                if let Some(j) = j {
                    st.serialize_field("J", &**j)?;
                }
                st.serialize_field("Y", &**y)?;
                st.end()
            }
            Self::TransparentDSAPrivateKey { p, q, g, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DSA)?;
                st.serialize_field("P", &**p)?;
                st.serialize_field("Q", &**q)?;
                st.serialize_field("G", &**g)?;
                st.serialize_field("X", &***x)?;
                st.end()
            }
            Self::TransparentDSAPublicKey { p, q, g, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DSA)?;
                st.serialize_field("P", &**p)?;
                st.serialize_field("Q", &**q)?;
                st.serialize_field("G", &**g)?;
                st.serialize_field("Y", &**y)?;
                st.end()
            }
            Self::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 9)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::RsaPrivate)?;
                st.serialize_field("Modulus", &**modulus)?;
                if let Some(private_exponent) = private_exponent {
                    st.serialize_field("PrivateExponent", &***private_exponent)?;
                }
                if let Some(public_exponent) = public_exponent {
                    st.serialize_field("PublicExponent", &**public_exponent)?;
                }
                if let Some(p) = p {
                    st.serialize_field("P", &***p)?;
                }
                if let Some(q) = q {
                    st.serialize_field("Q", &***q)?;
                }
                if let Some(prime_exponent_p) = prime_exponent_p {
                    st.serialize_field("PrimeExponentP", &***prime_exponent_p)?;
                }
                if let Some(prime_exponent_q) = prime_exponent_q {
                    st.serialize_field("PrimeExponentQ", &***prime_exponent_q)?;
                }
                if let Some(crt_coefficient) = crt_coefficient {
                    st.serialize_field("CrtCoefficient", &***crt_coefficient)?;
                }
                st.end()
            }
            Self::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::RsaPublic)?;
                st.serialize_field("Modulus", &**modulus)?;
                st.serialize_field("PublicExponent", &**public_exponent)?;
                st.end()
            }
            Self::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::EC)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", &***d)?;
                st.end()
            }
            Self::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::EC)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for KeyMaterial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            ByteString,
            D,
            P,
            Q,
            G,
            J,
            X,
            Y,
            Key,
            KeyTypeSer,
            Modulus,
            PrivateExponent,
            PublicExponent,
            PrimeExponentP,
            PrimeExponentQ,
            CrtCoefficient,
            RecommendedCurve,
            QString,
        }

        struct KeyMaterialVisitor;

        impl<'de> Visitor<'de> for KeyMaterialVisitor {
            type Value = KeyMaterial;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyMaterialVisitor")
            }

            #[allow(clippy::many_single_char_names)]
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut bytestring: Option<Zeroizing<Vec<u8>>> = None;
                let mut key_type_ser: Option<KeyTypeSer> = None;
                // Here `p` and `q` describes either a public value for DH or
                // a prime secret factor for RSA. Kept as `BigInt`` and wrapped
                // as `SafeBigInt` in RSA.
                let mut p: Option<Box<BigInt>> = None;
                let mut q: Option<Box<BigInt>> = None;
                let mut g: Option<Box<BigInt>> = None;
                let mut j: Option<Box<BigInt>> = None;
                let mut y: Option<Box<BigInt>> = None;
                let mut x: Option<Box<SafeBigInt>> = None;
                let mut key: Option<Zeroizing<Vec<u8>>> = None;
                let mut modulus: Option<Box<BigInt>> = None;
                let mut public_exponent: Option<Box<BigInt>> = None;
                let mut private_exponent: Option<Box<SafeBigInt>> = None;
                let mut prime_exponent_p: Option<Box<SafeBigInt>> = None;
                let mut prime_exponent_q: Option<Box<SafeBigInt>> = None;
                let mut crt_coefficient: Option<Box<SafeBigInt>> = None;
                let mut recommended_curve: Option<RecommendedCurve> = None;
                let mut d: Option<Box<SafeBigInt>> = None;
                let mut q_string: Option<Vec<u8>> = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::ByteString => {
                            if bytestring.is_some() {
                                return Err(de::Error::duplicate_field("ByteString"))
                            }
                            bytestring = Some(map.next_value()?);
                        }
                        Field::D => {
                            if d.is_some() {
                                return Err(de::Error::duplicate_field("D"))
                            }
                            d = Some(Box::new(map.next_value()?));
                        }
                        Field::P => {
                            if p.is_some() {
                                return Err(de::Error::duplicate_field("P"))
                            }
                            p = Some(Box::new(map.next_value()?));
                        }
                        Field::Q => {
                            if q.is_some() {
                                return Err(de::Error::duplicate_field("Q"))
                            }
                            q = Some(Box::new(map.next_value()?));
                        }
                        Field::G => {
                            if g.is_some() {
                                return Err(de::Error::duplicate_field("G"))
                            }
                            g = Some(Box::new(map.next_value()?));
                        }
                        Field::J => {
                            if j.is_some() {
                                return Err(de::Error::duplicate_field("J"))
                            }
                            j = Some(Box::new(map.next_value()?));
                        }
                        Field::X => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("X"))
                            }
                            x = Some(Box::new(map.next_value()?));
                        }
                        Field::Y => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("Y"))
                            }
                            y = Some(Box::new(map.next_value()?));
                        }
                        Field::Key => {
                            if key.is_some() {
                                return Err(de::Error::duplicate_field("Key"))
                            }
                            key = Some(map.next_value()?);
                        }
                        Field::KeyTypeSer => {
                            if key_type_ser.is_some() {
                                return Err(de::Error::duplicate_field("KeyTypeSer"))
                            }
                            key_type_ser = Some(map.next_value()?);
                        }
                        Field::Modulus => {
                            if modulus.is_some() {
                                return Err(de::Error::duplicate_field("Modulus"))
                            }
                            modulus = Some(Box::new(map.next_value()?));
                        }
                        Field::PrivateExponent => {
                            if private_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PrivateExponent"))
                            }
                            private_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PublicExponent => {
                            if public_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PublicExponent"))
                            }
                            public_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentP => {
                            if prime_exponent_p.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentP"))
                            }
                            prime_exponent_p = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentQ => {
                            if prime_exponent_q.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentQ"))
                            }
                            prime_exponent_q = Some(Box::new(map.next_value()?));
                        }
                        Field::CrtCoefficient => {
                            if crt_coefficient.is_some() {
                                return Err(de::Error::duplicate_field("CrtCoefficient"))
                            }
                            crt_coefficient = Some(Box::new(map.next_value()?));
                        }
                        Field::RecommendedCurve => {
                            if recommended_curve.is_some() {
                                return Err(de::Error::duplicate_field("RecommendedCurve"))
                            }
                            recommended_curve = Some(map.next_value()?);
                        }
                        Field::QString => {
                            if q_string.is_some() {
                                return Err(de::Error::duplicate_field("QString"))
                            }
                            q_string = Some(map.next_value()?);
                        }
                    }
                }

                if let Some(key) = key {
                    Ok(KeyMaterial::TransparentSymmetricKey { key })
                } else if let Some(bytestring) = bytestring {
                    Ok(KeyMaterial::ByteString(bytestring))
                } else {
                    Ok(match key_type_ser {
                        Some(KeyTypeSer::DH) => {
                            let p = p.ok_or_else(|| de::Error::missing_field("P for DH key"))?;
                            let g = g.ok_or_else(|| de::Error::missing_field("G for DH key"))?;
                            if let Some(x) = x {
                                KeyMaterial::TransparentDHPrivateKey { p, q, g, j, x }
                            } else {
                                let y = y.ok_or_else(|| {
                                    de::Error::missing_field("Y for DH public key")
                                })?;
                                KeyMaterial::TransparentDHPublicKey { p, q, g, j, y }
                            }
                        }
                        Some(KeyTypeSer::DSA) => {
                            let p = p.ok_or_else(|| de::Error::missing_field("P for DSA key"))?;
                            let g = g.ok_or_else(|| de::Error::missing_field("G for DSA key"))?;
                            let q = q.ok_or_else(|| de::Error::missing_field("Q for DSA key"))?;
                            if let Some(x) = x {
                                KeyMaterial::TransparentDSAPrivateKey { p, q, g, x }
                            } else {
                                let y = y.ok_or_else(|| {
                                    de::Error::missing_field("Y for DSA public key")
                                })?;
                                KeyMaterial::TransparentDSAPublicKey { p, q, g, y }
                            }
                        }
                        Some(KeyTypeSer::RsaPublic) => {
                            let modulus = modulus.ok_or_else(|| {
                                de::Error::missing_field("Modulus for RSA public key")
                            })?;
                            let public_exponent = public_exponent.ok_or_else(|| {
                                de::Error::missing_field("Public exponent for RSA public key")
                            })?;
                            KeyMaterial::TransparentRSAPublicKey {
                                modulus,
                                public_exponent,
                            }
                        }
                        Some(KeyTypeSer::RsaPrivate) => {
                            let modulus = modulus.ok_or_else(|| {
                                de::Error::missing_field("Modulus for RSA private key")
                            })?;
                            KeyMaterial::TransparentRSAPrivateKey {
                                modulus,
                                public_exponent,
                                private_exponent,
                                p: p.map(|p| Box::new(SafeBigInt::from(*p))),
                                q: q.map(|q| Box::new(SafeBigInt::from(*q))),
                                prime_exponent_p,
                                prime_exponent_q,
                                crt_coefficient,
                            }
                        }
                        Some(KeyTypeSer::EC) => {
                            let recommended_curve = recommended_curve.ok_or_else(|| {
                                de::Error::missing_field("RecommendedCurve for EC key")
                            })?;
                            if let Some(d) = d {
                                KeyMaterial::TransparentECPrivateKey {
                                    recommended_curve,
                                    d,
                                }
                            } else {
                                let q_string = q_string.ok_or_else(|| {
                                    de::Error::missing_field("QString for EC public key")
                                })?;
                                KeyMaterial::TransparentECPublicKey {
                                    recommended_curve,
                                    q_string,
                                }
                            }
                        }
                        _ => {
                            return Err(de::Error::custom(
                                "unable to differentiate key material variant",
                            ))
                        }
                    })
                }
            }
        }

        const FIELDS: &[&str] = &[
            "bytestring",
            "p",
            "q",
            "g",
            "j",
            "x",
            "y",
            "key",
            "modulus",
            "public_exponent",
            "private_exponent",
            "prime_exponent_p",
            "prime_exponent_q",
            "crt_coefficient",
            "recommended_curve",
            "d",
            "q_string",
        ];
        deserializer.deserialize_struct("KeyMaterial", FIELDS, KeyMaterialVisitor)
    }
}

/// The Server Information  base object is a structure that contains a set of OPTIONAL fields
/// that describe server information.
/// Where a server supports returning information in a vendor-specific field for
/// which there is an equivalent field within the structure,
/// the server SHALL provide the standardized version of the field.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ServerInformation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_serial_number: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_load: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_level: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_date: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_info: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_failover_endpoints: Option<Vec<String>>,
}

impl Display for ServerInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServerInformation {{ server_name: {:?}, server_serial_number: {:?}, server_version: \
             {:?}, server_load: {:?}, product_name: {:?}, build_level: {:?}, build_date: {:?}, \
             cluster_info: {:?}, alternative_failover_endpoints: {:?} }}",
            self.server_name,
            self.server_serial_number,
            self.server_version,
            self.server_load,
            self.product_name,
            self.build_level,
            self.build_date,
            self.cluster_info,
            self.alternative_failover_endpoints
        )
    }
}

/// An Extension Information object is a structure describing Objects with Item Tag values
/// in the Extensions range.
/// The Extension Name is a Text String that is used to name the Object.
/// The Extension Tag is the Item Tag Value of the Object.
/// The Extension Type is the Item Type Value of the Object.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ExtensionInformation {
    /// The extension name.
    pub extension_name: String,

    /// The extension tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_tag: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_type: Option<ItemType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_enumeration: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_attribute: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_parent_structure_tag: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_description: Option<String>,
}

/// The Object Defaults is a structure that details the values that the server will use
/// if the client omits them on factory methods for objects. The structure list the Attributes
/// nd their values by Object Type enumeration, as well as the Object Group(s)
/// for which such defaults pertain (if not pertinent to ALL Object Group values)
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ObjectDefaults {
    /// Specifies the object type that these defaults apply to.
    pub object_type: ObjectType,

    /// Default attributes for the specified object type that should be applied
    /// during object creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Attributes>,

    /// The Object Groups is a structure that lists the relevant Object Group Attributes
    /// and their values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_groups: Option<Vec<Attribute>>,
}

impl Display for ObjectDefaults {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjectDefaults {{ object_type: {:?}, attributes: {:?}, object_groups: {:?} }}",
            self.object_type, self.attributes, self.object_groups
        )
    }
}

/// The Defaults Information structure is used by the server to maintain client-defined
/// defaults and is returned to the client as the result of a Query operation.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DefaultsInformation {
    /// The set of object defaults defined by the client or server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_defaults: Option<Vec<ObjectDefaults>>,
}

impl Display for DefaultsInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DefaultsInformation {{ object_defaults: {:?} }}",
            self.object_defaults
        )
    }
}

/// The `CapabilityInformation` structure provides information about the capabilities
/// of the server, such as supported operations, objects, and algorithms.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CapabilityInformation {
    /// Specifies a particular KMIP profile supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming_capability: Option<bool>,

    /// Indicates whether the server supports asynchronous operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asynchronous_capability: Option<bool>,

    /// Indicates whether the server supports attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_capability: Option<bool>,

    /// Indicates whether the server supports batching of operations in a single request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_undo_capability: Option<bool>,

    /// Indicates whether the server supports batching of operations in a single request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_continue_capability: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrap_mode: Option<UnwrapMode>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy_action: Option<DestroyAction>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub shredding_algorithm: Option<ShreddingAlgorithm>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rng_mode: Option<RNGMode>,

    /// Client registration methods supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantum_safe_capability: Option<bool>,
}

impl Display for CapabilityInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CapabilityInformation {{ streaming_capability: {:?}, asynchronous_capability: {:?}, \
             ... }}",
            self.streaming_capability, self.asynchronous_capability
        )
    }
}

/// The RNG Parameters base object is a structure that contains a mandatory RNG Algorithm
/// and a set of OPTIONAL fields that describe a Random Number Generator.
/// Specific fields pertain only to certain types of RNGs.
///
/// The RNG Algorithm SHALL be specified and if the algorithm implemented is unknown
/// or the implementation does not want to provide the specific details of the RNG Algorithm
/// then the Unspecified enumeration SHALL be used.
///
/// If the cryptographic building blocks used within the RNG are known
/// they MAY be specified in combination of the remaining fields
///  within the RNG Parameters structure.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RNGParameters {
    pub rng_algorithm: RNGAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips186_variation: Option<FIPS186Variation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_resistance: Option<bool>,
}

/// Profile Information contains details about supported KMIP profiles.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ProfileInformation {
    pub profile_name: ProfileName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_version: Option<ProfileVersion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_port: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ProfileVersion {
    /// Major version number of the profile.
    pub profile_version_major: i32,
    /// Minor version number of the profile.
    pub profile_version_minor: i32,
}
