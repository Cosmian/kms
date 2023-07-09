use std::clone::Clone;

use num_bigint::BigUint;
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use super::kmip_types::{LinkType, LinkedObjectIdentifier};
use crate::{
    error::KmipError,
    kmip::{
        kmip_operations::ErrorReason,
        kmip_types::{
            Attributes, CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation,
            KeyCompressionType, KeyFormatType, MacSignatureKeyInformation, RecommendedCurve,
            WrappingMethod,
        },
    },
};

/// A Key Block object is a structure used to encapsulate all of the information
/// that is closely associated with a cryptographic key.
/// Section 3 of KMIP Reference 2.1
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,
    // may be a KeyValue serialized struct - see specs
    pub key_value: KeyValue,
    pub cryptographic_algorithm: CryptographicAlgorithm,
    pub cryptographic_length: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_data: Option<KeyWrappingData>,
}

impl KeyBlock {
    /// Give a slice view on the key bytes (which may be wrapped)
    /// Returns an error if there is no valid key material
    pub fn key_bytes(&self) -> Result<Vec<u8>, KmipError> {
        match &self.key_value.key_material {
            KeyMaterial::ByteString(v) => Ok(v.clone()),
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
            KeyMaterial::TransparentECPrivateKey {
                d,
                recommended_curve: _,
            } => Ok(d.to_bytes_be()),
            KeyMaterial::TransparentECPublicKey {
                recommended_curve: _,
                q_string,
            } => Ok(q_string.clone()),
            other => Err(KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Data_Type,
                format!("The key has an invalid key material: {other:?}"),
            )),
        }
    }

    /// Extract the Key bytes from the given `KeyBlock`
    /// and give an optional reference to `Attributes`
    /// Returns an error if there is no valid key material
    pub fn key_bytes_and_attributes(&self) -> Result<(Vec<u8>, Option<&Attributes>), KmipError> {
        let key = self.key_bytes().map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Data_Type, e.to_string())
        })?;
        Ok((key, self.key_value.attributes.as_ref()))
    }

    /// Returns the `Attributes` of that key block if any, an error otherwise
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        self.key_value.attributes()
    }

    /// Returns the `Attributes` of that key block if any, an error otherwise
    pub fn attributes_mut(&mut self) -> Result<&mut Attributes, KmipError> {
        self.key_value.attributes_mut()
    }

    /// Extract `counter_iv_nonce` value from `KeyBlock`
    ///
    /// # Arguments
    ///
    /// * `self`: the KMIP key block
    ///
    /// # Returns
    ///
    /// * an optional byte vector
    ///
    #[must_use]
    pub fn counter_iv_nonce(&self) -> Option<&Vec<u8>> {
        match &self.key_wrapping_data {
            Some(KeyWrappingData {
                iv_counter_nonce, ..
            }) => iv_counter_nonce.as_ref(),
            None => None,
        }
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
        let attributes = self.key_value.attributes()?;

        // Retrieve the links attribute from the object attributes, if it exists
        let links = match &attributes.link {
            Some(links) => links,
            None => return Ok(None),
        };

        // If there are no links, return None
        if links.is_empty() {
            return Ok(None)
        }

        // Find the link of the requested type in the list of links, if it exists
        match links.iter().find(|&link| link.link_type == link_type) {
            None => Ok(None),
            Some(link) => match &link.linked_object_identifier {
                // If the linked object identifier is a text string, return it
                LinkedObjectIdentifier::TextString(s) => Ok(Some(s.clone())),
                // Enumeration and index identifiers are not yet supported
                LinkedObjectIdentifier::Enumeration(_) => Err(KmipError::NotSupported(
                    "Link Enumeration not yet supported".to_owned(),
                )),
                LinkedObjectIdentifier::Index(_) => Err(KmipError::NotSupported(
                    "Link Index not yet supported".to_owned(),
                )),
            },
        }
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
#[derive(Deserialize, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub struct KeyValue {
    #[serde(rename = "KeyMaterial")]
    pub key_material: KeyMaterial,
    #[serde(rename = "Attributes", skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Attributes>,
}

impl KeyValue {
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        self.attributes.as_ref().ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "key is missing its attributes".to_string(),
            )
        })
    }

    pub fn attributes_mut(&mut self) -> Result<&mut Attributes, KmipError> {
        self.attributes.as_mut().ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "key is missing its mutable attributes".to_string(),
            )
        })
    }

    pub fn raw_bytes(&self) -> Result<&[u8], KmipError> {
        match &self.key_material {
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key),
            KeyMaterial::ByteString(v) => Ok(v),
            other => Err(KmipError::KmipNotSupported(
                ErrorReason::Invalid_Data_Type,
                format!("The key has an invalid key material: {other:?}"),
            )),
        }
    }
}

impl Serialize for KeyValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("KeyValue", 2)?;
        st.serialize_field("KeyMaterial", &self.key_material)?;
        st.serialize_field("Attributes", &self.attributes)?;
        st.end()
    }
}

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
    pub mac_or_signature_key_information: Option<MacSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_or_signature: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "IVCounterNonce")]
    pub iv_counter_nonce: Option<Vec<u8>>,
    /// Specifies the encoding of the Key Value Byte String. If not present, the
    /// wrapped Key Value structure SHALL be TTLV encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_option: Option<EncodingOption>,
}

impl Default for KeyWrappingData {
    fn default() -> Self {
        Self {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: None,
            mac_or_signature_key_information: None,
            mac_or_signature: None,
            iv_counter_nonce: None,
            encoding_option: Some(EncodingOption::NoEncoding),
        }
    }
}

// KeyMaterial has variants that do not appear in the TTLV
// Typically, for a Transparent Symmetric key it will look like
// this
// ```
// TTLV {
//     tag: "KeyMaterial".to_string(),
//     value: TTLValue::Structure(vec![TTLV {
//         tag: "Key".to_string(),
//         value: TTLValue::ByteString(key_value.to_vec()),
//     }]),
// }
// ```
// So we use the `untagged` which unfortunately breaks pascalCase
#[derive(Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum KeyMaterial {
    ByteString(Vec<u8>),
    #[serde(rename_all = "PascalCase")]
    TransparentDHPrivateKey {
        p: BigUint,
        #[serde(skip_serializing_if = "Option::is_none")]
        q: Option<BigUint>,
        g: BigUint,
        #[serde(skip_serializing_if = "Option::is_none")]
        j: Option<BigUint>,
        x: BigUint,
    },
    #[serde(rename_all = "PascalCase")]
    TransparentDHPublicKey {
        p: BigUint,
        #[serde(skip_serializing_if = "Option::is_none")]
        q: Option<BigUint>,
        g: BigUint,
        #[serde(skip_serializing_if = "Option::is_none")]
        j: Option<BigUint>,
        y: BigUint,
    },
    //TODO  can be confused by the Deserializer with the TransparentDHPrivateKey
    #[serde(rename_all = "PascalCase")]
    TransparentDSAPrivateKey {
        p: BigUint,
        q: BigUint,
        g: BigUint,
        x: BigUint,
    },
    //TODO  can be confused by the Deserializer with the TransparentDHPublicKey
    #[serde(rename_all = "PascalCase")]
    TransparentDSAPublicKey {
        p: BigUint,
        q: BigUint,
        g: BigUint,
        y: BigUint,
    },
    #[serde(rename_all = "PascalCase")]
    TransparentSymmetricKey {
        key: Vec<u8>,
    },
    #[serde(rename_all = "PascalCase")]
    TransparentRSAPrivateKey {
        modulus: BigUint,
        #[serde(skip_serializing_if = "Option::is_none")]
        private_exponent: Option<BigUint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        public_exponent: Option<BigUint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        p: Option<BigUint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        q: Option<BigUint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prime_exponent_p: Option<BigUint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prime_exponent_q: Option<BigUint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crt_coefficient: Option<BigUint>,
    },
    #[serde(rename_all = "PascalCase")]
    TransparentRSAPublicKey {
        modulus: BigUint,
        public_exponent: BigUint,
    },
    #[serde(rename_all = "PascalCase")]
    TransparentECPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: BigUint,
    },
    #[serde(rename_all = "PascalCase")]
    TransparentECPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
}

// Unfortunately, default serialization does not play well
// for ByteString, so we have to do it by had. Deserialization is OK though
impl Serialize for KeyMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ByteString(bytes) => serializer.serialize_bytes(bytes),
            Self::TransparentSymmetricKey { key } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("Key", key)?;
                st.end()
            }
            Self::TransparentDHPrivateKey { p, q, g, j, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("P", p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", q)?;
                };
                st.serialize_field("G", g)?;
                if let Some(j) = j {
                    st.serialize_field("J", j)?;
                };
                st.serialize_field("X", x)?;
                st.end()
            }
            Self::TransparentDHPublicKey { p, q, g, j, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("P", p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", q)?;
                };
                st.serialize_field("G", g)?;
                if let Some(j) = j {
                    st.serialize_field("J", j)?;
                };
                st.serialize_field("Y", y)?;
                st.end()
            }
            Self::TransparentDSAPrivateKey { p, q, g, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 4)?;
                st.serialize_field("P", p)?;
                st.serialize_field("Q", q)?;
                st.serialize_field("G", g)?;
                st.serialize_field("X", x)?;
                st.end()
            }
            Self::TransparentDSAPublicKey { p, q, g, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 4)?;
                st.serialize_field("P", p)?;
                st.serialize_field("Q", q)?;
                st.serialize_field("G", g)?;
                st.serialize_field("Y", y)?;
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
                let mut st = serializer.serialize_struct("KeyMaterial", 8)?;
                st.serialize_field("Modulus", modulus)?;
                if let Some(private_exponent) = private_exponent {
                    st.serialize_field("PrivateExponent", private_exponent)?;
                };
                if let Some(public_exponent) = public_exponent {
                    st.serialize_field("PublicExponent", public_exponent)?;
                };
                if let Some(p) = p {
                    st.serialize_field("P", p)?;
                };
                if let Some(q) = q {
                    st.serialize_field("Q", q)?;
                };
                if let Some(prime_exponent_p) = prime_exponent_p {
                    st.serialize_field("PrimeExponentP", prime_exponent_p)?;
                };
                if let Some(prime_exponent_q) = prime_exponent_q {
                    st.serialize_field("PrimeExponentQ", prime_exponent_q)?;
                };
                if let Some(crt_coefficient) = crt_coefficient {
                    st.serialize_field("CrtCoefficient", crt_coefficient)?;
                };
                st.end()
            }
            Self::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 2)?;
                st.serialize_field("Modulus", modulus)?;
                st.serialize_field("PublicExponent", public_exponent)?;
                st.end()
            }
            Self::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", d)?;
                st.end()
            }
            Self::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
        }
    }
}
