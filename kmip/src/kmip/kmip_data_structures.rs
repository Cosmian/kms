use std::clone::Clone;

use num_bigint::BigUint;
use paperclip::actix::Apiv2Schema;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use tracing::trace;

use crate::{
    error::KmipError,
    kmip::{
        kmip_key_utils::WrappedSymmetricKey,
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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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
    pub fn to_vec(&self) -> Result<Vec<u8>, KmipError> {
        let (key_material, _) = self.key_value.plaintext().ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "invalid Plain Text".to_string(),
            )
        })?;
        match key_material {
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
            other => {
                return Err(KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Message,
                    format!("Invalid key material type for a symmetric key: {:?}", other),
                ))
            }
        }
    }

    /// Extract the Key bytes from the given `KeyBlock`
    pub fn key_bytes(&self) -> Result<Vec<u8>, KmipError> {
        match &self.key_value {
            KeyValue::PlainText { key_material, .. } => {
                let key = match key_material {
                    KeyMaterial::ByteString(v) => Ok(v.clone()),
                    KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
                    other => Err(KmipError::InvalidKmipValue(
                        ErrorReason::Invalid_Data_Type,
                        format!("The key has an invalid key material: {:?}", other),
                    )),
                };
                key
            }
            KeyValue::Wrapped(wrapped) => Ok(wrapped.clone()),
        }
    }

    /// Extract the Key bytes from the given `KeyBlock`
    pub fn key_bytes_and_attributes(
        &self,
        uid: &str,
    ) -> Result<(Vec<u8>, Option<Attributes>), KmipError> {
        match &self.key_value {
            KeyValue::PlainText {
                key_material,
                attributes,
            } => {
                let key = match key_material {
                    KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
                    KeyMaterial::ByteString(v) => Ok(v.clone()),
                    other => Err(KmipError::InvalidKmipValue(
                        ErrorReason::Invalid_Data_Type,
                        format!(
                            "The key at uid: {} has an invalid key material: {:?}",
                            uid, other
                        ),
                    )),
                };
                let attributes = attributes.clone();
                Ok((key?, attributes))
            }
            KeyValue::Wrapped(wrapped) => Ok((wrapped.clone(), None)),
        }
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

    /// Convert a raw-wrapped symmetric key into a KMIP-`KeyBlock` struct.
    /// Remark/Warning:
    ///     The key attributes are serialized into the `KeyValue` in order to be located later
    ///
    /// # Arguments
    ///
    /// * `wrapped_key`: key byte-array
    /// * `iv_counter_nonce`: iv counter nonce
    /// * `key_format_type`: KMIP `KeyFormatType`
    /// * `wrapped_key_attributes`: the KMIP `Attributes
    ///
    /// # Returns
    ///
    /// * `key_block`: the new `KeyBlock` structure
    ///
    /// # Errors
    ///
    /// * serializing can fail
    pub fn to_wrapped_key_block(
        wrapped_key: &[u8],
        iv_counter_nonce: Option<Vec<u8>>,
        key_format_type: KeyFormatType,
        wrapped_key_attributes: &Attributes,
    ) -> Result<KeyBlock, KmipError> {
        trace!("array_to_wrapped_key_block: {}", wrapped_key.len());
        let key_value = serde_json::to_vec(&WrappedSymmetricKey {
            attributes: wrapped_key_attributes.clone(),
            wrapped_symmetric_key: wrapped_key.to_vec(),
        })
        .map_err(|e| {
            KmipError::InvalidKmipObject(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;
        let key_wrapping_data = KeyWrappingData {
            wrapping_method: WrappingMethod::Encrypt,
            iv_counter_nonce,
            ..KeyWrappingData::default()
        };
        Ok(KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::AES,
            key_format_type,
            key_compression_type: None,
            key_value: KeyValue::Wrapped(key_value),
            cryptographic_length: wrapped_key.len() as i32,
            key_wrapping_data: Some(key_wrapping_data),
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
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum KeyValue {
    PlainText {
        // may be a specialized key material
        #[serde(rename = "KeyMaterial")]
        key_material: KeyMaterial,
        #[serde(rename = "Attributes", skip_serializing_if = "Option::is_none")]
        attributes: Option<Attributes>,
    },
    Wrapped(Vec<u8>),
}

impl KeyValue {
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        match self {
            KeyValue::PlainText { attributes, .. } => attributes.as_ref().ok_or_else(|| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Attribute_Value,
                    "key is missing its attributes".to_string(),
                )
            }),
            KeyValue::Wrapped(_) => Err(KmipError::KmipNotSupported(
                ErrorReason::Feature_Not_Supported,
                "key is wrapped and this is not yet supported".to_string(),
            )),
        }
    }

    #[must_use]
    pub fn plaintext(&self) -> Option<(&KeyMaterial, &Option<Attributes>)> {
        match self {
            KeyValue::PlainText {
                key_material,
                attributes,
            } => Some((key_material, attributes)),
            _ => None,
        }
    }

    pub fn raw_bytes(&self) -> Result<Vec<u8>, KmipError> {
        match &self {
            KeyValue::PlainText { key_material, .. } => {
                let key = match key_material {
                    KeyMaterial::ByteString(v) => Ok(v.clone()),
                    other => Err(KmipError::KmipNotSupported(
                        ErrorReason::Invalid_Data_Type,
                        format!("The key has an invalid key material: {:?}", other),
                    )),
                };
                key
            }
            KeyValue::Wrapped(wrapped) => Ok(wrapped.clone()),
        }
    }
}

impl Serialize for KeyValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            KeyValue::PlainText {
                key_material,
                attributes,
            } => {
                let mut st = serializer.serialize_struct("PlainText", 2)?;
                st.serialize_field("KeyMaterial", key_material)?;
                st.serialize_field("Attributes", attributes)?;
                st.end()
            }
            KeyValue::Wrapped(bytes) => serializer.serialize_bytes(bytes),
        }
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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Apiv2Schema, Default)]
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
#[derive(Deserialize, Clone, Debug, PartialEq, Apiv2Schema)]
#[serde(untagged)]
#[openapi(empty)]
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
            KeyMaterial::ByteString(bytes) => serializer.serialize_bytes(bytes),
            KeyMaterial::TransparentSymmetricKey { key } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("Key", key)?;
                st.end()
            }
            KeyMaterial::TransparentDHPrivateKey { p, q, g, j, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("P", p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", q)?
                };
                st.serialize_field("G", g)?;
                if let Some(j) = j {
                    st.serialize_field("J", j)?
                };
                st.serialize_field("X", x)?;
                st.end()
            }
            KeyMaterial::TransparentDHPublicKey { p, q, g, j, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("P", p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", q)?
                };
                st.serialize_field("G", g)?;
                if let Some(j) = j {
                    st.serialize_field("J", j)?
                };
                st.serialize_field("Y", y)?;
                st.end()
            }
            KeyMaterial::TransparentDSAPrivateKey { p, q, g, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 4)?;
                st.serialize_field("P", p)?;
                st.serialize_field("Q", q)?;
                st.serialize_field("G", g)?;
                st.serialize_field("X", x)?;
                st.end()
            }
            KeyMaterial::TransparentDSAPublicKey { p, q, g, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 4)?;
                st.serialize_field("P", p)?;
                st.serialize_field("Q", q)?;
                st.serialize_field("G", g)?;
                st.serialize_field("Y", y)?;
                st.end()
            }
            KeyMaterial::TransparentRSAPrivateKey {
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
                    st.serialize_field("PrivateExponent", private_exponent)?
                };
                if let Some(public_exponent) = public_exponent {
                    st.serialize_field("PublicExponent", public_exponent)?
                };
                if let Some(p) = p {
                    st.serialize_field("P", p)?
                };
                if let Some(q) = q {
                    st.serialize_field("Q", q)?
                };
                if let Some(prime_exponent_p) = prime_exponent_p {
                    st.serialize_field("PrimeExponentP", prime_exponent_p)?
                };
                if let Some(prime_exponent_q) = prime_exponent_q {
                    st.serialize_field("PrimeExponentQ", prime_exponent_q)?
                };
                if let Some(crt_coefficient) = crt_coefficient {
                    st.serialize_field("CrtCoefficient", crt_coefficient)?
                };
                st.end()
            }
            KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 2)?;
                st.serialize_field("Modulus", modulus)?;
                st.serialize_field("PublicExponent", public_exponent)?;
                st.end()
            }
            KeyMaterial::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", d)?;
                st.end()
            }
            KeyMaterial::TransparentECPublicKey {
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
