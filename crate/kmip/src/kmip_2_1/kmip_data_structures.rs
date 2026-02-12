use std::{
    clone::Clone,
    fmt,
    fmt::{Display, Formatter, Write as _},
};

use cosmian_logger::{trace, warn};
use num_bigint_dig::BigInt;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, Visitor},
    ser::SerializeStruct,
};
use tracing::instrument;
use zeroize::Zeroizing;

use super::{
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, EncodingOption, EncryptionKeyInformation,
        KeyCompressionType, KeyFormatType, LinkType, LinkedObjectIdentifier,
        MacSignatureKeyInformation, ProfileName, RNGMode, RecommendedCurve, WrappingMethod,
    },
};
use crate::{
    SafeBigInt,
    error::KmipError,
    kmip_0::kmip_types::{
        DRBGAlgorithm, DestroyAction, ErrorReason, FIPS186Variation, HashingAlgorithm,
        RNGAlgorithm, ShreddingAlgorithm, UnwrapMode,
    },
    kmip_2_1::{kmip_attributes::Attribute, kmip_types::ItemType},
    pad_be_bytes,
    ttlv::{KmipFlavor, TTLV, TtlvDeserializer, to_ttlv},
};

#[derive(Clone, Eq, Serialize, Deserialize, PartialEq, Debug)]
pub struct DerivationParameters {
    /// Depends on the PRF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// Depends on the PRF and mode of operation: an empty IV is assumed if not
    /// provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_vector: Option<Vec<u8>>,
    /// Mandatory unless the Unique Identifier of a Secret Data object is
    /// provided. May be repeated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_data: Option<Zeroizing<Vec<u8>>>,
    /// Mandatory if Derivation method is PBKDF2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<Vec<u8>>,
    /// Mandatory if derivation method is PBKDF2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration_count: Option<i32>,
}

impl Display for DerivationParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(cryptographic_parameters) = &self.cryptographic_parameters {
            parts.push(format!(
                "cryptographic_parameters: {cryptographic_parameters}"
            ));
        }
        if let Some(initialization_vector) = &self.initialization_vector {
            parts.push(format!("initialization_vector: {initialization_vector:?}"));
        }
        if let Some(derivation_data) = &self.derivation_data {
            parts.push(format!("derivation_data: {derivation_data:?}"));
        }
        if let Some(salt) = &self.salt {
            parts.push(format!("salt: {salt:?}"));
        }
        if let Some(iteration_count) = &self.iteration_count {
            parts.push(format!("iteration_count: {iteration_count}"));
        }
        write!(f, "DerivationParameters {{ {} }}", parts.join(", "))
    }
}

/// A Key Block object is a structure used to encapsulate all of the information
/// that is closely associated with a cryptographic key.
/// Section 3 of KMIP Reference 2.1
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,

    /// Indicates the format of the elliptic curve public key. By default, the public key is uncompressed
    pub key_compression_type: Option<KeyCompressionType>,

    /// Byte String: for wrapped Key Value; Structure: for plaintext Key Value
    pub key_value: Option<KeyValue>,

    /// MAY be omitted only if this information is available from the Key Value.
    /// Does not apply to Secret Data or Opaque.
    /// If present, the Cryptographic Length SHALL also be present.
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    /// MAY be omitted only if this information is available from the Key Value.
    /// Does not apply to Secret Data or Opaque.
    /// If present, the Cryptographic Algorithm SHALL also be present.
    pub cryptographic_length: Option<i32>,

    /// SHALL only be present if the key is wrapped.
    pub key_wrapping_data: Option<KeyWrappingData>,
}

impl Display for KeyBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        parts.push(format!("key_format_type: {}", self.key_format_type));
        if let Some(key_compression_type) = &self.key_compression_type {
            parts.push(format!("key_compression_type: {key_compression_type:?}"));
        }
        if let Some(key_value) = &self.key_value {
            parts.push(format!("key_value: {key_value}"));
        }
        if let Some(cryptographic_algorithm) = &self.cryptographic_algorithm {
            parts.push(format!(
                "cryptographic_algorithm: {cryptographic_algorithm}"
            ));
        }
        if let Some(cryptographic_length) = &self.cryptographic_length {
            parts.push(format!("cryptographic_length: {cryptographic_length}"));
        }
        if let Some(key_wrapping_data) = &self.key_wrapping_data {
            parts.push(format!("key_wrapping_data: {key_wrapping_data}"));
        }
        write!(f, "KeyBlock {{ {} }}", parts.join(", "))
    }
}

impl Serialize for KeyBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("KeyBlock", 6)?;
        st.serialize_field("KeyFormatType", &self.key_format_type)?;
        if let Some(key_compression_type) = &self.key_compression_type {
            st.serialize_field("KeyCompressionType", key_compression_type)?;
        }
        if let Some(key_value) = &self.key_value {
            st.serialize_field(
                "KeyValue",
                &KeyValueSerializer {
                    key_format_type: self.key_format_type,
                    key_value: key_value.clone(),
                },
            )?;
        }
        if let Some(cryptographic_algorithm) = &self.cryptographic_algorithm {
            st.serialize_field("CryptographicAlgorithm", cryptographic_algorithm)?;
        }
        if let Some(cryptographic_length) = &self.cryptographic_length {
            st.serialize_field("CryptographicLength", cryptographic_length)?;
        }
        if let Some(key_wrapping_data) = &self.key_wrapping_data {
            st.serialize_field("KeyWrappingData", key_wrapping_data)?;
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for KeyBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            KeyFormatType,
            KeyCompressionType,
            KeyValue,
            CryptographicAlgorithm,
            CryptographicLength,
            KeyWrappingData,
        }

        struct KeyBlockVisitor;

        impl<'de> Visitor<'de> for KeyBlockVisitor {
            type Value = KeyBlock;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyBlock")
            }

            #[instrument(level = "trace", skip(self, map))]
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_format_type: Option<KeyFormatType> = None;
                let mut key_compression_type: Option<KeyCompressionType> = None;
                let mut key_value: Option<KeyValue> = None;
                let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
                let mut cryptographic_length: Option<i32> = None;
                let mut key_wrapping_data: Option<KeyWrappingData> = None;

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::KeyFormatType => {
                            if key_format_type.is_some() {
                                return Err(de::Error::duplicate_field("KeyFormatType"));
                            }
                            key_format_type = Some(map.next_value()?);
                        }
                        Field::KeyCompressionType => {
                            if key_compression_type.is_some() {
                                return Err(de::Error::duplicate_field("KeyCompressionType"));
                            }
                            key_compression_type = Some(map.next_value()?);
                        }
                        Field::KeyValue => {
                            if key_value.is_some() {
                                return Err(de::Error::duplicate_field("KeyValue"));
                            }
                            key_value = Some(map.next_value_seed(KeyValueDeserializer {
                                key_format_type: key_format_type.ok_or_else(|| {
                                    de::Error::missing_field(
                                        "KeyFormatType must be known to deserialize the KeyValue",
                                    )
                                })?,
                            })?);
                        }
                        Field::CryptographicAlgorithm => {
                            if cryptographic_algorithm.is_some() {
                                return Err(de::Error::duplicate_field("CryptographicAlgorithm"));
                            }
                            cryptographic_algorithm = Some(map.next_value()?);
                        }
                        Field::CryptographicLength => {
                            if cryptographic_length.is_some() {
                                return Err(de::Error::duplicate_field("CryptographicLength"));
                            }
                            cryptographic_length = Some(map.next_value()?);
                        }
                        Field::KeyWrappingData => {
                            if key_wrapping_data.is_some() {
                                return Err(de::Error::duplicate_field("KeyWrappingData"));
                            }
                            key_wrapping_data = Some(map.next_value()?);
                        }
                    }
                }
                let key_format_type =
                    key_format_type.ok_or_else(|| de::Error::missing_field("KeyFormatType"))?;
                Ok(KeyBlock {
                    key_format_type,
                    key_compression_type,
                    key_value,
                    cryptographic_algorithm,
                    cryptographic_length,
                    key_wrapping_data,
                })
            }
        }

        trace!("==> Deserializing KeyBlock");
        deserializer.deserialize_struct(
            "KeyBlock",
            &[
                "KeyFormatType",
                "KeyCompressionType",
                "KeyValue",
                "CryptographicAlgorithm",
                "CryptographicLength",
                "KeyWrappingData",
            ],
            KeyBlockVisitor,
        )
    }
}

impl KeyBlock {
    /// Return the wrapped key bytes if the object is wrapped, an error otherwise
    pub fn wrapped_key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        let key_value = self.key_value.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "wrapped_key_bytes: key is missing its key value".to_owned(),
            )
        })?;

        match key_value {
            KeyValue::ByteString(v) => Ok(v.clone()),
            KeyValue::Structure { .. } => Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Object_Type,
                "wrapped_key_bytes: the key is not wrapped".to_owned(),
            )),
        }
    }

    /// Return the raw bytes of a symmetric key
    /// Deprecated: use `key_bytes()`
    #[deprecated]
    pub fn symmetric_key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        self.key_bytes()
    }

    /// Return the key material of a symmetric key, raw or transparent.
    /// The PKCS#1 of an RSA Key, etc.
    pub fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        let key_value = self.key_value.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "key is missing its key value".to_owned(),
            )
        })?;

        match key_value {
            KeyValue::ByteString(_) => Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Object_Type,
                "Key bytes cannot be recovered from wrapped keys".to_owned(),
            )),
            KeyValue::Structure { key_material, .. } => match key_material {
                KeyMaterial::ByteString(v) => Ok(v.clone()),
                KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
                _ => Err(KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Object_Type,
                    "Key bytes can only be recovered from RSA and symmetric keys".to_owned(),
                )),
            },
        }
    }

    /// Return the key material of a covercrypt key, raw or transparent.
    pub fn covercrypt_key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        let key_value = self.key_value.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "key is missing its key value".to_owned(),
            )
        })?;

        match key_value {
            KeyValue::ByteString(_) => Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Object_Type,
                "Covercrypt key bytes: key bytes cannot be recovered from wrapped keys".to_owned(),
            )),
            KeyValue::Structure { key_material, .. } => {
                if let KeyMaterial::ByteString(v) = key_material {
                    return Ok(v.clone());
                }
                Err(KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Object_Type,
                    "Key bytes can only be recovered from Covercrypt keys".to_owned(),
                ))
            }
        }
    }

    /// Return the PKCS#1 or PKCS#8 or PKCS#12 DER bytes of a key
    pub fn pkcs_der_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        let key_value = self.key_value.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "pkcs_der_bytes: key is missing its key value".to_owned(),
            )
        })?;

        match key_value {
            KeyValue::ByteString(_) => Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Object_Type,
                "PKCS DER bytes cannot be recovered from wrapped keys".to_owned(),
            )),
            KeyValue::Structure { key_material, .. } => {
                if let KeyMaterial::ByteString(v) = key_material {
                    return Ok(v.clone());
                }
                Err(KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Object_Type,
                    "PKCS DER bytes can only be recovered this key".to_owned(),
                ))
            }
        }
    }

    /// Extract the raw bytes from the EC key material.
    /// These bytes are the same as the ones in openssl rwa bytes
    pub fn ec_raw_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        let KeyValue::Structure { key_material, .. } =
            self.key_value.as_ref().ok_or_else(|| {
                KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Object_Type,
                    "ec_raw_bytes: the key is missing its key value".to_owned(),
                )
            })?
        else {
            return Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Object_Type,
                "ec_raw_bytes: the key is wrapped".to_owned(),
            ));
        };
        match key_material {
            KeyMaterial::TransparentECPrivateKey { d, .. } => {
                let mut d_vec = d.to_bytes_be().1;
                let privkey_size = match key_material {
                    KeyMaterial::TransparentECPrivateKey {
                        recommended_curve, ..
                    } => match recommended_curve {
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
                    },
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
                "Elliptic Curve raw bytes can only be recovered from EC keys".to_owned(),
            )),
        }
    }

    /// Return the key material of a secret data
    pub fn secret_data_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KmipError> {
        let key_value = self.key_value.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "secret data key is missing its key value".to_owned(),
            )
        })?;

        match key_value {
            KeyValue::ByteString(_) => Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Object_Type,
                "secret_data_bytes: key bytes cannot be recovered from wrapped keys".to_owned(),
            )),
            KeyValue::Structure { key_material, .. } => match key_material {
                KeyMaterial::ByteString(v) => Ok(v.clone()),
                _ => Err(KmipError::InvalidKmip21Value(
                    ErrorReason::Invalid_Object_Type,
                    "Secret Data Key bytes can only be recovered from raw secret data".to_owned(),
                )),
            },
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
        let attributes = self.attributes().ok();
        Ok((key, attributes))
    }

    /// Returns the `Attributes` of that key block if any, an error otherwise
    pub fn attributes(&self) -> Result<&Attributes, KmipError> {
        let Some(KeyValue::Structure { attributes, .. }) = &self.key_value else {
            let mut error_msg =
                "The Object Key Value is wrapped. Attributes cannot be recovered".to_owned();
            if let Some(wrapping_data) = &self.key_wrapping_data {
                if let Some(encryption_key_info) = &wrapping_data.encryption_key_information {
                    let _ = write!(
                        error_msg,
                        " (wrapped with key: {})",
                        encryption_key_info.unique_identifier
                    );
                }
            }
            return Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                error_msg,
            ));
        };
        attributes.as_ref().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "The object has no attributes".to_owned(),
            )
        })
    }

    /// Returns the `Attributes` of that key block if any, an error otherwise
    pub fn attributes_mut(&mut self) -> Result<&mut Attributes, KmipError> {
        let mut error_msg =
            "The Object Key Value is wrapped. Attributes cannot be recovered".to_owned();
        if let Some(wrapping_data) = &self.key_wrapping_data {
            if let Some(encryption_key_info) = &wrapping_data.encryption_key_information {
                let _ = write!(
                    error_msg,
                    " (wrapped with key: {})",
                    encryption_key_info.unique_identifier
                );
            }
        }
        let Some(KeyValue::Structure { attributes, .. }) = &mut self.key_value else {
            return Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                error_msg,
            ));
        };
        attributes.as_mut().ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "The object has no attributes".to_owned(),
            )
        })
    }

    /// Returns the `KeyMaterial` of that key block if any, an error otherwise
    pub fn key_material(&self) -> Result<&KeyMaterial, KmipError> {
        let Some(KeyValue::Structure { key_material, .. }) = &self.key_value else {
            return Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "The Object Key Value is wrapped. The Key Material cannot be recovered".to_owned(),
            ));
        };
        Ok(key_material)
    }

    /// Returns the `KeyMaterial` of that key block if any, an error otherwise
    pub fn key_material_mut(&mut self) -> Result<&mut KeyMaterial, KmipError> {
        let Some(KeyValue::Structure { key_material, .. }) = &mut self.key_value else {
            return Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "The Object Key Value is wrapped. The Key Material cannot be recovered".to_owned(),
            ));
        };
        Ok(key_material)
    }

    /// Returns the identifier of a linked object of a particular type if it exists in the attributes
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
        let attributes = self.attributes()?;

        // Retrieve the links attribute from the object attributes, if it exists
        let Some(links) = &attributes.link else {
            return Ok(None);
        };

        // If there are no links, return None
        if links.is_empty() {
            return Ok(None);
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
            let Some(key_value) = &self.key_value else {
                return None;
            };
            let KeyValue::Structure { attributes, .. } = key_value else {
                return None;
            };
            let a = attributes.as_ref()?;
            a.cryptographic_algorithm.as_ref()
        })
    }
}

/// The Key Value is used only inside a Key Block and is either a Byte String or
/// a structure:
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
#[expect(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum KeyValue {
    /// The key value is a byte string when key wrapped
    ByteString(Zeroizing<Vec<u8>>),
    /// The key value is a structure when the key is not wrapped
    Structure {
        key_material: KeyMaterial,
        attributes: Option<Attributes>,
    },
}

impl Display for KeyValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteString(v) => write!(f, "KeyValue::ByteString(len={})", v.len()),
            Self::Structure {
                key_material,
                attributes,
            } => {
                if let Some(attributes) = attributes {
                    if attributes != &Attributes::default() {
                        return write!(
                            f,
                            "KeyValue::Structure {{ key_material: {key_material}, attributes: \
                             {attributes} }}"
                        );
                    }
                    Ok(())
                } else {
                    write!(
                        f,
                        "KeyValue::Structure {{ key_material: {key_material}, attributes: None }}"
                    )
                }
            }
        }
    }
}

/// Structure used to serialize `KeyValue`
/// This structure maintains the `KeyFormatType` which is passed down
/// to the serializer of the `KeyMaterial` called
struct KeyValueSerializer {
    key_format_type: KeyFormatType,
    key_value: KeyValue,
}

impl Serialize for KeyValueSerializer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.key_value {
            KeyValue::ByteString(bytes) => serializer.serialize_bytes(bytes),
            KeyValue::Structure {
                key_material,
                attributes,
            } => {
                let mut st = serializer.serialize_struct("KeyValue", 2)?;
                st.serialize_field(
                    "KeyMaterial",
                    &KeyMaterialSerializer {
                        key_format_type: self.key_format_type,
                        key_material: key_material.clone(),
                    },
                )?;
                if let Some(attributes) = attributes {
                    if attributes != &Attributes::default() {
                        st.serialize_field("Attributes", attributes)?;
                    }
                }
                st.end()
            }
        }
    }
}

struct KeyValueDeserializer {
    key_format_type: KeyFormatType,
}

impl<'de> DeserializeSeed<'de> for KeyValueDeserializer {
    type Value = KeyValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            KeyMaterial,
            Attributes,
        }

        struct KeyValueVisitor {
            key_format_type: KeyFormatType,
        }

        impl<'de> Visitor<'de> for KeyValueVisitor {
            type Value = KeyValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyValue")
            }

            /// This is called by the TTLV deserializer in `deserialize_seq`
            /// which is itself called by the call to `deserializer.deserialize_any()` below
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytestring = Vec::<u8>::new();
                while let Some(byte) = seq.next_element()? {
                    bytestring.push(byte);
                }
                Ok(KeyValue::ByteString(Zeroizing::new(bytestring)))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_material: Option<KeyMaterial> = None;
                let mut attributes: Option<Attributes> = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::KeyMaterial => {
                            if key_material.is_some() {
                                return Err(de::Error::duplicate_field("KeyMaterial"));
                            }
                            key_material = Some(map.next_value_seed(KeyMaterialDeserializer {
                                key_format_type: self.key_format_type,
                            })?);
                        }
                        Field::Attributes => {
                            if attributes.is_some() {
                                return Err(de::Error::duplicate_field("Attributes"));
                            }
                            attributes = Some(map.next_value()?);
                        }
                    }
                }

                let key_material =
                    key_material.ok_or_else(|| de::Error::missing_field("KeyMaterial"))?;
                Ok(KeyValue::Structure {
                    key_material,
                    attributes,
                })
            }
        }

        deserializer.deserialize_any(KeyValueVisitor {
            key_format_type: self.key_format_type,
        })
    }
}

impl KeyValue {
    /// Returns the `KeyValue` key material bytes if any, an error otherwise
    /// Only `KeyMaterial::ByteString` and `KeyMaterial::TransparentSymmetricKey` are supported
    pub fn raw_bytes(&self) -> Result<&[u8], KmipError> {
        let Self::Structure { key_material, .. } = self else {
            return Err(KmipError::InvalidKmip21Value(
                ErrorReason::Invalid_Attribute_Value,
                "key Value is wrapped".to_owned(),
            ));
        };
        match &key_material {
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key),
            KeyMaterial::ByteString(v) => Ok(v),
            other => Err(KmipError::Kmip21NotSupported(
                ErrorReason::Invalid_Data_Type,
                format!("The key has an invalid key material: {other}"),
            )),
        }
    }

    /// Returns the `KeyValue` key material bytes if any, an error otherwise
    pub fn to_ttlv_bytes(&self, key_format_type: KeyFormatType) -> Result<Vec<u8>, KmipError> {
        to_ttlv(&KeyValueSerializer {
            key_format_type,
            key_value: self.clone(),
        })
        .and_then(|ttlv| ttlv.to_bytes(KmipFlavor::Kmip2))
        .map_err(Into::into)
    }

    /// Deserializes a `KeyValue` from the given TTLV bytes
    pub fn from_ttlv_bytes(
        bytes: &[u8],
        key_format_type: KeyFormatType,
    ) -> Result<Self, KmipError> {
        let ttlv = TTLV::from_bytes(bytes, KmipFlavor::Kmip2)?;
        KeyValueDeserializer { key_format_type }
            .deserialize(&mut TtlvDeserializer::from_ttlv(ttlv))
            .map_err(Into::into)
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
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
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

impl Display for KeyWrappingData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        parts.push(format!("wrapping_method: {}", self.wrapping_method));
        if let Some(eki) = &self.encryption_key_information {
            parts.push(format!("encryption_key_information: {eki}"));
        }
        if let Some(mski) = &self.mac_signature_key_information {
            parts.push(format!("mac_signature_key_information: {mski}"));
        }
        if let Some(mac) = &self.mac_signature {
            parts.push(format!("mac_signature: len={}", mac.len()));
        }
        if let Some(iv) = &self.iv_counter_nonce {
            parts.push(format!("iv_counter_nonce: len={}", iv.len()));
        }
        if let Some(encoding) = &self.encoding_option {
            parts.push(format!("encoding_option: {encoding:?}"));
        }
        write!(f, "KeyWrappingData {{ {} }}", parts.join(", "))
    }
}

impl KeyWrappingData {
    /// Returns the encoding option for the key wrapping data
    /// If not present, the wrapped Key Value structure SHALL not have any encoding.
    #[must_use]
    pub fn get_encoding(&self) -> EncodingOption {
        self.encoding_option.unwrap_or(EncodingOption::TTLVEncoding)
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
            encoding_option: Some(EncodingOption::TTLVEncoding),
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
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
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
            encoding_option: Some(EncodingOption::TTLVEncoding),
        }
    }
}

impl Display for KeyWrappingSpecification {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        parts.push(format!("wrapping_method: {}", self.wrapping_method));
        if let Some(eki) = &self.encryption_key_information {
            parts.push(format!("encryption_key_information: {eki}"));
        }
        if let Some(mski) = &self.mac_or_signature_key_information {
            parts.push(format!("mac_or_signature_key_information: {mski}"));
        }
        if let Some(attr_names) = &self.attribute_name {
            parts.push(format!("attribute_name: {attr_names:?}"));
        }
        if let Some(encoding) = &self.encoding_option {
            parts.push(format!("encoding_option: {encoding:?}"));
        }
        write!(f, "KeyWrappingSpecification {{ {} }}", parts.join(", "))
    }
}

impl KeyWrappingSpecification {
    /// Returns the encoding option for the key wrapping specification
    /// If not present, the wrapped Key Value structure SHALL be TTLV encoded.
    #[must_use]
    pub fn get_encoding(&self) -> EncodingOption {
        self.encoding_option.unwrap_or(EncodingOption::TTLVEncoding)
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
        c_r_t_coefficient: Option<Box<SafeBigInt>>,
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

impl KeyMaterial {
    /// Converts the `KeyMaterial` to a JSON value.
    /// Used by the database migration scripts
    pub fn to_json_value(
        &self,
        key_format_type: KeyFormatType,
    ) -> Result<serde_json::Value, KmipError> {
        let serializer = KeyMaterialSerializer {
            key_format_type,
            key_material: self.clone(),
        };
        serde_json::to_value(&serializer).map_err(|e| {
            KmipError::ConversionError(format!("Failed to serialize KeyMaterial to JSON: {e}"))
        })
    }

    /// Converts the `KeyMaterial` to a TTLV object.
    /// This is used to calculate the Digest
    pub fn to_ttlv(&self, key_format_type: KeyFormatType) -> Result<TTLV, KmipError> {
        to_ttlv(&KeyMaterialSerializer {
            key_format_type,
            key_material: self.clone(),
        })
        .map_err(Into::into)
    }
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

/// Serializer used by `KeyValueSerializer`
pub(crate) struct KeyMaterialSerializer {
    pub(crate) key_format_type: KeyFormatType,
    pub(crate) key_material: KeyMaterial,
}

impl Serialize for KeyMaterialSerializer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.key_material {
            KeyMaterial::ByteString(bytes) => match self.key_format_type {
                KeyFormatType::Raw
                | KeyFormatType::ECPrivateKey
                | KeyFormatType::Opaque
                | KeyFormatType::PKCS1
                | KeyFormatType::PKCS10
                | KeyFormatType::PKCS12
                | KeyFormatType::PKCS7
                | KeyFormatType::PKCS8
                | KeyFormatType::X509
                | KeyFormatType::ConfigurableKEM
                | KeyFormatType::CoverCryptSecretKey
                | KeyFormatType::CoverCryptPublicKey => serializer.serialize_bytes(bytes),
                #[cfg(feature = "non-fips")]
                KeyFormatType::Pkcs12Legacy => serializer.serialize_bytes(bytes),
                x => Err(serde::ser::Error::custom(format!(
                    "KeyMaterialWrapper: {x:?} key format type does not support byte strings"
                ))),
            },
            KeyMaterial::TransparentSymmetricKey { key } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("Key", &**key)?;
                st.end()
            }
            KeyMaterial::TransparentDHPrivateKey { p, q, g, j, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
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
            KeyMaterial::TransparentDHPublicKey { p, q, g, j, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
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
            KeyMaterial::TransparentDSAPrivateKey { p, q, g, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("P", &**p)?;
                st.serialize_field("Q", &**q)?;
                st.serialize_field("G", &**g)?;
                st.serialize_field("X", &***x)?;
                st.end()
            }
            KeyMaterial::TransparentDSAPublicKey { p, q, g, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("P", &**p)?;
                st.serialize_field("Q", &**q)?;
                st.serialize_field("G", &**g)?;
                st.serialize_field("Y", &**y)?;
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
                c_r_t_coefficient: crt_coefficient,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 9)?;
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
                    st.serialize_field("CRTCoefficient", &***crt_coefficient)?;
                }
                st.end()
            }
            KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("Modulus", &**modulus)?;
                st.serialize_field("PublicExponent", &**public_exponent)?;
                st.end()
            }
            KeyMaterial::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", &***d)?;
                st.end()
            }
            KeyMaterial::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
        }
    }
}

struct KeyMaterialDeserializer {
    key_format_type: KeyFormatType,
}

impl<'de> DeserializeSeed<'de> for KeyMaterialDeserializer {
    type Value = KeyMaterial;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
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
            Modulus,
            PrivateExponent,
            PublicExponent,
            PrimeExponentP,
            PrimeExponentQ,
            CRTCoefficient,
            RecommendedCurve,
            QString,
        }

        struct KeyMaterialVisitor {
            key_format_type: KeyFormatType,
        }

        impl<'de> Visitor<'de> for KeyMaterialVisitor {
            type Value = KeyMaterial;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyMaterialVisitor")
            }

            /// This is called by the TTLV deserializer in `deserialize_seq`
            /// which is itself called by the call to `deserializer.deserialize_any()` below
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytestring = Vec::<u8>::new();
                while let Some(byte) = seq.next_element()? {
                    bytestring.push(byte);
                }
                match self.key_format_type {
                    KeyFormatType::Raw
                    | KeyFormatType::ECPrivateKey
                    | KeyFormatType::Opaque
                    | KeyFormatType::PKCS1
                    | KeyFormatType::PKCS10
                    | KeyFormatType::PKCS12
                    | KeyFormatType::PKCS7
                    | KeyFormatType::PKCS8
                    | KeyFormatType::X509
                    | KeyFormatType::ConfigurableKEM
                    | KeyFormatType::CoverCryptPublicKey
                    | KeyFormatType::CoverCryptSecretKey => {
                        Ok(KeyMaterial::ByteString(Zeroizing::new(bytestring)))
                    }
                    #[cfg(feature = "non-fips")]
                    KeyFormatType::Pkcs12Legacy => {
                        Ok(KeyMaterial::ByteString(Zeroizing::new(bytestring)))
                    }
                    _ => Err(de::Error::custom(format!(
                        "KeyMaterialVisitor: {:?} key format type is not expected to have a byte \
                         string key material",
                        self.key_format_type
                    ))),
                }
            }

            #[expect(clippy::many_single_char_names)]
            #[instrument(level = "trace", skip(self, map))]
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut bytestring: Option<Zeroizing<Vec<u8>>> = None;
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
                                return Err(de::Error::duplicate_field("ByteString"));
                            }
                            bytestring = Some(map.next_value()?);
                        }
                        Field::D => {
                            if d.is_some() {
                                return Err(de::Error::duplicate_field("D"));
                            }
                            d = Some(Box::new(map.next_value()?));
                        }
                        Field::P => {
                            if p.is_some() {
                                return Err(de::Error::duplicate_field("P"));
                            }
                            p = Some(Box::new(map.next_value()?));
                        }
                        Field::Q => {
                            if q.is_some() {
                                return Err(de::Error::duplicate_field("Q"));
                            }
                            q = Some(Box::new(map.next_value()?));
                        }
                        Field::G => {
                            if g.is_some() {
                                return Err(de::Error::duplicate_field("G"));
                            }
                            g = Some(Box::new(map.next_value()?));
                        }
                        Field::J => {
                            if j.is_some() {
                                return Err(de::Error::duplicate_field("J"));
                            }
                            j = Some(Box::new(map.next_value()?));
                        }
                        Field::X => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("X"));
                            }
                            x = Some(Box::new(map.next_value()?));
                        }
                        Field::Y => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("Y"));
                            }
                            y = Some(Box::new(map.next_value()?));
                        }
                        Field::Key => {
                            if key.is_some() {
                                return Err(de::Error::duplicate_field("Key"));
                            }
                            key = Some(map.next_value()?);
                        }
                        Field::Modulus => {
                            if modulus.is_some() {
                                return Err(de::Error::duplicate_field("Modulus"));
                            }
                            modulus = Some(Box::new(map.next_value()?));
                        }
                        Field::PrivateExponent => {
                            if private_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PrivateExponent"));
                            }
                            private_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PublicExponent => {
                            if public_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PublicExponent"));
                            }
                            public_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentP => {
                            if prime_exponent_p.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentP"));
                            }
                            prime_exponent_p = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentQ => {
                            if prime_exponent_q.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentQ"));
                            }
                            prime_exponent_q = Some(Box::new(map.next_value()?));
                        }
                        Field::CRTCoefficient => {
                            if crt_coefficient.is_some() {
                                return Err(de::Error::duplicate_field("CrtCoefficient"));
                            }
                            crt_coefficient = Some(Box::new(map.next_value()?));
                        }
                        Field::RecommendedCurve => {
                            if recommended_curve.is_some() {
                                return Err(de::Error::duplicate_field("RecommendedCurve"));
                            }
                            recommended_curve = Some(map.next_value()?);
                        }
                        Field::QString => {
                            if q_string.is_some() {
                                return Err(de::Error::duplicate_field("QString"));
                            }
                            q_string = Some(map.next_value()?);
                        }
                    }
                }

                if let Some(key) = key {
                    Ok(KeyMaterial::TransparentSymmetricKey { key })
                } else {
                    Ok(match &self.key_format_type {
                        KeyFormatType::TransparentDHPublicKey
                        | KeyFormatType::TransparentDHPrivateKey => {
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
                        KeyFormatType::TransparentDSAPublicKey
                        | KeyFormatType::TransparentDSAPrivateKey => {
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
                        KeyFormatType::TransparentRSAPublicKey => {
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
                        KeyFormatType::TransparentRSAPrivateKey => {
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
                                c_r_t_coefficient: crt_coefficient,
                            }
                        }
                        KeyFormatType::TransparentECPublicKey
                        | KeyFormatType::TransparentECPrivateKey => {
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
                        f => {
                            return Err(de::Error::custom(format!(
                                "unsupported key format type: {f:?}, for the key material"
                            )));
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
        match self.key_format_type {
            KeyFormatType::Raw
            | KeyFormatType::ECPrivateKey
            | KeyFormatType::Opaque
            | KeyFormatType::PKCS1
            | KeyFormatType::PKCS10
            | KeyFormatType::PKCS12
            | KeyFormatType::PKCS7
            | KeyFormatType::PKCS8
            | KeyFormatType::X509
            | KeyFormatType::CoverCryptPublicKey
            | KeyFormatType::CoverCryptSecretKey => {
                trace!(
                    "===> KeyMaterial: Deserializing Bytes String for key format type: {:?} ",
                    self.key_format_type
                );
                // This will call visit_seq for both the TTLV and the JSON deserializer
                deserializer.deserialize_any(KeyMaterialVisitor {
                    key_format_type: self.key_format_type,
                })
            }
            #[cfg(feature = "non-fips")]
            KeyFormatType::Pkcs12Legacy => {
                trace!(
                    "===> KeyMaterial: Deserializing Bytes String for key format type: {:?} ",
                    self.key_format_type
                );
                // This will call visit_seq for both the TTLV and the JSON deserializer
                deserializer.deserialize_any(KeyMaterialVisitor {
                    key_format_type: self.key_format_type,
                })
            }
            f => {
                trace!("===> KeyMaterial: Deserializing Structure for key format type: {f:?}");
                deserializer.deserialize_struct(
                    "KeyMaterial",
                    FIELDS,
                    KeyMaterialVisitor {
                        key_format_type: self.key_format_type,
                    },
                )
            }
        }
    }
}

/// The Server Information  base object is a structure that contains a set of OPTIONAL fields
/// that describe server information.
/// Where a server supports returning information in a vendor-specific field for
/// which there is an equivalent field within the structure,
/// the server SHALL provide the standardized version of the field.
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Debug, Clone)]
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

/// The conversion to KMIP 1.4 uses the `to_string()` call on `ServerInformation`
impl Display for ServerInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strings = vec![];
        if let Some(server_name) = &self.server_name {
            strings.push(format!("server_name: {server_name}"));
        }
        if let Some(server_serial_number) = &self.server_serial_number {
            strings.push(format!("server_serial_number: {server_serial_number}"));
        }
        if let Some(server_version) = &self.server_version {
            strings.push(format!("server_version: {server_version}"));
        }
        if let Some(server_load) = &self.server_load {
            strings.push(format!("server_load: {server_load}"));
        }
        if let Some(product_name) = &self.product_name {
            strings.push(format!("product_name: {product_name}"));
        }
        if let Some(build_level) = &self.build_level {
            strings.push(format!("build_level: {build_level}"));
        }
        if let Some(build_date) = &self.build_date {
            strings.push(format!("build_date: {build_date}"));
        }
        if let Some(cluster_info) = &self.cluster_info {
            strings.push(format!("cluster_info: {cluster_info}"));
        }
        if let Some(alternative_failover_endpoints) = &self.alternative_failover_endpoints {
            strings.push(format!(
                "alternative_failover_endpoints: {alternative_failover_endpoints:?}"
            ));
        }
        write!(f, "{}", strings.join(", "))
    }
}

/// An Extension Information object is a structure describing Objects with Item Tag values
/// in the Extensions range.
/// The Extension Name is a Text String that is used to name the Object.
/// The Extension Tag is the Item Tag Value of the Object.
/// The Extension Type is the Item Type Value of the Object.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
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
/// and their values by Object Type enumeration, as well as the Object Group(s)
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
        if let Some(attributes) = &self.attributes {
            if let Some(object_groups) = &self.object_groups {
                use std::fmt::Write as _;
                let mut groups = String::new();
                for group in object_groups {
                    let _ = write!(groups, "{group}, ");
                }
                let object_groups = groups.trim_end_matches(", ");
                return write!(
                    f,
                    "ObjectDefaults {{ object_type: {:?}, attributes: {}, object_groups: {} }}",
                    self.object_type, attributes, object_groups
                );
            }
            return write!(
                f,
                "ObjectDefaults {{ object_type: {:?}, attributes: {} }}",
                self.object_type, attributes
            );
        }
        if let Some(object_groups) = &self.object_groups {
            use std::fmt::Write as _;
            let mut groups = String::new();
            for group in object_groups {
                let _ = write!(groups, "{group}, ");
            }
            let object_groups = groups.trim_end_matches(", ");

            return write!(
                f,
                "ObjectDefaults {{ object_type: {:?}, object_groups: {} }}",
                self.object_type, object_groups
            );
        }
        write!(
            f,
            "ObjectDefaults {{ object_type: {:?} }}",
            self.object_type
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
        if let Some(object_defaults) = &self.object_defaults {
            for (i, object_default) in object_defaults.iter().enumerate() {
                write!(f, "Object Default {i}: {object_default}")?;
            }
        } else {
            write!(f, "DefaultsInformation: No Object Defaults")?;
        }
        Ok(())
    }
}

/// The `CapabilityInformation` structure provides information about the capabilities
/// of the server, such as supported operations, objects, and algorithms.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
