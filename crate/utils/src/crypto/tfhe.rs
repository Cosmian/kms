use std::convert::TryFrom;

use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse, ErrorReason},
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType, VendorAttribute},
    },
};
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use torus_fhe::{
    torus::{TorusElement, T32},
    trlwe::{T32RLWEPoly, T32RLWESample, TRLWEKey},
    typenum::{U1023, U512},
};

use crate::{DeCipher, EnCipher};

type N = U512;
//*** LUT Parameters
type D = U1023;

#[derive(Serialize, Deserialize, Clone)]
pub struct TFHEKeyCreateRequest {
    /// Security Parameter
    pub vector_size: usize,
    /// Parameter (Mersenne Number >= out bits - 1)
    pub d: usize,
    /// sigma
    pub noise_deviation: f32,
    /// Pre-generated key to insert
    pub pregenerated_key: Option<TRLWEKey<N, D>>,
}

/// Create `VendorAttribute` to set in a `CreateRequest`
impl TryFrom<&TFHEKeyCreateRequest> for VendorAttribute {
    type Error = KmipError;

    fn try_from(request: &TFHEKeyCreateRequest) -> Result<Self, KmipError> {
        Ok(VendorAttribute {
            vendor_identification: "cosmian".to_owned(),
            attribute_name: "tfhe_key_create_request".to_owned(),
            attribute_value: serde_json::to_vec(&request).map_err(|_| {
                KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Attribute_Value,
                    "failed serializing the key setup value".to_string(),
                )
            })?,
        })
    }
}

impl TryFrom<&VendorAttribute> for TFHEKeyCreateRequest {
    type Error = KmipError;

    fn try_from(attribute: &VendorAttribute) -> Result<Self, KmipError> {
        if &attribute.vendor_identification != "cosmian"
            || &attribute.attribute_name != "tfhe_key_create_request"
        {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Attribute_Value,
                "the attributes in not a key create request".to_string(),
            ))
        }
        serde_json::from_slice::<TFHEKeyCreateRequest>(&attribute.attribute_value).map_err(|_| {
            KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing the Key Create Request".to_string(),
            )
        })
    }
}

impl TryFrom<&Attributes> for TFHEKeyCreateRequest {
    type Error = KmipError;

    fn try_from(attributes: &Attributes) -> Result<Self, KmipError> {
        let vdr = attributes.vendor_attributes.as_ref().ok_or_else(|| {
            KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Attribute_Value,
                "the attributes do not contain any vendor attribute, hence no shared key setup
                 data"
                    .to_string(),
            )
        })?;

        let va = vdr
            .iter()
            .find(|att| {
                &att.attribute_name == "tfhe_key_create_request"
                    && &att.vendor_identification == "cosmian"
            })
            .ok_or_else(|| {
                KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Attribute_Value,
                    "this attribute response does not contain a Shared Key Create Request"
                        .to_string(),
                )
            })?;
        TFHEKeyCreateRequest::try_from(va)
    }
}

pub struct Cipher {
    key_uid: String,
    shared_key: KeyBlock,
    noise_deviation: f32,
}

impl Cipher {
    pub fn instantiate(uid: impl Into<String>, shared_key: &Object) -> Result<Self, KmipError> {
        let key_block = match shared_key {
            Object::SymmetricKey { key_block } => key_block.clone(),
            _ => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Message,
                    "Expected a LWE Secret Key in a KMIP Symmetric Key".to_owned(),
                ))
            }
        };
        let attrs = key_block.key_value.attributes()?;
        let attrs = TFHEKeyCreateRequest::try_from(attrs)?;
        let noise_deviation = attrs.noise_deviation;
        Ok(Self {
            key_uid: uid.into(),
            shared_key: key_block.clone(),
            noise_deviation,
        })
    }
}

impl EnCipher for Cipher {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        let enc_code = match &request.data {
            None => None,
            Some(d) => {
                let shared_key = self.shared_key.as_bytes()?;
                let shared_key = serde_json::from_slice(shared_key).map_err(|e| {
                    KmipError::KmipError(ErrorReason::Invalid_Message, e.to_string())
                })?;

                let mut vec = T32RLWEPoly::<D>::default();
                let d: Vec<u32> = serde_json::from_slice(d).map_err(|e| {
                    KmipError::KmipError(ErrorReason::Invalid_Message, e.to_string())
                })?;
                for (dest, val) in vec.iter_mut().zip(d) {
                    *dest = T32::encode(val);
                }
                let mut rng = rand_hc::Hc128Rng::from_entropy();
                let mut res =
                    T32RLWESample::<N, D>::gen_from(&mut rng, &shared_key, self.noise_deviation);
                res += vec;
                Some(serde_json::to_vec(&res).map_err(|e| {
                    KmipError::KmipError(ErrorReason::Invalid_Message, e.to_string())
                })?)
            }
        };
        Ok(EncryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: enc_code,
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: None,
        })
    }
}

impl DeCipher for Cipher {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError> {
        let messages_bytes = match &request.data {
            None => None,
            Some(d) => {
                let shared_key = self.shared_key.as_bytes()?;
                let shared_key = serde_json::from_slice(shared_key).map_err(|e| {
                    KmipError::KmipError(ErrorReason::Invalid_Message, e.to_string())
                })?;
                let d: T32RLWESample<N, D> = serde_json::from_slice(d).map_err(|_| {
                    KmipError::KmipError(
                        ErrorReason::Invalid_Message,
                        "FHE: failed deserializing the messages to encrypt".to_string(),
                    )
                })?;

                let decrypted: Vec<u32> = d.decrypt(&shared_key).iter().copied().collect();
                Some(serde_json::to_vec(&decrypted).map_err(|_| {
                    KmipError::KmipError(
                        ErrorReason::Invalid_Message,
                        "DMCFE: failed serializing the messages".to_string(),
                    )
                })?)
            }
        };
        Ok(DecryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: messages_bytes,
            correlation_value: None,
        })
    }
}

pub fn array_to_key_block(
    key: &[u8],
    attributes: Attributes,
    key_format_type: KeyFormatType,
) -> KeyBlock {
    KeyBlock {
        cryptographic_algorithm: CryptographicAlgorithm::TFHE,
        key_format_type,
        key_compression_type: None,
        key_value: KeyValue {
            key_material: KeyMaterial::ByteString(key.to_vec()),
            attributes: Some(attributes),
        },
        // FIXME: is this the length of `key`? Document this field.
        cryptographic_length: 256_i32,
        key_wrapping_data: None,
    }
}
