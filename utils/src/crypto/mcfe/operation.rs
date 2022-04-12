use std::convert::TryFrom;

use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse, ErrorReason},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask,
            KeyFormatType, SecretDataType, VendorAttribute,
        },
    },
};
use cosmian_mcfe::lwe;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{DeCipher, EnCipher};

/// Create LWE Setup `VendorAttribute` to set in a `CreateRequest` or for
/// importing an LWE key
pub fn vendor_attributes_from_mcfe_setup(
    setup: &cosmian_mcfe::lwe::Setup,
) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: "cosmian".to_owned(),
        attribute_name: "mcfe_setup".to_owned(),
        attribute_value: serde_json::to_vec(setup).map_err(|_e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed serializing the MCFE setup value".to_string(),
            )
        })?,
    })
}

pub fn mcfe_setup_from_attributes(
    attributes: &Attributes,
) -> Result<cosmian_mcfe::lwe::Setup, KmipError> {
    let vdr = attributes.vendor_attributes.as_ref().ok_or_else(|| {
        KmipError::InvalidKmipObject(
            ErrorReason::Attribute_Not_Found,
            "the attributes do not contain any vendor attribute, hence no MCFE LWE setup data"
                .to_string(),
        )
    })?;

    let setup_attr = vdr
        .iter()
        .find(|att| &att.attribute_name == "mcfe_setup" && &att.vendor_identification == "cosmian")
        .ok_or_else(|| {
            KmipError::InvalidKmipObject(
                ErrorReason::Attribute_Not_Found,
                "this attribute response does not contain the MCFE LWE setup".to_string(),
            )
        })?;

    serde_json::from_slice::<cosmian_mcfe::lwe::Setup>(setup_attr.attribute_value.as_slice())
        .map_err(|_| {
            KmipError::InvalidKmipObject(
                ErrorReason::Attribute_Not_Found,
                "failed deserializing the LWE setup from the vendor attribute".to_string(),
            )
        })
}

pub fn mcfe_master_key_from_key_block(
    sk: &KeyBlock,
) -> Result<cosmian_mcfe::lwe::MasterSecretKey, KmipError> {
    if sk.cryptographic_algorithm != CryptographicAlgorithm::LWE {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            "this Secret Key does not contain an LWE key".to_string(),
        ))
    }

    if sk.key_format_type != KeyFormatType::McfeMasterSecretKey {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            "this Secret Key does not contain an (D)MCFE Key".to_string(),
        ))
    }

    if sk.key_wrapping_data.is_some() {
        return Err(KmipError::KmipNotSupported(
            ErrorReason::Key_Wrap_Type_Not_Supported,
            "unwrapping a LWE Master Secret Key is not yet support".to_string(),
        ))
    }

    match &sk.key_value {
        KeyValue::Wrapped(_bytes) => Err(KmipError::KmipNotSupported(
            ErrorReason::Key_Wrap_Type_Not_Supported,
            "unwrapping an LWE Master Secret Key is not yet supported".to_string(),
        )),
        KeyValue::PlainText { key_material, .. } => serde_json::from_slice::<
            cosmian_mcfe::lwe::MasterSecretKey,
        >(match key_material {
            KeyMaterial::ByteString(v) => v.as_slice(),
            other => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Data_Type,
                    format!(
                        "Invalid key material for an LWE master secret key: {:?}",
                        other
                    ),
                ))
            }
        })
        .map_err(|_| {
            KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Data_Type,
                "failed deserializing the LWE Master Secret Key from the Key Material".to_string(),
            )
        }),
    }
}

pub fn mcfe_functional_key_from_key_block(
    sk: &KeyBlock,
) -> Result<cosmian_mcfe::lwe::FunctionalKey, KmipError> {
    if sk.cryptographic_algorithm != CryptographicAlgorithm::LWE {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            "this Secret Key does not contain an LWE key".to_string(),
        ))
    }

    if sk.key_format_type != KeyFormatType::McfeFunctionalKey {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            "this Secret Key does not contain an (D)MCFE Key".to_string(),
        ))
    }

    if sk.key_wrapping_data.is_some() {
        return Err(KmipError::KmipNotSupported(
            ErrorReason::Key_Wrap_Type_Not_Supported,
            "unwrapping a LWE Functional Key is not yet support".to_string(),
        ))
    }

    match &sk.key_value {
        KeyValue::Wrapped(_bytes) => Err(KmipError::KmipNotSupported(
            ErrorReason::Key_Wrap_Type_Not_Supported,
            "unwrapping a LWE Functional Key is not yet support".to_owned(),
        )),
        KeyValue::PlainText { key_material, .. } => serde_json::from_slice::<
            cosmian_mcfe::lwe::FunctionalKey,
        >(match key_material {
            KeyMaterial::ByteString(v) => v.as_slice(),
            other => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    format!(
                        "Invalid key material for an LWE functional key: {:?}",
                        other
                    ),
                ))
            }
        })
        .map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the LWE Functional Key from the Key Material {e}"),
            )
        }),
    }
}

pub fn mcfe_secret_key_from_key_block(
    sk: &KeyBlock,
) -> Result<cosmian_mcfe::lwe::SecretKey, KmipError> {
    if sk.cryptographic_algorithm != CryptographicAlgorithm::LWE {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            "this Secret Key does not contain an LWE key".to_string(),
        ))
    }

    if !(sk.key_format_type == KeyFormatType::McfeSecretKey
        || sk.key_format_type == KeyFormatType::McfeFksSecretKey)
    {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            "this Secret Key does not contain an (D)MCFE Key".to_string(),
        ))
    }

    if sk.key_wrapping_data.is_some() {
        return Err(KmipError::KmipNotSupported(
            ErrorReason::Key_Wrap_Type_Not_Supported,
            "unwrapping a LWE Master Secret Key is not yet support".to_string(),
        ))
    }

    match &sk.key_value {
        KeyValue::Wrapped(_bytes) => Err(KmipError::KmipNotSupported(
            ErrorReason::Key_Wrap_Type_Not_Supported,
            "unwrapping a LWE Functional Key is not yet support".to_owned(),
        )),
        KeyValue::PlainText { key_material, .. } => {
            serde_json::from_slice::<cosmian_mcfe::lwe::SecretKey>(match key_material {
                KeyMaterial::ByteString(v) => v.as_slice(),
                other => {
                    return Err(KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Object_Type,
                        format!(
                            "Invalid key material for an LWE functional key: {:?}",
                            other
                        ),
                    ))
                }
            })
            .map_err(|e| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Attribute_Value,
                    format!("failed deserializing the LWE Secret Key from the Key Material {e}"),
                )
            })
        }
    }
}

pub fn secret_key_from_lwe_secret_key(
    setup: &lwe::Setup,
    sk: &lwe::SecretKey,
) -> Result<Object, KmipError> {
    let n0_m0 = sk.0[0].len();
    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::LWE,
            key_format_type: KeyFormatType::McfeSecretKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(serde_json::to_vec(&sk).map_err(|_| {
                    KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Message,
                        "failed serializing the MCFE LWE Secret Key".to_string(),
                    )
                })?),
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
                    cryptographic_length: Some(n0_m0 as i32),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: Some(vec![vendor_attributes_from_mcfe_setup(setup)?]),
                    key_format_type: Some(KeyFormatType::McfeSecretKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
                        ..CryptographicParameters::default()
                    }),
                    ..Attributes::new(ObjectType::SymmetricKey)
                }),
            },
            cryptographic_length: n0_m0 as i32,
            key_wrapping_data: None,
        },
    })
}

pub fn secret_key_from_lwe_master_secret_key(
    setup: &lwe::Setup,
    msk: &[lwe::SecretKey], //lwe::MasterSecretKey,
) -> Result<Object, KmipError> {
    let n0_m0 = msk[0].0.len();
    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::LWE,
            key_format_type: KeyFormatType::McfeMasterSecretKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(serde_json::to_vec(&msk).map_err(|_| {
                    KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Message,
                        "failed serializing the MCFE LWE Master".to_string(),
                    )
                })?),
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
                    cryptographic_length: Some(n0_m0 as i32),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: Some(vec![vendor_attributes_from_mcfe_setup(setup)?]),
                    key_format_type: Some(KeyFormatType::McfeMasterSecretKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
                        ..CryptographicParameters::default()
                    }),
                    ..Attributes::new(ObjectType::SymmetricKey)
                }),
            },
            cryptographic_length: n0_m0 as i32,
            key_wrapping_data: None,
        },
    })
}

pub fn secret_data_from_lwe_functional_key(
    setup: &lwe::Setup,
    fk: &lwe::FunctionalKey, //lwe::MasterSecretKey,
) -> Result<Object, KmipError> {
    let n0_m0 = fk.0.len();
    Ok(Object::SecretData {
        secret_data_type: SecretDataType::FunctionalKey,
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::LWE,
            key_format_type: KeyFormatType::McfeFunctionalKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(serde_json::to_vec(&fk).map_err(|_| {
                    KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Message,
                        "failed serializing the MCFE LWE Functional Key".to_string(),
                    )
                })?),
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
                    cryptographic_length: Some(n0_m0 as i32),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Decrypt),
                    vendor_attributes: Some(vec![vendor_attributes_from_mcfe_setup(setup)?]),
                    key_format_type: Some(KeyFormatType::McfeFunctionalKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
                        ..CryptographicParameters::default()
                    }),
                    ..Attributes::new(ObjectType::SecretData)
                }),
            },
            cryptographic_length: n0_m0 as i32,
            key_wrapping_data: None,
        },
    })
}

/// The Labeled Messages passed as `data` in the KMIP Encryption Request
#[derive(Serialize, Deserialize)]
pub struct McfeEncryptionRequest(pub Vec<(Vec<u8>, Vec<BigUint>)>);

/// The Message passed as `data` in the KMIP Decryption Request
/// Cipher Texts must be arranged by vectors of n client cipher texts: to
/// decrypt messages m1 and m2, of client 1, 2 and 3, cipher texts must be
/// arranged
///
/// ```json
/// [
///     [ct_m1_c1, ct_m1_c2, ct_m1_c3],
///     [ct_m2_c1, ct_m2_c2, ct_m2_c3]
/// ]
/// ```
#[derive(Serialize, Deserialize)]
pub struct McfeDecryptionRequest {
    // vectors of client cipher texts and their corresponding label
    pub labeled_cipher_texts: Vec<(Vec<u8>, Vec<Vec<BigUint>>)>,
    // n clients x m vector length
    pub vectors: Vec<Vec<BigUint>>,
}

#[derive(Serialize, Deserialize)]
pub struct FunctionalKeyCreateRequest {
    pub master_secret_key_uid: String,
    pub vectors: Vec<Vec<BigUint>>,
}

/// Create LWE Setup `VendorAttributes` to set in a `CreateRequest` for a
/// functional Key
impl TryFrom<&FunctionalKeyCreateRequest> for VendorAttribute {
    type Error = KmipError;

    fn try_from(request: &FunctionalKeyCreateRequest) -> Result<Self, KmipError> {
        Ok(VendorAttribute {
            vendor_identification: "cosmian".to_owned(),
            attribute_name: "mcfe_functional_key_create_request".to_owned(),
            attribute_value: serde_json::to_vec(&request).map_err(|_| {
                KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Message,
                    "failed serializing the MCFE setup value".to_string(),
                )
            })?,
        })
    }
}

impl TryFrom<&VendorAttribute> for FunctionalKeyCreateRequest {
    type Error = KmipError;

    fn try_from(attribute: &VendorAttribute) -> Result<Self, KmipError> {
        if &attribute.vendor_identification != "cosmian"
            || &attribute.attribute_name != "mcfe_functional_key_create_request"
        {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Attribute_Value,
                "the attributes in not a functional key create request".to_owned(),
            ))
        }

        serde_json::from_slice(&attribute.attribute_value).map_err(|_| {
            KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing the Functional Key Create Request".to_string(),
            )
        })
    }
}

impl TryFrom<&Attributes> for FunctionalKeyCreateRequest {
    type Error = KmipError;

    fn try_from(attributes: &Attributes) -> Result<Self, KmipError> {
        let vdr = attributes.vendor_attributes.as_ref().ok_or_else(|| {
            KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Attribute_Value,
                "the attributes do not contain any vendor attribute, hence no MCFE LWE setup data"
                    .to_string(),
            )
        })?;

        let va = vdr
            .iter()
            .find(|att| {
                &att.attribute_name == "mcfe_functional_key_create_request"
                    && &att.vendor_identification == "cosmian"
            })
            .ok_or_else(|| {
                KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Attribute_Value,
                    "this attribute response does not contain a Functional Key Create Request"
                        .to_string(),
                )
            })?;

        FunctionalKeyCreateRequest::try_from(va)
    }
}

/// Extract the `lwe::Setup` value from the `SecretKey` attributes
pub fn setup_from_secret_key(_uid: &str, sk: &KeyBlock) -> Result<lwe::Setup, KmipError> {
    let attributes = sk.key_value.attributes()?;
    mcfe_setup_from_attributes(attributes)
}

/// Extract the `lwe::Setup` value from the `SecretKey` attributes
pub fn setup_from_functional_key(_uid: &str, sk: &KeyBlock) -> Result<lwe::Setup, KmipError> {
    let attributes = sk.key_value.attributes()?;
    mcfe_setup_from_attributes(attributes)
}

pub struct DMcfeEnCipher {
    key_uid: String,
    dmcfe: lwe::DMcfe,
}

impl DMcfeEnCipher {
    pub fn instantiate(uid: &str, secret_key: &Object) -> Result<DMcfeEnCipher, KmipError> {
        let key_block = match secret_key {
            Object::SymmetricKey { key_block } => key_block.clone(),
            _ => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    "Expected a DMCFE LWE Secret Key in a KMIP Symmetric Key Key".to_owned(),
                ))
            }
        };
        let setup = setup_from_secret_key(uid, &key_block)?;
        let parameters = lwe::Parameters::instantiate(&setup).map_err(|e| {
            KmipError::InvalidKmipObject(ErrorReason::Invalid_Message, e.to_string())
        })?;
        let mut dmcfe = lwe::DMcfe::instantiate(&parameters).map_err(|e| {
            KmipError::InvalidKmipObject(ErrorReason::Invalid_Message, e.to_string())
        })?;
        dmcfe.set_secret_key(mcfe_secret_key_from_key_block(&key_block)?);
        Ok(DMcfeEnCipher {
            dmcfe,
            key_uid: uid.to_string(),
        })
    }
}

impl EnCipher for DMcfeEnCipher {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        let cts = match &request.data {
            None => None,
            Some(d) => {
                let req: McfeEncryptionRequest = serde_json::from_slice(d).map_err(|_| {
                    KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Message,
                        "DMCFE: failed deserializing the messages to encrypt".to_string(),
                    )
                })?;
                let mut cts: Vec<Vec<BigUint>> = Vec::with_capacity(req.0.len());
                for (l, m) in &req.0 {
                    let ct = self.dmcfe.encrypt(m, l).map_err(|e| {
                        KmipError::InvalidKmipObject(ErrorReason::Invalid_Message, e.to_string())
                    })?;
                    cts.push(ct);
                }
                Some(serde_json::to_vec(&cts).map_err(|_| {
                    KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Message,
                        "DMCFE: failed serializing the cipher texts".to_string(),
                    )
                })?)
            }
        };
        Ok(EncryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: cts,
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: None,
        })
    }
}

pub struct DMcfeDeCipher {
    key_uid: String,
    functional_key: lwe::FunctionalKey,
    parameters: lwe::Parameters,
}

impl DMcfeDeCipher {
    /// Instantiate a DMCFE decipher
    /// The `SecretKey` should be a functional Key
    pub fn instantiate(uid: &str, functional_key: &Object) -> Result<DMcfeDeCipher, KmipError> {
        let key_block = match functional_key {
            Object::SecretData {
                secret_data_type,
                key_block,
            } if secret_data_type == &SecretDataType::FunctionalKey => key_block.clone(),
            _ => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Message,
                    "Expected a DMCFE Functional Key".to_owned(),
                ))
            }
        };

        let setup = setup_from_functional_key(uid, &key_block)?;
        let parameters = lwe::Parameters::instantiate(&setup).map_err(|e| {
            KmipError::InvalidKmipObject(ErrorReason::Invalid_Message, e.to_string())
        })?;
        let functional_key: lwe::FunctionalKey = mcfe_functional_key_from_key_block(&key_block)?;
        Ok(DMcfeDeCipher {
            key_uid: uid.to_string(),
            functional_key,
            parameters,
        })
    }
}

impl DeCipher for DMcfeDeCipher {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError> {
        let messages_bytes = match &request.data {
            None => None,
            Some(d) => {
                let req: McfeDecryptionRequest = serde_json::from_slice(d).map_err(|_| {
                    KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Message,
                        "DMCFE: failed deserializing the messages to encrypt".to_string(),
                    )
                })?;

                let mut messages: Vec<BigUint> = Vec::with_capacity(req.labeled_cipher_texts.len());
                for (label, cts) in &req.labeled_cipher_texts {
                    let message = self
                        .parameters
                        .decrypt(label, cts, &self.functional_key, &req.vectors)
                        .map_err(|e| {
                            KmipError::InvalidKmipObject(
                                ErrorReason::Invalid_Message,
                                e.to_string(),
                            )
                        })?;
                    messages.push(message);
                }
                Some(serde_json::to_vec(&messages).map_err(|_| {
                    KmipError::InvalidKmipObject(
                        ErrorReason::Invalid_Message,
                        "DMCFE: failed serializing the messages to encrypt".to_string(),
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
