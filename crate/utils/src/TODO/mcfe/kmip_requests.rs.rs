use std::convert::TryFrom;

use cosmian_kms_common::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Create, Decrypt, DecryptResponse, Encrypt, EncryptResponse, ErrorReason},
    kmip_types::{
        AttributeReference, Attributes, CryptographicAlgorithm, CryptographicParameters,
        CryptographicUsageMask, KeyFormatType, SecretDataType, VendorAttribute,
        VendorAttributeReference,
    },
};
use cosmian_mcfe::lwe;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    error::KmsError,
    kmip::kmip_server::server::{DeCipher, EnCipher},
    kms_bail, kms_ensure,
    result::{KResult, KResultHelper},
};

/// Create LWE Setup `VendorAttribute` to set in a `CreateRequest` or for
/// importing an LWE key
pub fn vendor_attributes_from_mcfe_setup(
    setup: &cosmian_mcfe::lwe::Setup,
) -> KResult<VendorAttribute> {
    Ok(VendorAttribute {
        vendor_identification: "cosmian".to_owned(),
        attribute_name: "mcfe_setup".to_owned(),
        attribute_value: serde_json::to_vec(setup).map_err(|_e| {
            KmsError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed serializing the MCFE setup value".to_string(),
            )
        })?,
    })
}

pub fn mcfe_setup_from_attributes(attributes: &Attributes) -> KResult<cosmian_mcfe::lwe::Setup> {
    let vdr = attributes.vendor_attributes.as_ref().context(
        "the attributes do not contain any vendor attribute, hence no MCFE LWE setup data",
    )?;
    let setup_attr = vdr
        .iter()
        .find(|att| &att.attribute_name == "mcfe_setup" && &att.vendor_identification == "cosmian")
        .context("this attribute response does not contain the MCFE LWE setup")?;
    serde_json::from_slice::<cosmian_mcfe::lwe::Setup>(setup_attr.attribute_value.as_slice())
        .context("failed deserializing the LWE setup from the vendor attribute")
}

pub fn mcfe_master_key_from_key_block(
    sk: &KeyBlock,
) -> KResult<cosmian_mcfe::lwe::MasterSecretKey> {
    kms_ensure!(
        sk.cryptographic_algorithm == CryptographicAlgorithm::LWE,
        "this Get Response does not contain an LWE key"
    );
    kms_ensure!(
        sk.key_format_type == KeyFormatType::McfeMasterSecretKey,
        "this Get Response does not contain an MCFE Master Secret Key"
    );
    kms_ensure!(
        sk.key_wrapping_data.is_none(),
        "unwrapping a LWE Master Secret Key is not yet support",
    );
    match &sk.key_value {
        KeyValue::Wrapped(_bytes) => Err(KmsError::ServerError(
            "unwrapping a LWE Master Secret Key is not yet support".to_owned(),
        )),
        KeyValue::PlainText { key_material, .. } => {
            serde_json::from_slice::<cosmian_mcfe::lwe::MasterSecretKey>(match key_material {
                KeyMaterial::ByteString(v) => v.as_slice(),
                other => kms_bail!(
                    "Invalid key material for an LWE master secret key: {:?}",
                    other
                ),
            })
            .context("failed deserializing the LWE Master Secret Key from the Key Material")
        }
    }
}

pub fn mcfe_functional_key_from_key_block(
    sk: &KeyBlock,
) -> KResult<cosmian_mcfe::lwe::FunctionalKey> {
    kms_ensure!(
        sk.cryptographic_algorithm == CryptographicAlgorithm::LWE,
        "this Get Response does not contain an LWE key",
    );
    kms_ensure!(
        sk.key_format_type == KeyFormatType::McfeFunctionalKey,
        "this Get Response does not contain an MCFE Functional Key",
    );
    kms_ensure!(
        sk.key_wrapping_data.is_none(),
        "unwrapping a LWE Functional Key is not yet support"
    );
    match &sk.key_value {
        KeyValue::Wrapped(_bytes) => Err(KmsError::ServerError(
            "unwrapping a LWE Functional Key is not yet support".to_owned(),
        )),
        KeyValue::PlainText { key_material, .. } => {
            serde_json::from_slice::<cosmian_mcfe::lwe::FunctionalKey>(match key_material {
                KeyMaterial::ByteString(v) => v.as_slice(),
                other => kms_bail!(
                    "Invalid key material for an LWE functional key: {:?}",
                    other
                ),
            })
            .context("failed deserializing the LWE Functional Key from the Key Material")
        }
    }
}

pub fn mcfe_secret_key_from_key_block(sk: &KeyBlock) -> KResult<cosmian_mcfe::lwe::SecretKey> {
    kms_ensure!(
        sk.cryptographic_algorithm == CryptographicAlgorithm::LWE,
        "this Secret Key does not contain an LWE key"
    );
    kms_ensure!(
        sk.key_format_type == KeyFormatType::McfeSecretKey
            || sk.key_format_type == KeyFormatType::McfeFksSecretKey,
        "this Secret Key does not contain a (D)MCFE Key"
    );
    kms_ensure!(
        sk.key_wrapping_data.is_none(),
        "unwrapping a LWE Secret Key is not yet supported",
    );
    match &sk.key_value {
        KeyValue::Wrapped(_bytes) => {
            kms_bail!("unwrapping a LWE Secret Key is not yet supported".to_owned(),)
        }
        KeyValue::PlainText { key_material, .. } => {
            serde_json::from_slice::<cosmian_mcfe::lwe::SecretKey>(match key_material {
                KeyMaterial::ByteString(v) => v.as_slice(),
                other => {
                    kms_bail!(
                        "Invalid key material for an LWE secret key: {:?}",
                        other.to_owned(),
                    )
                }
            })
            .context("failed deserializing the LWE Secret Key from the Key Material")
        }
    }
}

// The `AttributeReference` to recover the LWE `Setup` of a stored LWE Key
pub fn lwe_setup_attribute_reference() -> AttributeReference {
    AttributeReference::Vendor(VendorAttributeReference {
        vendor_identification: "cosmian".to_owned(),
        attribute_name: "mcfe_setup".to_owned(),
    })
}

pub fn secret_key_from_lwe_secret_key(setup: &lwe::Setup, sk: &lwe::SecretKey) -> KResult<Object> {
    let n0_m0 = sk.0[0].len();
    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::LWE,
            key_format_type: KeyFormatType::McfeSecretKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(
                    serde_json::to_vec(&sk)
                        .context("failed serializing the MCFE LWE Secret Key")
                        .reason(ErrorReason::Invalid_Message)?,
                ),
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

pub fn secret_key_from_lwe_fks_secret_key(
    setup: &lwe::Setup,
    sk: &lwe::SecretKey,
) -> KResult<Object> {
    let n0_m0 = sk.0[0].len();
    Ok(Object::SecretData {
        secret_data_type: SecretDataType::FunctionalKeyShare,
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::LWE,
            key_format_type: KeyFormatType::McfeFksSecretKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(
                    serde_json::to_vec(&sk)
                        .context("failed serializing the MCFE LWE FKS Secret Key")
                        .reason(ErrorReason::Invalid_Message)?,
                ),
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
                    ..Attributes::new(ObjectType::SecretData)
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
) -> KResult<Object> {
    let n0_m0 = msk[0].0.len();
    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::LWE,
            key_format_type: KeyFormatType::McfeMasterSecretKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(
                    serde_json::to_vec(&msk)
                        .context("failed serializing the MCFE LWE Master Secret Key")
                        .reason(ErrorReason::Invalid_Message)?,
                ),
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
) -> KResult<Object> {
    let n0_m0 = fk.0.len();
    Ok(Object::SecretData {
        secret_data_type: SecretDataType::FunctionalKey,
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::LWE,
            key_format_type: KeyFormatType::McfeFunctionalKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(
                    serde_json::to_vec(&fk)
                        .context("failed serializing the MCFE LWE Functional Key")
                        .reason(ErrorReason::Invalid_Message)?,
                ),
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

/// The Cipher Texts passed as `data` in the KMIP Encryption Response
pub type McfeEncryptionResponse = Vec<Vec<BigUint>>;

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

/// The Cipher Texts passed as `data` in the KMIP Decryption Response
pub type McfeDecryptionResponse = Vec<Vec<BigUint>>;

/// Build a `CreateRequest` for an LWE Secret Key
pub fn lwe_secret_key_create_request(setup: &lwe::Setup) -> KResult<Create> {
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
            key_format_type: Some(KeyFormatType::McfeSecretKey),
            vendor_attributes: Some(vec![vendor_attributes_from_mcfe_setup(setup)?]),
            ..Attributes::new(ObjectType::SymmetricKey)
        },
        protection_storage_masks: None,
    })
}

/// Build a `CreateRequest` for an LWE Master Secret Key
pub fn lwe_master_secret_key_create_request(setup: &lwe::Setup) -> KResult<Create> {
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
            key_format_type: Some(KeyFormatType::McfeMasterSecretKey),
            vendor_attributes: Some(vec![vendor_attributes_from_mcfe_setup(setup)?]),
            ..Attributes::new(ObjectType::SymmetricKey)
        },
        protection_storage_masks: None,
    })
}

#[derive(Serialize, Deserialize)]
pub struct FunctionalKeyCreateRequest {
    pub master_secret_key_uid: String,
    pub vectors: Vec<Vec<BigUint>>,
}

/// Create LWE Setup `VendorAttributes` to set in a `CreateRequest` for a
/// functional Key
impl TryFrom<&FunctionalKeyCreateRequest> for VendorAttribute {
    type Error = KmsError;

    fn try_from(request: &FunctionalKeyCreateRequest) -> KResult<Self> {
        Ok(VendorAttribute {
            vendor_identification: "cosmian".to_owned(),
            attribute_name: "mcfe_functional_key_create_request".to_owned(),
            attribute_value: serde_json::to_vec(&request)
                .context("failed serializing the MCFE setup value")
                .reason(ErrorReason::Invalid_Attribute_Value)?,
        })
    }
}

impl TryFrom<&VendorAttribute> for FunctionalKeyCreateRequest {
    type Error = KmsError;

    fn try_from(attribute: &VendorAttribute) -> KResult<Self> {
        if &attribute.vendor_identification != "cosmian"
            || &attribute.attribute_name != "mcfe_functional_key_create_request"
        {
            return Err(KmsError::ServerError(
                "the attributes in not a functional key create request".to_owned(),
            )
            .reason(ErrorReason::Invalid_Attribute_Value))
        }
        serde_json::from_slice(&attribute.attribute_value)
            .context("failed deserializing the Functional Key Create Request")
            .reason(ErrorReason::Invalid_Attribute_Value)
    }
}

impl TryFrom<&Attributes> for FunctionalKeyCreateRequest {
    type Error = KmsError;

    fn try_from(attributes: &Attributes) -> KResult<Self> {
        let vdr = attributes.vendor_attributes.as_ref().context(
            "the attributes do not contain any vendor attribute, hence no MCFE LWE setup data",
        )?;
        let va = vdr
            .iter()
            .find(|att| {
                &att.attribute_name == "mcfe_functional_key_create_request"
                    && &att.vendor_identification == "cosmian"
            })
            .context("this attribute response does not contain a Functional Key Create Request")?;
        FunctionalKeyCreateRequest::try_from(va)
    }
}

/// Build a `CreateRequest` for an LWE Functional Key
pub fn lwe_functional_key_create_request(request: &FunctionalKeyCreateRequest) -> KResult<Create> {
    Ok(Create {
        object_type: ObjectType::SecretData,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
            key_format_type: Some(KeyFormatType::McfeFunctionalKey),
            vendor_attributes: Some(vec![VendorAttribute::try_from(request)?]),
            ..Attributes::new(ObjectType::SecretData)
        },
        protection_storage_masks: None,
    })
}

/// Extract the lwe::Setup value from the `SecretKey` attributes
pub fn setup_from_secret_key(uid: &str, sk: &KeyBlock) -> KResult<lwe::Setup> {
    let attributes = sk
        .key_value
        .attributes()
        .with_context(|| format!("for key {}", uid))?;
    mcfe_setup_from_attributes(attributes)
        .with_context(|| format!("failed extracting Setup values from key: {}", uid))
        .reason(ErrorReason::Invalid_Attribute_Value)
}

/// Extract the lwe::Setup value from the `SecretKey` attributes
pub fn setup_from_functional_key(uid: &str, sk: &KeyBlock) -> KResult<lwe::Setup> {
    let attributes = sk
        .key_value
        .attributes()
        .with_context(|| format!("for key {}", uid))?;
    mcfe_setup_from_attributes(attributes)
        .with_context(|| format!("failed extracting Setup values from key: {}", uid))
        .reason(ErrorReason::Invalid_Attribute_Value)
}
