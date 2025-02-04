use std::str::FromStr;

use base64::Engine as _;
use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::KeyWrappingSpecification,
    kmip_operations::{
        Certify, CertifyResponse, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Decrypt,
        DecryptResponse, Destroy, DestroyResponse, EncryptResponse, Export, ExportResponse,
        GetAttributes, GetAttributesResponse, ImportResponse, Locate, LocateResponse,
        RevokeResponse, Validate, ValidateResponse,
    },
    kmip_types::{
        BlockCipherMode, CertificateRequestType, CryptographicAlgorithm, CryptographicParameters,
        EncodingOption, EncryptionKeyInformation, HashingAlgorithm, KeyFormatType, PaddingMethod,
        RecommendedCurve, UniqueIdentifier, WrappingMethod,
    },
    requests::{
        build_revoke_key_request, create_ec_key_pair_request, create_rsa_key_pair_request,
        create_symmetric_key_kmip_object, decrypt_request, encrypt_request,
        get_ec_private_key_request, get_ec_public_key_request, get_rsa_private_key_request,
        get_rsa_public_key_request, import_object_request, symmetric_key_create_request,
    },
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use js_sys::Uint8Array;
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

use crate::{
    create_utils::{prepare_sym_key_elements, Curve, SymmetricAlgorithm},
    export_utils::{der_to_pem, tag_from_object},
    types::{ExportKeyFormat, WrappingAlgorithm},
};

fn parse_ttlv_response<T>(response: &str) -> Result<JsValue, JsValue>
where
    T: DeserializeOwned + Serialize,
{
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    from_ttlv(&ttlv)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects: T| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

// Certify request
#[wasm_bindgen]
pub fn certify_ttlv_request(
    unique_identifier: Option<String>,
    certificate_request_type: Option<String>,
    certificate_request_value: Option<Vec<u8>>,
    attributes: JsValue,
) -> Result<JsValue, JsValue> {
    let unique_identifier = unique_identifier.map(UniqueIdentifier::TextString);
    let certificate_request_type = certificate_request_type.and_then(|s| {
        CertificateRequestType::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid certificate type: {e}")))
            .ok()
    });
    let attributes = serde_wasm_bindgen::from_value(attributes)?;
    let request = Certify {
        unique_identifier,
        attributes: Some(attributes),
        certificate_request_value,
        certificate_request_type,
        ..Certify::default()
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_certify_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<CertifyResponse>(response)
}

// Create_key_pair requests
#[wasm_bindgen]
pub fn create_rsa_key_pair_ttlv_request(
    private_key_id: Option<String>,
    tags: Vec<String>,
    cryptographic_length: usize,
    sensitive: bool,
) -> Result<JsValue, JsValue> {
    let private_key_id = private_key_id.map(UniqueIdentifier::TextString);
    let request: CreateKeyPair =
        create_rsa_key_pair_request(private_key_id, tags, cryptographic_length, sensitive)
            .map_err(|e| JsValue::from_str(&format!("Key pair creation failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn create_ec_key_pair_ttlv_request(
    private_key_id: Option<String>,
    tags: Vec<String>,
    recommended_curve: &str,
    sensitive: bool,
) -> Result<JsValue, JsValue> {
    let private_key_id = private_key_id.map(UniqueIdentifier::TextString);
    let recommended_curve: RecommendedCurve = Curve::from_str(recommended_curve)
        .map_err(|e| JsValue::from_str(&format!("Invalid recommended curve: {e}")))?
        .into();
    let request: CreateKeyPair =
        create_ec_key_pair_request(private_key_id, tags, recommended_curve, sensitive)
            .map_err(|e| JsValue::from_str(&format!("Key pair creation failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_create_keypair_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<CreateKeyPairResponse>(response)
}

// Create request

#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn create_sym_key_ttlv_request(
    key_id: Option<String>,
    tags: Vec<String>,
    number_of_bits: Option<usize>,
    symmetric_algorithm: &str,
    sensitive: bool,
    wrap_key_id: Option<String>,
    wrap_key_b64: Option<String>,
) -> Result<JsValue, JsValue> {
    let algorithm = SymmetricAlgorithm::from_str(symmetric_algorithm)
        .map_err(|e| JsValue::from_str(&format!("Invalid cryptographic algorithm: {e}")))?;
    let (number_of_bits, key_bytes, algorithm) =
        prepare_sym_key_elements(number_of_bits, &wrap_key_b64, algorithm).map_err(|e| {
            JsValue::from_str(&format!("Error building symmetric key elements: {e}"))
        })?;

    if let Some(key_bytes) = key_bytes {
        let mut object =
            create_symmetric_key_kmip_object(key_bytes.as_slice(), algorithm, sensitive)
                .map_err(|e| JsValue::from_str(&format!("Error creating symmetric key: {e}")))?;
        if let Some(wrapping_key_id) = &wrap_key_id {
            let attributes = object.attributes_mut().map_err(|e| {
                JsValue::from_str(&format!("Error creating symmetric key attributes: {e}"))
            })?;
            attributes.set_wrapping_key_id(wrapping_key_id);
        }
        let request = import_object_request(key_id, object, None, false, false, &tags);
        to_ttlv(&request)
            .map_err(|e| JsValue::from(e.to_string()))
            .and_then(|objects| {
                serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
            })
    } else {
        let key_id = key_id.map(UniqueIdentifier::TextString);
        let request = symmetric_key_create_request(
            key_id,
            number_of_bits,
            algorithm,
            &tags,
            sensitive,
            wrap_key_id.as_ref(),
        )
        .map_err(|e| JsValue::from_str(&format!("Sym key request creation failed: {e}")))?;
        to_ttlv(&request)
            .map_err(|e| JsValue::from(e.to_string()))
            .and_then(|objects| {
                serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
            })
    }
}

#[wasm_bindgen]
pub fn parse_create_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<CreateResponse>(response)
}

// Decrypt request
#[wasm_bindgen]
pub fn decrypt_ttlv_request(
    key_unique_identifier: &str,
    nonce: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    authenticated_tag: Option<Vec<u8>>,
    authentication_data: Option<Vec<u8>>,
    cryptographic_parameters: JsValue,
) -> Result<JsValue, JsValue> {
    let cryptographic_parameters: Option<CryptographicParameters> =
        if cryptographic_parameters.is_null() || cryptographic_parameters.is_undefined() {
            None
        } else {
            Some(serde_wasm_bindgen::from_value(cryptographic_parameters)?)
        };
    let request: Decrypt = decrypt_request(
        key_unique_identifier,
        nonce,
        ciphertext,
        authenticated_tag,
        authentication_data,
        cryptographic_parameters,
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_decrypt_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<DecryptResponse>(response)
}

// Destroy request
#[wasm_bindgen]
pub fn destroy_ttlv_request(unique_identifier: String, remove: bool) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let request = Destroy {
        unique_identifier: Some(unique_identifier),
        remove,
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_destroy_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<DestroyResponse>(response)
}

// Encrypt request
#[wasm_bindgen]
pub fn encrypt_ttlv_request(
    key_unique_identifier: &str,
    encryption_policy: Option<String>,
    plaintext: Vec<u8>,
    header_metadata: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    authentication_data: Option<Vec<u8>>,
    cryptographic_parameters: JsValue,
) -> Result<JsValue, JsValue> {
    let cryptographic_parameters: Option<CryptographicParameters> =
        if cryptographic_parameters.is_null() || cryptographic_parameters.is_undefined() {
            None
        } else {
            Some(serde_wasm_bindgen::from_value(cryptographic_parameters)?)
        };
    let request = encrypt_request(
        key_unique_identifier,
        encryption_policy,
        plaintext,
        header_metadata,
        nonce,
        authentication_data,
        cryptographic_parameters,
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_encrypt_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<EncryptResponse>(response)
}

// Export request
#[wasm_bindgen]
pub fn export_ttlv_request(
    unique_identifier: String,
    unwrap: bool,
    key_format: Option<String>,
    wrap_key_id: Option<String>,
    wrapping_algorithm: Option<String>,
    authentication_data: Option<String>,
) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let key_format: Option<ExportKeyFormat> = key_format.and_then(|s| {
        ExportKeyFormat::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid export key format type: {e}")))
            .ok()
    });
    let key_format_type = match key_format {
        // For Raw: use the default format then do the local extraction of the bytes
        Some(ExportKeyFormat::JsonTtlv)
        | Some(ExportKeyFormat::Raw)
        | Some(ExportKeyFormat::Base64) => None,

        Some(ExportKeyFormat::Sec1Pem) => Some(KeyFormatType::ECPrivateKey),
        Some(ExportKeyFormat::Sec1Der) => Some(KeyFormatType::ECPrivateKey),

        Some(ExportKeyFormat::Pkcs1Pem) => Some(KeyFormatType::PKCS1),
        Some(ExportKeyFormat::Pkcs1Der) => Some(KeyFormatType::PKCS1),

        Some(ExportKeyFormat::Pkcs8Pem) | Some(ExportKeyFormat::SpkiPem) => {
            Some(KeyFormatType::PKCS8)
        }

        Some(ExportKeyFormat::Pkcs8Der) | Some(ExportKeyFormat::SpkiDer) => {
            Some(KeyFormatType::PKCS8)
        }

        None => None, // Default case for when key_format is None
    };
    let encode_to_ttlv = key_format == Some(ExportKeyFormat::JsonTtlv);

    let wrapping_algorithm = wrapping_algorithm.and_then(|s| {
        WrappingAlgorithm::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid wrapping algorithm: {e}")))
            .ok()
    });
    let cryptographic_parameters =
        wrapping_algorithm
            .as_ref()
            .map(|wrapping_algorithm| match wrapping_algorithm {
                WrappingAlgorithm::NistKeyWrap => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    block_cipher_mode: Some(BlockCipherMode::NISTKeyWrap),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::AesGCM => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    block_cipher_mode: Some(BlockCipherMode::GCM),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::RsaPkcsV15 => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    padding_method: Some(PaddingMethod::PKCS1v15),
                    hashing_algorithm: Some(HashingAlgorithm::SHA256),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::RsaOaep => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    padding_method: Some(PaddingMethod::OAEP),
                    hashing_algorithm: Some(HashingAlgorithm::SHA256),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::RsaAesKeyWrap => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    padding_method: Some(PaddingMethod::OAEP),
                    hashing_algorithm: Some(HashingAlgorithm::SHA256),
                    ..CryptographicParameters::default()
                },
            });

    let request = Export::new(
        unique_identifier,
        unwrap,
        wrap_key_id.map(|wrapping_key_id| KeyWrappingSpecification {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(wrapping_key_id.to_string()),
                cryptographic_parameters,
            }),
            attribute_name: authentication_data.map(|data| vec![data]),
            encoding_option: Some(if encode_to_ttlv {
                EncodingOption::TTLVEncoding
            } else {
                EncodingOption::NoEncoding
            }),
            ..KeyWrappingSpecification::default()
        }),
        key_format_type,
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_export_ttlv_response(response: &str, key_format: &str) -> Result<JsValue, JsValue> {
    // let response = parse_ttlv_response::<ExportResponse>(response)?;
    let key_format = ExportKeyFormat::from_str(&key_format)
        .map_err(|e| JsValue::from_str(&format!("Invalid export key format type: {e}")))?;
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let response: ExportResponse = from_ttlv(&ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    let data = match key_format {
        ExportKeyFormat::JsonTtlv => {
            let kmip_object = response.object;
            let mut ttlv = to_ttlv(&kmip_object).map_err(|e| JsValue::from(e.to_string()))?;
            ttlv.tag = tag_from_object(&kmip_object);
            let bytes = serde_json::to_vec::<TTLV>(&ttlv)
                .map_err(|e| JsValue::from_str(&format!("{e}")))?;
            JsValue::from(Uint8Array::from(bytes.as_slice()))
        }
        ExportKeyFormat::Base64 => {
            let key_block = response
                .object
                .key_block()
                .map_err(|e| JsValue::from_str(&format!("{e}")))?;
            let string = base64::engine::general_purpose::STANDARD
                .encode(
                    key_block
                        .key_bytes()
                        .map_err(|e| JsValue::from_str(&format!("{e}")))?,
                )
                .to_lowercase();
            JsValue::from(string)
        }
        _ => {
            let key_block = response
                .object
                .key_block()
                .map_err(|e| JsValue::from_str(&format!("{e}")))?;
            let object_type = response.object.object_type();
            let bytes = {
                let mut bytes = key_block
                    .key_bytes()
                    .map_err(|e| JsValue::from_str(&format!("{e}")))?;
                let (key_format_type, encode_to_pem) = match key_format {
                    // For Raw: use the default format then do the local extraction of the bytes
                    ExportKeyFormat::JsonTtlv | ExportKeyFormat::Raw | ExportKeyFormat::Base64 => {
                        (None, false)
                    }
                    ExportKeyFormat::Sec1Pem => (Some(KeyFormatType::ECPrivateKey), true),
                    ExportKeyFormat::Sec1Der => (Some(KeyFormatType::ECPrivateKey), false),
                    ExportKeyFormat::Pkcs1Pem => (Some(KeyFormatType::PKCS1), true),
                    ExportKeyFormat::Pkcs1Der => (Some(KeyFormatType::PKCS1), false),
                    ExportKeyFormat::Pkcs8Pem | ExportKeyFormat::SpkiPem => {
                        (Some(KeyFormatType::PKCS8), true)
                    }
                    ExportKeyFormat::Pkcs8Der | ExportKeyFormat::SpkiDer => {
                        (Some(KeyFormatType::PKCS8), false)
                    }
                };

                if encode_to_pem {
                    bytes = der_to_pem(bytes.as_slice(), key_format_type.unwrap(), object_type)
                        .map_err(|e| JsValue::from_str(&format!("{e}")))?;
                }
                bytes
            };
            JsValue::from(Uint8Array::from(bytes.as_slice()))
        }
    };
    Ok(data)
}

// Get requests
#[wasm_bindgen]
pub fn get_rsa_private_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_rsa_private_key_request(key_unique_identifier);
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn get_rsa_public_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_rsa_public_key_request(key_unique_identifier);
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn get_ec_private_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_ec_private_key_request(key_unique_identifier);
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn get_ec_public_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_ec_public_key_request(key_unique_identifier);
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

// Get attributes request
#[wasm_bindgen]
pub fn get_attributes_ttlv_request(unique_identifier: String) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let request = GetAttributes {
        unique_identifier: Some(unique_identifier),
        attribute_references: None,
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_get_attributes_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<GetAttributesResponse>(response)
}

// Import request
/// Read a key from a PEM file
// fn read_key_from_pem(bytes: &[u8]) -> CliResult<Object> {
//     let mut objects = objects_from_pem(bytes)?;
//     let object = objects
//         .pop()
//         .ok_or_else(|| CliError::Default("The PEM file does not contain any object".to_owned()))?;
//     match object.object_type() {
//         ObjectType::PrivateKey | ObjectType::PublicKey => {
//             if !objects.is_empty() {
//                 println!(
//                     "WARNING: the PEM file contains multiple objects. Only the private key will \
//                      be imported. A corresponding public key will be generated automatically."
//                 );
//             }
//             Ok(object)
//         }
//         ObjectType::Certificate => Err(CliError::Default(
//             "For certificates, use the `ckms certificate` sub-command".to_owned(),
//         )),
//         _ => Err(CliError::Default(format!(
//             "The PEM file contains an object of type {:?} which is not supported",
//             object.object_type()
//         ))),
//     }
// }

// pub(crate) fn build_private_key_from_der_bytes(
//     key_format_type: KeyFormatType,
//     bytes: Zeroizing<Vec<u8>>,
// ) -> Object {
//     Object::PrivateKey {
//         key_block: KeyBlock {
//             key_format_type,
//             key_compression_type: None,
//             key_value: KeyValue {
//                 key_material: KeyMaterial::ByteString(bytes),
//                 attributes: Some(Attributes::default()),
//             },
//             // According to the KMIP spec, the cryptographic algorithm is not required
//             // as long as it can be recovered from the Key Format Type or the Key Value.
//             // Also it should not be specified if the cryptographic length is not specified.
//             cryptographic_algorithm: None,
//             // See comment above
//             cryptographic_length: None,
//             key_wrapping_data: None,
//         },
//     }
// }

// // Here the zeroizing type on public key bytes is overkill, but it aligns with
// // other methods dealing with private components.
// fn build_public_key_from_der_bytes(
//     key_format_type: KeyFormatType,
//     bytes: Zeroizing<Vec<u8>>,
// ) -> Object {
//     Object::PublicKey {
//         key_block: KeyBlock {
//             key_format_type,
//             key_compression_type: None,
//             key_value: KeyValue {
//                 key_material: KeyMaterial::ByteString(bytes),
//                 attributes: Some(Attributes::default()),
//             },
//             // According to the KMIP spec, the cryptographic algorithm is not required
//             // as long as it can be recovered from the Key Format Type or the Key Value.
//             // Also it should not be specified if the cryptographic length is not specified.
//             cryptographic_algorithm: None,
//             // See comment above
//             cryptographic_length: None,
//             key_wrapping_data: None,
//         },
//     }
// }

// fn build_symmetric_key_from_bytes(
//     cryptographic_algorithm: CryptographicAlgorithm,
//     bytes: Zeroizing<Vec<u8>>,
// ) -> CliResult<Object> {
//     let len = i32::try_from(bytes.len())? * 8;
//     Ok(Object::SymmetricKey {
//         key_block: KeyBlock {
//             key_format_type: KeyFormatType::TransparentSymmetricKey,
//             key_compression_type: None,
//             key_value: KeyValue {
//                 key_material: KeyMaterial::TransparentSymmetricKey { key: bytes },
//                 attributes: Some(Attributes::default()),
//             },
//             cryptographic_algorithm: Some(cryptographic_algorithm),
//             cryptographic_length: Some(len),
//             key_wrapping_data: None,
//         },
//     })
// }

// pub(crate) fn build_usage_mask_from_key_usage(
//     key_usage_vec: &[KeyUsage],
// ) -> Option<CryptographicUsageMask> {
//     let mut flags = 0;
//     for key_usage in key_usage_vec {
//         flags |= match key_usage {
//             KeyUsage::Sign => CryptographicUsageMask::Sign,
//             KeyUsage::Verify => CryptographicUsageMask::Verify,
//             KeyUsage::Encrypt => CryptographicUsageMask::Encrypt,
//             KeyUsage::Decrypt => CryptographicUsageMask::Decrypt,
//             KeyUsage::WrapKey => CryptographicUsageMask::WrapKey,
//             KeyUsage::UnwrapKey => CryptographicUsageMask::UnwrapKey,
//             KeyUsage::MACGenerate => CryptographicUsageMask::MACGenerate,
//             KeyUsage::MACVerify => CryptographicUsageMask::MACVerify,
//             KeyUsage::DeriveKey => CryptographicUsageMask::DeriveKey,
//             KeyUsage::KeyAgreement => CryptographicUsageMask::KeyAgreement,
//             KeyUsage::CertificateSign => CryptographicUsageMask::CertificateSign,
//             KeyUsage::CRLSign => CryptographicUsageMask::CRLSign,
//             KeyUsage::Authenticate => CryptographicUsageMask::Authenticate,
//             KeyUsage::Unrestricted => CryptographicUsageMask::Unrestricted,
//         }
//         .bits();
//     }
//     CryptographicUsageMask::from_bits(flags)
// }

// /// Read an object from KMIP JSON TTLV bytes slice
// pub fn read_object_from_json_ttlv_bytes(bytes: &[u8]) -> Result<Object, KmsClientError> {
//     // Read the object from the file
//     let ttlv = serde_json::from_slice::<TTLV>(bytes)
//         .with_context(|| "failed parsing the object from the json file")?;
//     // Deserialize the object
//     let object: Object = from_ttlv(&ttlv)?;
//     Ok(object)
// }

// #[wasm_bindgen]
// pub fn import_ttlv_request(
//     unique_identifier: Option<String>,
//     key_file: Vec<u8>,
//     key_format: String,
//     public_key_id: Option<String>,
//     private_key_id: Option<String>,
//     certificate_id: Option<String>,
//     unwrap: bool,
//     replace_existing: bool,
//     tags: Vec<String>,
//     key_usage: Option<Vec<String>>
// ) -> Result<JsValue, JsValue> {
//     let cryptographic_usage_mask = key_usage
//         .as_deref()
//         .and_then(build_usage_mask_from_key_usage);
//     let key_file =
//     // read the key file
//     let bytes = Zeroizing::from(key_file);
//     let mut object = match &key_format {
//         ImportKeyFormat::JsonTtlv => read_object_from_json_ttlv_bytes(&bytes)?,
//         ImportKeyFormat::Pem => read_key_from_pem(&bytes)?,
//         ImportKeyFormat::Sec1 => {
//             build_private_key_from_der_bytes(KeyFormatType::ECPrivateKey, bytes)
//         }
//         ImportKeyFormat::Pkcs1Priv => {
//             build_private_key_from_der_bytes(KeyFormatType::PKCS1, bytes)
//         }
//         ImportKeyFormat::Pkcs1Pub => {
//             build_public_key_from_der_bytes(KeyFormatType::PKCS1, bytes)
//         }
//         ImportKeyFormat::Pkcs8 => build_private_key_from_der_bytes(KeyFormatType::PKCS8, bytes),
//         ImportKeyFormat::Spki => build_public_key_from_der_bytes(KeyFormatType::PKCS8, bytes),
//         ImportKeyFormat::Aes => {
//             build_symmetric_key_from_bytes(CryptographicAlgorithm::AES, bytes)?
//         }
//         ImportKeyFormat::Chacha20 => {
//             build_symmetric_key_from_bytes(CryptographicAlgorithm::ChaCha20, bytes)?
//         }
//     };
//     // Assign CryptographicUsageMask from command line arguments.
//     object
//         .attributes_mut()?
//         .set_cryptographic_usage_mask(cryptographic_usage_mask);

//     let object_type = object.object_type();

//     // Generate the import attributes if links are specified.
//     let mut import_attributes = object
//         .attributes()
//         .unwrap_or(&Attributes {
//             cryptographic_usage_mask,
//             ..Default::default()
//         })
//         .clone();

//     if let Some(issuer_certificate_id) = &certificate_id {
//         //let attributes = import_attributes.get_or_insert(Attributes::default());
//         import_attributes.set_link(
//             LinkType::CertificateLink,
//             LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
//         );
//     };
//     if let Some(private_key_id) = &private_key_id {
//         //let attributes = import_attributes.get_or_insert(Attributes::default());
//         import_attributes.set_link(
//             LinkType::PrivateKeyLink,
//             LinkedObjectIdentifier::TextString(private_key_id.clone()),
//         );
//     };
//     if let Some(public_key_id) = &public_key_id {
//         import_attributes.set_link(
//             LinkType::PublicKeyLink,
//             LinkedObjectIdentifier::TextString(public_key_id.clone()),
//         );
//     };

//     if unwrap {
//         if let Some(data) = &authenticated_additional_data {
//             // If authenticated_additional_data are provided, must be added on key attributes for unwrapping
//             let aad = data.as_bytes();
//             object.attributes_mut()?.add_aad(aad);
//         }
//     }

//     let request = import_object_request(
//         unique_identifier,
//         object,
//         Some(import_attributes),
//         unwrap,
//         replace_existing,
//         tags,
//     );
//     to_ttlv(&request)
//         .map_err(|e| JsValue::from(e.to_string()))
//         .and_then(|objects| {
//             serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
//         })
// }

#[wasm_bindgen]
pub fn parse_import_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<ImportResponse>(response)
}

// Locate request
#[wasm_bindgen]
pub fn locate_ttlv_request(
    maximum_items: Option<i32>,
    offset_items: Option<i32>,
    attributes: JsValue,
) -> Result<JsValue, JsValue> {
    let attributes = serde_wasm_bindgen::from_value(attributes)?;
    let request = Locate {
        maximum_items,
        offset_items,
        attributes,
        ..Default::default()
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_locate_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<LocateResponse>(response)
}

// Revoke request
#[wasm_bindgen]
pub fn revoke_key_ttlv_request(
    unique_identifier: &str,
    revocation_reason: JsValue,
) -> Result<JsValue, JsValue> {
    let revocation_reason = serde_wasm_bindgen::from_value(revocation_reason)?;
    let request = build_revoke_key_request(unique_identifier, revocation_reason)
        .map_err(|e| JsValue::from_str(&format!("Revocation request creation failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_revoke_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<RevokeResponse>(response)
}

// Validate request
#[wasm_bindgen]
pub fn validate_certificate_ttlv_request(
    certificate: Option<Vec<u8>>,
    unique_identifier: Option<String>,
    validity_time: Option<String>,
) -> Result<JsValue, JsValue> {
    let certificate: Option<Vec<Vec<u8>>> = certificate.map(|bytes| vec![bytes]);
    let unique_identifier = unique_identifier.map(|id| vec![UniqueIdentifier::TextString(id)]);
    let request = Validate {
        certificate,
        unique_identifier,
        validity_time,
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_validate_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<ValidateResponse>(response)
}

// // Covercrypt requests
// #[wasm_bindgen]
// pub fn create_covercrypt_master_keypair_ttlv_request(
//     policy: &str,
//     tags: Vec<String>,
//     sensitive: bool,
// ) -> Result<JsValue, JsValue> {
//     let policy = if let Some(specs_file) = &policy_specifications_file {
//         policy_from_json_file(specs_file)?
//     } else if let Some(binary_file) = &policy_binary_file {
//         policy_from_binary_file(binary_file)?
//     } else {
//         Err(JsValue::from_str(&"Invalid policy specification"))?;
//     };
//     let request = build_create_covercrypt_master_keypair_request(&policy, &tags, sensitive)
//         .map_err(|e| JsValue::from_str(&format!("Covercrypt master keypair creation failed: {e}")))?;
//     to_ttlv(&request)
//         .map_err(|e| JsValue::from(e.to_string()))
//         .and_then(|objects| {
//             serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
//         })
// }
