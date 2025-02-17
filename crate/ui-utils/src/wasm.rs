use std::str::FromStr;

use base64::Engine as _;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_operations::{
        Certify, CertifyResponse, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Decrypt,
        DecryptResponse, Destroy, DestroyResponse, EncryptResponse, ExportResponse, GetAttributes,
        GetAttributesResponse, ImportResponse, Locate, LocateResponse, RevokeResponse, Validate,
        ValidateResponse,
    },
    kmip_types::{
        CertificateRequestType, CryptographicParameters, RecommendedCurve, UniqueIdentifier,
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
    error::UtilsError,
    export_utils::{
        der_to_pem, export_request, get_export_key_format_type, prepare_key_export_elements,
        tag_from_object, ExportKeyFormat, WrappingAlgorithm,
    },
    import_utils::{prepare_key_import_elements, ImportKeyFormat, KeyUsage},
    rsa_utils::{HashFn, RsaEncryptionAlgorithm},
    symmetric_utils::{parse_decrypt_elements, DataEncryptionAlgorithm},
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
pub fn decrypt_sym_ttlv_request(
    key_unique_identifier: &str,
    ciphertext: Vec<u8>,
    authentication_data: Option<Vec<u8>>,
    data_encryption_algorithm: JsValue,
) -> Result<JsValue, JsValue> {
    let cryptographic_parameters: CryptographicParameters =
        serde_wasm_bindgen::from_value::<DataEncryptionAlgorithm>(data_encryption_algorithm)?
            .into();
    let (ciphertext, nonce, tag) = parse_decrypt_elements(&cryptographic_parameters, ciphertext)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let request: Decrypt = decrypt_request(
        key_unique_identifier,
        Some(nonce),
        ciphertext,
        Some(tag),
        authentication_data,
        Some(cryptographic_parameters),
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn decrypt_rsa_ttlv_request(
    key_unique_identifier: &str,
    ciphertext: Vec<u8>,
    encryption_algorithm: JsValue,
    hash_fn: JsValue,
) -> Result<JsValue, JsValue> {
    let encryption_algorithm =
        serde_wasm_bindgen::from_value::<RsaEncryptionAlgorithm>(encryption_algorithm)?;
    let hash_fn = serde_wasm_bindgen::from_value::<HashFn>(hash_fn)?;
    let request = decrypt_request(
        key_unique_identifier,
        None,
        ciphertext,
        None,
        None,
        Some(encryption_algorithm.to_cryptographic_parameters(hash_fn)),
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn decrypt_ec_ttlv_request(
    key_unique_identifier: &str,
    ciphertext: Vec<u8>,
    authentication_data: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let request = decrypt_request(
        key_unique_identifier,
        None,
        ciphertext,
        None,
        authentication_data,
        None,
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
pub fn encrypt_sym_ttlv_request(
    key_unique_identifier: &str,
    encryption_policy: Option<String>,
    plaintext: Vec<u8>,
    header_metadata: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    authentication_data: Option<Vec<u8>>,
    data_encryption_algorithm: JsValue,
) -> Result<JsValue, JsValue> {
    let cryptographic_parameters: Option<CryptographicParameters> = if data_encryption_algorithm
        .is_null()
        || data_encryption_algorithm.is_undefined()
    {
        None
    } else {
        Some(
            serde_wasm_bindgen::from_value::<DataEncryptionAlgorithm>(data_encryption_algorithm)?
                .into(),
        )
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
pub fn encrypt_rsa_ttlv_request(
    key_unique_identifier: &str,
    plaintext: Vec<u8>,
    encryption_algorithm: JsValue,
    hash_fn: JsValue,
) -> Result<JsValue, JsValue> {
    let encryption_algorithm =
        serde_wasm_bindgen::from_value::<RsaEncryptionAlgorithm>(encryption_algorithm)?;
    let hash_fn = serde_wasm_bindgen::from_value::<HashFn>(hash_fn)?;
    let request = encrypt_request(
        key_unique_identifier,
        None,
        plaintext,
        None,
        None,
        None,
        Some(encryption_algorithm.to_cryptographic_parameters(hash_fn)),
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn encrypt_ec_ttlv_request(
    key_unique_identifier: &str,
    plaintext: Vec<u8>,
    authentication_data: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let request = encrypt_request(
        key_unique_identifier,
        None,
        plaintext,
        None,
        None,
        authentication_data,
        None,
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
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn export_ttlv_request(
    unique_identifier: &str,
    unwrap: bool,
    key_format: &str,
    wrap_key_id: Option<String>,
    wrapping_algorithm: Option<String>,
    authentication_data: Option<String>,
) -> Result<JsValue, JsValue> {
    let key_format = ExportKeyFormat::from_str(key_format)
        .map_err(|e| JsValue::from_str(&format!("Invalid key format: {e}")))?;
    let wrapping_algorithm = wrapping_algorithm.and_then(|s| {
        WrappingAlgorithm::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid wrapping algorithm: {e}")))
            .ok()
    });
    let (key_format_type, _encode_to_pem, encode_to_ttlv, wrapping_cryptographic_parameters) =
        prepare_key_export_elements(&key_format, &wrapping_algorithm)
            .map_err(|e| JsValue::from_str(&format!("Error preparing export elements: {e}")))?;
    let request = export_request(
        unique_identifier,
        unwrap,
        wrap_key_id.as_deref(),
        key_format_type,
        encode_to_ttlv,
        wrapping_cryptographic_parameters,
        authentication_data,
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
    let key_format = ExportKeyFormat::from_str(key_format)
        .map_err(|e| JsValue::from_str(&format!("Invalid export key format type: {e}")))?;
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let response: ExportResponse = from_ttlv(&ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    let data = match key_format {
        ExportKeyFormat::JsonTtlv => {
            let kmip_object = Object::post_fix(response.object_type, response.object);
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
                let (key_format_type, encode_to_pem) = get_export_key_format_type(&key_format);

                if encode_to_pem {
                    let format_type = key_format_type
                        .ok_or_else(|| {
                            UtilsError::Default(
                                "Server Error: the Key Format Type should be known at this stage"
                                    .to_owned(),
                            )
                        })
                        .map_err(|e| JsValue::from_str(&e.to_string()))?;
                    bytes = der_to_pem(bytes.as_slice(), format_type, object_type)
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
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn import_ttlv_request(
    unique_identifier: Option<String>,
    key_bytes: Vec<u8>,
    key_format: &str,
    public_key_id: Option<String>,
    private_key_id: Option<String>,
    certificate_id: Option<String>,
    unwrap: bool,
    replace_existing: bool,
    tags: Vec<String>,
    key_usage: Option<Vec<String>>,
    authenticated_additional_data: Option<String>,
) -> Result<JsValue, JsValue> {
    let key_usage = key_usage.map(|vec| {
        vec.into_iter()
            .filter_map(|s| s.parse::<KeyUsage>().ok()) // Parse and filter out errors
            .collect()
    });
    let key_format =
        ImportKeyFormat::from_str(key_format).map_err(|e| JsValue::from(e.to_string()))?;

    let (object, import_attributes) = prepare_key_import_elements(
        &key_usage,
        &key_format,
        key_bytes,
        &certificate_id,
        &private_key_id,
        &public_key_id,
        unwrap,
        &authenticated_additional_data,
    )
    .map_err(|e| JsValue::from(e.to_string()))?;
    let request = import_object_request(
        unique_identifier,
        object,
        Some(import_attributes),
        unwrap,
        replace_existing,
        tags,
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

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
