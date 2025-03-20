use std::str::FromStr;

use base64::Engine as _;
use cloudproof::reexport::cover_crypt::{
    self,
    abe_policy::{AccessPolicy, Policy},
};
use cosmian_kmip::kmip_2_1::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{
        CertifyResponse, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Decrypt,
        DecryptResponse, DeleteAttribute, DeleteAttributeResponse, Destroy, DestroyResponse,
        EncryptResponse, ExportResponse, GetAttributes, GetAttributesResponse, ImportResponse,
        LocateResponse, RevokeResponse, SetAttribute, SetAttributeResponse, Validate,
        ValidateResponse,
    },
    kmip_types::{
        AttributeReference, CertificateType, CryptographicAlgorithm, CryptographicParameters,
        KeyFormatType, LinkType, LinkedObjectIdentifier, RecommendedCurve, Tag, UniqueIdentifier,
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
use x509_cert::{
    der::{Decode, DecodePem, Encode},
    Certificate,
};
use zeroize::Zeroizing;

use crate::{
    attributes_utils::{build_selected_attribute, parse_selected_attributes, CLinkType},
    certificate_utils::{build_certify_request, Algorithm},
    cover_crypt_utils::{
        build_create_covercrypt_master_keypair_request,
        build_create_covercrypt_user_decryption_key_request,
    },
    create_utils::{prepare_sym_key_elements, Curve, SymmetricAlgorithm},
    error::UtilsError,
    export_utils::{
        der_to_pem, export_request, get_export_key_format_type,
        prepare_certificate_export_elements, prepare_key_export_elements, tag_from_object,
        CertificateExportFormat, ExportKeyFormat, WrappingAlgorithm,
    },
    import_utils::{
        build_private_key_from_der_bytes, build_usage_mask_from_key_usage,
        prepare_certificate_attributes, prepare_key_import_elements,
        read_object_from_json_ttlv_bytes, CertificateInputFormat, ImportKeyFormat, KeyUsage,
    },
    locate_utils::build_locate_request,
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

// Locate request
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn locate_ttlv_request(
    tags: Option<Vec<String>>,
    cryptographic_algorithm: Option<String>,
    cryptographic_length: Option<usize>,
    key_format_type: Option<String>,
    object_type: Option<String>,
    public_key_id: Option<String>,
    private_key_id: Option<String>,
    certificate_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let cryptographic_algorithm: Option<CryptographicAlgorithm> = cryptographic_algorithm
        .as_deref()
        .map(|s| CryptographicAlgorithm::from_str(s).map_err(|e| JsValue::from(e.to_string())))
        .transpose()?;

    let cryptographic_length = cryptographic_length
        .map(|x| i32::try_from(x).map_err(|e| JsValue::from(e.to_string())))
        .transpose()?;

    let key_format_type: Option<KeyFormatType> = key_format_type
        .as_deref()
        .map(|s| KeyFormatType::from_str(s).map_err(|e| JsValue::from(e.to_string())))
        .transpose()?;

    let object_type: Option<ObjectType> = object_type
        .as_deref()
        .map(|s| ObjectType::try_from(s).map_err(|e| JsValue::from(e.to_string())))
        .transpose()?;

    let request = build_locate_request(
        tags,
        cryptographic_algorithm,
        cryptographic_length,
        key_format_type,
        object_type,
        public_key_id.as_deref(),
        private_key_id.as_deref(),
        certificate_id.as_deref(),
    )
    .map_err(|e| JsValue::from(e.to_string()))?;
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

// Create keys Requests
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

// Decrypt requests
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

// Encrypt requests
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
            .filter_map(|s| s.parse::<KeyUsage>().ok())
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

// Revoke request
#[wasm_bindgen]
pub fn revoke_ttlv_request(
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

use std::collections::HashMap;

// Covercrypt requests
#[wasm_bindgen]
pub fn create_cc_master_keypair_ttlv_request(
    policy: &[u8],
    tags: Vec<String>,
    sensitive: bool,
) -> Result<JsValue, JsValue> {
    let policy_specs: HashMap<String, Vec<String>> =
        serde_json::from_slice(policy).map_err(|e| JsValue::from(e.to_string()))?;
    let policy: Policy = policy_specs
        .try_into()
        .map_err(|e: cover_crypt::Error| JsValue::from(e.to_string()))?;
    // let policy = Policy::parse_and_convert(policy.as_slice()).map_err(|e| JsValue::from(e.to_string()))?; // for bianary
    let request = build_create_covercrypt_master_keypair_request(&policy, tags, sensitive)
        .map_err(|e| {
            JsValue::from_str(&format!("Covercrypt master keypair creation failed: {e}"))
        })?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn create_cc_user_key_ttlv_request(
    master_private_key_id: &str,
    access_policy: &str,
    tags: Vec<String>,
    sensitive: bool,
) -> Result<JsValue, JsValue> {
    AccessPolicy::from_boolean_expression(access_policy)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let request = build_create_covercrypt_user_decryption_key_request(
        access_policy,
        master_private_key_id,
        tags,
        sensitive,
    )
    .map_err(|e| JsValue::from_str(&format!("Covercrypt user key creation failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn encrypt_cc_ttlv_request(
    key_unique_identifier: &str,
    encryption_policy: String,
    plaintext: Vec<u8>,
    authentication_data: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let request = encrypt_request(
        key_unique_identifier,
        Some(encryption_policy),
        plaintext,
        None,
        None,
        authentication_data,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn decrypt_cc_ttlv_request(
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
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

// Certificate requests
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn import_certificate_ttlv_request(
    certificate_id: Option<String>,
    certificate_bytes: Vec<u8>,
    input_format: &str,
    private_key_id: Option<String>,
    public_key_id: Option<String>,
    issuer_certificate_id: Option<String>,
    pkcs12_password: Option<String>,
    replace_existing: bool,
    tags: Vec<String>,
    key_usage: Option<Vec<String>>,
) -> Result<JsValue, JsValue> {
    let input_format =
        CertificateInputFormat::from_str(input_format).map_err(|e| JsValue::from(e.to_string()))?;
    let key_usage: Option<Vec<KeyUsage>> = key_usage.map(|vec| {
        vec.into_iter()
            .filter_map(|s| s.parse::<KeyUsage>().ok()) // Parse and filter out errors
            .collect()
    });
    let attributes =
        prepare_certificate_attributes(&issuer_certificate_id, &private_key_id, &public_key_id);
    let request = match input_format {
        CertificateInputFormat::JsonTtlv => {
            let object: Object = read_object_from_json_ttlv_bytes(&certificate_bytes)
                .map_err(|e| JsValue::from(e.to_string()))?;
            import_object_request(
                certificate_id,
                object,
                attributes,
                false,
                replace_existing,
                tags,
            )
        }
        CertificateInputFormat::Pem => {
            let certificate = Certificate::from_pem(&certificate_bytes)
                .map_err(|e| JsValue::from(e.to_string()))?;
            let object = Object::Certificate {
                certificate_type: CertificateType::X509,
                certificate_value: certificate
                    .to_der()
                    .map_err(|e| JsValue::from(e.to_string()))?,
            };
            import_object_request(
                certificate_id,
                object,
                attributes,
                false,
                replace_existing,
                tags,
            )
        }
        CertificateInputFormat::Der => {
            let certificate = Certificate::from_der(&certificate_bytes)
                .map_err(|e| JsValue::from(e.to_string()))?;
            let object = Object::Certificate {
                certificate_type: CertificateType::X509,
                certificate_value: certificate
                    .to_der()
                    .map_err(|e| JsValue::from(e.to_string()))?,
            };
            import_object_request(
                certificate_id,
                object,
                attributes,
                false,
                replace_existing,
                tags,
            )
        }
        CertificateInputFormat::Pkcs12 => {
            let cryptographic_usage_mask = key_usage
                .as_deref()
                .and_then(build_usage_mask_from_key_usage);
            let pkcs12_bytes = Zeroizing::from(certificate_bytes);
            let private_key = build_private_key_from_der_bytes(KeyFormatType::PKCS12, pkcs12_bytes);
            let mut attributes = private_key.attributes().cloned().unwrap_or_default();
            attributes.set_cryptographic_usage_mask(cryptographic_usage_mask);
            if let Some(password) = &pkcs12_password {
                attributes.set_link(
                    LinkType::PKCS12PasswordLink,
                    LinkedObjectIdentifier::TextString(password.clone()),
                );
            }
            import_object_request(
                certificate_id,
                private_key,
                Some(attributes),
                false,
                replace_existing,
                &tags,
            )
        }
        CertificateInputFormat::Chain => Err(UtilsError::Default(
            "Chain import not supported from the UI.".to_owned(),
        ))
        .map_err(|e| JsValue::from(e.to_string()))?,
        CertificateInputFormat::CCADB => Err(UtilsError::Default(
            "CCADB import not supported from the UI.".to_owned(),
        ))
        .map_err(|e| JsValue::from(e.to_string()))?,
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn export_certificate_ttlv_request(
    unique_identifier: &str,
    output_format: &str,
    pkcs12_password: Option<String>,
) -> Result<JsValue, JsValue> {
    let output_format = CertificateExportFormat::from_str(output_format)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let (key_format_type, wrapping_key_id) =
        prepare_certificate_export_elements(&output_format, pkcs12_password);
    let request = export_request(
        unique_identifier,
        false,
        wrapping_key_id.as_deref(),
        Some(key_format_type),
        false,
        None,
        None,
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_export_certificate_ttlv_response(
    response: &str,
    output_format: &str,
) -> Result<JsValue, JsValue> {
    // let response = parse_ttlv_response::<ExportResponse>(response)?;
    let output_format = CertificateExportFormat::from_str(output_format)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let response: ExportResponse = from_ttlv(&ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    let object = Object::post_fix(response.object_type, response.object);
    let object_type = response.object_type;
    match &object {
        Object::Certificate {
            certificate_value, ..
        } => {
            let data = match output_format {
                CertificateExportFormat::JsonTtlv => {
                    let mut ttlv = to_ttlv(&object).map_err(|e| JsValue::from(e.to_string()))?;
                    ttlv.tag = tag_from_object(&object);
                    let bytes = serde_json::to_vec::<TTLV>(&ttlv)
                        .map_err(|e| JsValue::from_str(&format!("{e}")))?;
                    JsValue::from(Uint8Array::from(bytes.as_slice()))
                }
                CertificateExportFormat::Pem => {
                    // save the pem to a file
                    let pem = pem::Pem::new("CERTIFICATE", certificate_value.as_slice());
                    JsValue::from(Uint8Array::from(pem.to_string().as_bytes()))
                }
                CertificateExportFormat::Pkcs12 => {
                    // PKCS12 is exported as a private key object
                    Err(UtilsError::Default(
                        "PKCS12: invalid object returned by the server.".to_owned(),
                    ))
                    .map_err(|e| JsValue::from(e.to_string()))?
                }
                #[cfg(not(feature = "fips"))]
                CertificateExportFormat::Pkcs12Legacy => {
                    // PKCS12 is exported as a private key object
                    Err(UtilsError::Default(
                        "PKCS12: invalid object returned by the server.".to_owned(),
                    ))
                    .map_err(|e| JsValue::from(e.to_string()))?
                }
                CertificateExportFormat::Pkcs7 => {
                    // save the pem to a file
                    let pem = pem::Pem::new(String::from("PKCS7"), certificate_value.as_slice());
                    JsValue::from(Uint8Array::from(pem.to_string().as_bytes()))
                }
            };
            Ok(data)
        }
        // PKCS12 is exported as a private key object
        Object::PrivateKey { key_block } => {
            let p12_bytes = key_block
                .key_bytes()
                .map_err(|e| JsValue::from(e.to_string()))?
                .to_vec();
            Ok(JsValue::from(Uint8Array::from(p12_bytes.as_slice())))
        }
        _ => Err(UtilsError::Default(format!(
            "The object is not a certificate but a {object_type}"
        )))
        .map_err(|e| JsValue::from(e.to_string()))?,
    }
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

#[wasm_bindgen]
pub fn encrypt_certificate_ttlv_request(
    unique_identifier: &str,
    plaintext: Vec<u8>,
    authentication_data: Option<Vec<u8>>,
    encryption_algorithm: &str,
) -> Result<JsValue, JsValue> {
    let encryption_algorithm: RsaEncryptionAlgorithm =
        RsaEncryptionAlgorithm::from_str(encryption_algorithm)
            .map_err(|e| JsValue::from(e.to_string()))?;
    let cryptographic_parameters = encryption_algorithm.to_cryptographic_parameters(HashFn::Sha256);
    let request = encrypt_request(
        unique_identifier,
        None,
        plaintext,
        None,
        None,
        authentication_data,
        Some(cryptographic_parameters),
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn decrypt_certificate_ttlv_request(
    unique_identifier: &str,
    ciphertext: Vec<u8>,
    authentication_data: Option<Vec<u8>>,
    encryption_algorithm: &str,
) -> Result<JsValue, JsValue> {
    let encryption_algorithm: RsaEncryptionAlgorithm =
        RsaEncryptionAlgorithm::from_str(encryption_algorithm)
            .map_err(|e| JsValue::from(e.to_string()))?;
    let cryptographic_parameters = encryption_algorithm.to_cryptographic_parameters(HashFn::Sha256);
    let request = decrypt_request(
        unique_identifier,
        None,
        ciphertext,
        None,
        authentication_data,
        Some(cryptographic_parameters),
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

// Certify request
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn certify_ttlv_request(
    certificate_id: Option<String>,
    certificate_signing_request_format: Option<String>,
    certificate_signing_request: Option<Vec<u8>>,
    public_key_id_to_certify: Option<String>,
    certificate_id_to_re_certify: Option<String>,
    generate_key_pair: bool,
    subject_name: Option<String>,
    algorithm: Option<String>,
    issuer_private_key_id: Option<String>,
    issuer_certificate_id: Option<String>,
    number_of_days: usize,
    certificate_extensions: Option<Vec<u8>>,
    tags: Vec<String>,
) -> Result<JsValue, JsValue> {
    let algorithm = Algorithm::from_str(&algorithm.unwrap_or_else(|| "rsa4096".to_owned()))
        .map_err(|e| JsValue::from(e.to_string()))?;
    let request = build_certify_request(
        &certificate_id,
        &certificate_signing_request_format,
        &certificate_signing_request,
        &public_key_id_to_certify,
        &certificate_id_to_re_certify,
        generate_key_pair,
        &subject_name,
        algorithm,
        &issuer_private_key_id,
        &issuer_certificate_id,
        number_of_days,
        &certificate_extensions,
        &tags,
    )
    .map_err(|e| JsValue::from(e.to_string()))?;
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

// Attributes request
#[wasm_bindgen]
pub fn get_attributes_ttlv_request(
    unique_identifier: String,
    attribute_tags: Vec<String>,
) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let attribute_tags: Result<Vec<Tag>, JsValue> = attribute_tags
        .into_iter()
        .map(|tag| Tag::from_str(&tag).map_err(|e| JsValue::from(e.to_string())))
        .collect();

    let attribute_tags = attribute_tags?;
    let mut references: Vec<AttributeReference> = Vec::with_capacity(attribute_tags.len());
    for tag in &attribute_tags {
        references.push(AttributeReference::Standard(*tag));
    }
    let request = GetAttributes {
        unique_identifier: Some(unique_identifier),
        attribute_references: Some(references),
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_get_attributes_ttlv_response(
    response: &str,
    attribute_tags: Vec<String>,
    attribute_link_types: Vec<String>,
) -> Result<JsValue, JsValue> {
    let attribute_tags: Result<Vec<Tag>, JsValue> = attribute_tags
        .into_iter()
        .map(|tag| Tag::from_str(&tag).map_err(|e| JsValue::from(e.to_string())))
        .collect();
    let attribute_tags = attribute_tags?;
    let attribute_link_types: Result<Vec<CLinkType>, JsValue> = attribute_link_types
        .into_iter()
        .map(|tag| CLinkType::from_str(&tag).map_err(|e| JsValue::from(e.to_string())))
        .collect();
    let attribute_link_types = attribute_link_types?;
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let GetAttributesResponse {
        unique_identifier: _,
        attributes,
    } = from_ttlv(&ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    let results = parse_selected_attributes(&attributes, &attribute_tags, &attribute_link_types)
        .map_err(|e| JsValue::from(e.to_string()))?;
    Ok(serde_wasm_bindgen::to_value(&results)?)
}

#[wasm_bindgen]
pub fn set_attribute_ttlv_request(
    unique_identifier: String,
    attribute_name: &str,
    attribute_value: String,
) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let attribute = build_selected_attribute(attribute_name, attribute_value)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let request = SetAttribute {
        unique_identifier: Some(unique_identifier),
        new_attribute: attribute,
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_set_attribute_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<SetAttributeResponse>(response)
}

#[wasm_bindgen]
pub fn delete_attribute_ttlv_request(
    unique_identifier: String,
    attribute_name: &str,
) -> Result<JsValue, JsValue> {
    // use web_sys::console;
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    // console::log_1(&"two".into());
    let request = match attribute_name {
        "public_key_id"
        | "private_key_id"
        | "certificate_id"
        | "pkcs12_certificate_id"
        | "pkcs12_password_certificate"
        | "parent_id"
        | "child_id" => {
            let attribute = build_selected_attribute(attribute_name, String::new())
                .map_err(|e| JsValue::from(e.to_string()))?;
            DeleteAttribute {
                unique_identifier: Some(unique_identifier),
                current_attribute: Some(attribute),
                attribute_references: None,
            }
        }
        _ => {
            let attribute_tag =
                Tag::from_str(attribute_name).map_err(|e| JsValue::from(e.to_string()))?;
            let attribute_reference = AttributeReference::Standard(attribute_tag);
            let references = vec![attribute_reference];
            DeleteAttribute {
                unique_identifier: Some(unique_identifier),
                current_attribute: None,
                attribute_references: Some(references),
            }
        }
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_delete_attribute_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<DeleteAttributeResponse>(response)
}
