use std::str::FromStr;

use wasm_bindgen::prelude::*;

use crate::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_operations::{
        Certify, Create, CreateKeyPair, Decrypt, Destroy, Export, GetAttributes, Locate, Validate,
    },
    kmip_types::{
        CertificateRequestType, CryptographicAlgorithm, CryptographicParameters,
        KeyCompressionType, KeyFormatType, KeyWrapType, RecommendedCurve, UniqueIdentifier,
    },
    requests::{
        build_import_object_request, build_revoke_key_request, create_ec_key_pair_request,
        create_rsa_key_pair_request, decrypt_request, encrypt_request, get_ec_private_key_request,
        get_ec_public_key_request, get_rsa_private_key_request, get_rsa_public_key_request,
        symmetric_key_create_request,
    },
    ttlv::serializer::to_ttlv,
};

// Certify request
#[wasm_bindgen]
pub fn certify_ttlv_request(
    unique_identifier: Option<String>,
    certificate_request_type: Option<String>,
    certificate_request_value: Option<Vec<u8>>,
    attributes: JsValue,
) -> Result<JsValue, JsValue> {
    let unique_identifier = unique_identifier.map(UniqueIdentifier::TextString);
    let certificate_request_type =
        certificate_request_type.map(|s| CertificateRequestType::from_str(&s).unwrap());
    let attributes = serde_wasm_bindgen::from_value(attributes).unwrap();
    let request = Certify {
        unique_identifier,
        attributes: Some(attributes),
        certificate_request_value,
        certificate_request_type,
        ..Certify::default()
    };
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
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
        create_rsa_key_pair_request(private_key_id, tags, cryptographic_length, sensitive).unwrap();
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn create_ec_key_pair_ttlv_request(
    private_key_id: Option<String>,
    tags: Vec<String>,
    recommended_curve: String,
    sensitive: bool,
) -> Result<JsValue, JsValue> {
    let private_key_id = private_key_id.map(UniqueIdentifier::TextString);
    let curve = RecommendedCurve::from_str(&recommended_curve).unwrap();
    let request: CreateKeyPair =
        create_ec_key_pair_request(private_key_id, tags, curve, sensitive).unwrap();
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Create request
#[wasm_bindgen]
pub fn create_sym_key_ttlv_request(
    key_id: Option<String>,
    tags: Vec<String>,
    key_len_in_bits: usize,
    cryptographic_algorithm: String,
    sensitive: bool,
    wrap_key_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let key_id = key_id.map(UniqueIdentifier::TextString);
    let algorithm = CryptographicAlgorithm::from_str(&cryptographic_algorithm).unwrap();
    let request: Create = symmetric_key_create_request(
        key_id,
        key_len_in_bits,
        algorithm,
        tags,
        sensitive,
        wrap_key_id.as_ref(),
    )
    .unwrap();
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Decrypt request
#[wasm_bindgen]
pub fn decrypt_ttlv_request(
    key_unique_identifier: String,
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
            Some(serde_wasm_bindgen::from_value(cryptographic_parameters).unwrap())
        };
    let request: Decrypt = decrypt_request(
        &key_unique_identifier,
        nonce,
        ciphertext,
        authenticated_tag,
        authentication_data,
        cryptographic_parameters,
    );
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Destroy request
#[wasm_bindgen]
pub fn destroy_ttlv_request(unique_identifier: String, remove: bool) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let request = Destroy {
        unique_identifier: Some(unique_identifier),
        remove,
    };
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Encrypt request
#[wasm_bindgen]
pub fn encrypt_ttlv_request(
    key_unique_identifier: String,
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
            Some(serde_wasm_bindgen::from_value(cryptographic_parameters).unwrap())
        };
    let request = encrypt_request(
        &key_unique_identifier,
        encryption_policy,
        plaintext,
        header_metadata,
        nonce,
        authentication_data,
        cryptographic_parameters,
    )
    .unwrap();
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Export request
#[wasm_bindgen]
pub fn export_ttlv_request(
    unique_identifier: Option<String>,
    key_format_type: Option<String>,
    key_wrap_type: Option<String>,
    key_compression_type: Option<String>,
    key_wrapping_specification: JsValue,
) -> Result<JsValue, JsValue> {
    let unique_identifier = unique_identifier.map(UniqueIdentifier::TextString);
    let key_format_type = key_format_type.map(|s| KeyFormatType::from_str(&s).unwrap());
    let key_wrap_type = key_wrap_type.map(|s| KeyWrapType::from_str(&s).unwrap());
    let key_compression_type =
        key_compression_type.map(|s| KeyCompressionType::from_str(&s).unwrap());
    let key_wrapping_specification =
        if key_wrapping_specification.is_null() || key_wrapping_specification.is_undefined() {
            None
        } else {
            Some(serde_wasm_bindgen::from_value(key_wrapping_specification).unwrap())
        };
    let request = Export {
        unique_identifier,
        key_format_type,
        key_wrap_type,
        key_compression_type,
        key_wrapping_specification,
    };
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Get requests
#[wasm_bindgen]
pub fn get_rsa_private_key_ttlv_request(key_unique_identifier: String) -> Result<JsValue, JsValue> {
    let request = get_rsa_private_key_request(&key_unique_identifier);
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn get_rsa_public_key_ttlv_request(key_unique_identifier: String) -> Result<JsValue, JsValue> {
    let request = get_rsa_public_key_request(&key_unique_identifier);
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn get_ec_private_key_ttlv_request(key_unique_identifier: String) -> Result<JsValue, JsValue> {
    let request = get_ec_private_key_request(&key_unique_identifier);
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn get_ec_public_key_ttlv_request(key_unique_identifier: String) -> Result<JsValue, JsValue> {
    let request = get_ec_public_key_request(&key_unique_identifier);
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Get attributes request
#[wasm_bindgen]
pub fn get_attributes_ttlv_request(unique_identifier: String) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let request = GetAttributes {
        unique_identifier: Some(unique_identifier),
        attribute_references: None,
    };
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Import request
#[wasm_bindgen]
pub fn import_ttlv_request(
    object: JsValue,
    object_type: String,
    attributes: JsValue,
    unique_identifier: String,
    replace_existing: Option<bool>,
) -> Result<JsValue, JsValue> {
    let object = serde_wasm_bindgen::from_value(object).unwrap();
    let object_type = ObjectType::try_from(object_type.as_ref()).unwrap();
    let attributes = serde_wasm_bindgen::from_value(attributes).unwrap();
    let request = build_import_object_request(
        object,
        object_type,
        attributes,
        &unique_identifier,
        replace_existing,
    );
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Locate request
#[wasm_bindgen]
pub fn locate_ttlv_request(
    maximum_items: Option<i32>,
    offset_items: Option<i32>,
    attributes: JsValue,
) -> Result<JsValue, JsValue> {
    let attributes = serde_wasm_bindgen::from_value(attributes).unwrap();
    let request = Locate {
        maximum_items,
        offset_items,
        attributes,
        ..Default::default()
    };
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}

// Revoke request
#[wasm_bindgen]
pub fn revoke_key_ttlv_request(
    unique_identifier: String,
    revocation_reason: JsValue,
) -> Result<JsValue, JsValue> {
    let revocation_reason = serde_wasm_bindgen::from_value(revocation_reason).unwrap();
    let request = build_revoke_key_request(&unique_identifier, revocation_reason).unwrap();
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
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
    let result = to_ttlv(&request);
    result
        .map(|objects| serde_wasm_bindgen::to_value(&objects).unwrap())
        .map_err(|e| JsValue::from(e.to_string()))
}
