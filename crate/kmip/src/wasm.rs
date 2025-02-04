use std::str::FromStr;

use base64::{engine::general_purpose, Engine as _};
use serde::{de::DeserializeOwned, Serialize};
use strum::EnumString;
use wasm_bindgen::prelude::*;

use crate::kmip_2_1::{
    kmip_operations::{
        Certify, CertifyResponse, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Decrypt,
        DecryptResponse, Destroy, DestroyResponse, EncryptResponse, Export, ExportResponse,
        GetAttributes, GetAttributesResponse, ImportResponse, Locate, LocateResponse,
        RevokeResponse, Validate, ValidateResponse,
    },
    kmip_types::{
        CertificateRequestType, CryptographicAlgorithm, CryptographicParameters,
        KeyCompressionType, KeyFormatType, KeyWrapType, RecommendedCurve, UniqueIdentifier,
    },
    requests::{
        build_revoke_key_request, create_ec_key_pair_request, create_rsa_key_pair_request,
        create_symmetric_key_kmip_object, decrypt_request, encrypt_request,
        get_ec_private_key_request, get_ec_public_key_request, get_rsa_private_key_request,
        get_rsa_public_key_request, import_object_request, symmetric_key_create_request,
    },
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
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
    let recommended_curve = RecommendedCurve::from_str(recommended_curve)
        .map_err(|e| JsValue::from_str(&format!("Invalid recommended curve: {e}")))?;
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
#[derive(Debug, Clone, Copy, Default, EnumString)]
pub enum SymmetricAlgorithm {
    #[cfg(not(feature = "fips"))]
    Chacha20,
    #[default]
    Aes,
    Sha3,
    Shake,
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
    let mut key_bytes = None;
    let number_of_bits = if let Some(key_b64) = &wrap_key_b64 {
        let bytes = general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| JsValue::from_str(&format!("Error decoding bytes: {e}")))?;
        let number_of_bits = bytes.len() * 8;
        key_bytes = Some(bytes);
        number_of_bits
    } else {
        number_of_bits.unwrap_or(256)
    };
    let sym_algorithm: SymmetricAlgorithm = SymmetricAlgorithm::from_str(symmetric_algorithm)
        .map_err(|e| JsValue::from_str(&format!("Invalid cryptographic algorithm: {e}")))?;
    let algorithm = match sym_algorithm {
        SymmetricAlgorithm::Aes => CryptographicAlgorithm::AES,
        #[cfg(not(feature = "fips"))]
        SymmetricAlgorithm::Chacha20 => CryptographicAlgorithm::ChaCha20,
        SymmetricAlgorithm::Sha3 => match number_of_bits {
            224 => CryptographicAlgorithm::SHA3224,
            256 => CryptographicAlgorithm::SHA3256,
            384 => CryptographicAlgorithm::SHA3384,
            512 => CryptographicAlgorithm::SHA3512,
            _ => Err(JsValue::from_str(&format!(
                "Invalid cryptographic key length: {number_of_bits}")))?,
        },
        SymmetricAlgorithm::Shake => match number_of_bits {
            128 => CryptographicAlgorithm::SHAKE128,
            256 => CryptographicAlgorithm::SHAKE256,
            _ => Err(JsValue::from_str(&format!(
                "Invalid cryptographic key length: {number_of_bits}"
            )))?,
        },
    };

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
    unique_identifier: Option<String>,
    key_format_type: Option<String>,
    key_wrap_type: Option<String>,
    key_compression_type: Option<String>,
    key_wrapping_specification: JsValue,
) -> Result<JsValue, JsValue> {
    let unique_identifier = unique_identifier.map(UniqueIdentifier::TextString);
    let key_format_type = key_format_type.and_then(|s| {
        KeyFormatType::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid certificate type: {e}")))
            .ok()
    });
    let key_wrap_type = key_wrap_type.and_then(|s| {
        KeyWrapType::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid certificate type: {e}")))
            .ok()
    });
    let key_compression_type = key_compression_type.and_then(|s| {
        KeyCompressionType::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid certificate type: {e}")))
            .ok()
    });
    let key_wrapping_specification =
        if key_wrapping_specification.is_null() || key_wrapping_specification.is_undefined() {
            None
        } else {
            Some(serde_wasm_bindgen::from_value(key_wrapping_specification)?)
        };
    let request = Export {
        unique_identifier,
        key_format_type,
        key_wrap_type,
        key_compression_type,
        key_wrapping_specification,
    };
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[wasm_bindgen]
pub fn parse_export_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<ExportResponse>(response)
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
#[wasm_bindgen]
pub fn import_ttlv_request(
    unique_identifier: Option<String>,
    object: JsValue,
    attributes: JsValue,
    unwrap: bool,
    replace_existing: bool,
    tags: Vec<String>,
) -> Result<JsValue, JsValue> {
    let object = serde_wasm_bindgen::from_value(object)
        .map_err(|e| JsValue::from_str(&format!("Invalid object: {e}")))?;
    let attributes = serde_wasm_bindgen::from_value(attributes)?;
    let request = import_object_request(
        unique_identifier,
        object,
        attributes,
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
        .map_err(|e| JsValue::from_str(&format!("Revocation failed: {e}")))?;
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
