use std::str::FromStr;
use std::fmt::Display;

use base64::{engine::general_purpose, Engine as _};
use serde::{de::DeserializeOwned, Serialize};
use strum::EnumString;
use wasm_bindgen::prelude::*;
use pem::{EncodeConfig, LineEnding};
use zeroize::Zeroizing;
use js_sys::Uint8Array;

use crate::kmip_2_1::{
    kmip_objects::{Object, ObjectType},
    kmip_data_structures::KeyWrappingSpecification, kmip_operations::{
        Certify, CertifyResponse, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Decrypt,
        DecryptResponse, Destroy, DestroyResponse, EncryptResponse, Export, ExportResponse,
        GetAttributes, GetAttributesResponse, ImportResponse, Locate, LocateResponse,
        RevokeResponse, Validate, ValidateResponse,
    }, kmip_types::{
        CertificateRequestType, CryptographicAlgorithm, CryptographicParameters,
        KeyFormatType, RecommendedCurve, UniqueIdentifier, WrappingMethod, EncodingOption, EncryptionKeyInformation, HashingAlgorithm, PaddingMethod, BlockCipherMode
    }, requests::{
        build_revoke_key_request, create_ec_key_pair_request, create_rsa_key_pair_request,
        create_symmetric_key_kmip_object, decrypt_request, encrypt_request,
        get_ec_private_key_request, get_ec_public_key_request, get_rsa_private_key_request,
        get_rsa_public_key_request, import_object_request, symmetric_key_create_request,
    }, ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV}
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

#[derive(Debug, Clone, Copy, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum Curve {
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "nist-p192")]
    NistP192,
    #[strum(to_string = "nist-p224")]
    NistP224,
    #[strum(to_string = "nist-p256")]
    NistP256,
    #[strum(to_string = "nist-p384")]
    NistP384,
    #[strum(to_string = "nist-p521")]
    NistP521,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "x25519")]
    X25519,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "ed25519")]
    Ed25519,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "x448")]
    X448,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "ed448")]
    Ed448,
}

impl From<Curve> for RecommendedCurve {
    fn from(curve: Curve) -> Self {
        match curve {
            #[cfg(not(feature = "fips"))]
            Curve::NistP192 => Self::P192,
            Curve::NistP224 => Self::P224,
            Curve::NistP256 => Self::P256,
            Curve::NistP384 => Self::P384,
            Curve::NistP521 => Self::P521,
            #[cfg(not(feature = "fips"))]
            Curve::X25519 => Self::CURVE25519,
            #[cfg(not(feature = "fips"))]
            Curve::Ed25519 => Self::CURVEED25519,
            #[cfg(not(feature = "fips"))]
            Curve::X448 => Self::CURVE448,
            #[cfg(not(feature = "fips"))]
            Curve::Ed448 => Self::CURVEED448,
        }
    }
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
                "Invalid cryptographic key length: {number_of_bits}"
            )))?,
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
#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum ExportKeyFormat {
    JsonTtlv,
    Sec1Pem,
    Sec1Der,
    Pkcs1Pem,
    Pkcs1Der,
    Pkcs8Pem,
    Pkcs8Der,
    SpkiPem,
    SpkiDer,
    Base64,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub(crate) enum WrappingAlgorithm {
    NistKeyWrap,
    AesGCM,
    RsaPkcsV15,
    RsaOaep,
    RsaAesKeyWrap,
}

impl WrappingAlgorithm {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::NistKeyWrap => "nist-key-wrap",
            Self::AesGCM => "aes-gcm",
            Self::RsaPkcsV15 => "rsa-pkcs-v15",
            Self::RsaOaep => "rsa-oaep",
            Self::RsaAesKeyWrap => "rsa-aes-key-wrap",
        }
    }
}

impl Display for WrappingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[wasm_bindgen]
pub fn export_ttlv_request(
    unique_identifier: String,
    unwrap: bool,
    key_format: Option<String>,
    wrap_key_id: Option<String>,
    wrapping_algorithm: Option<String>,
    authentication_data: Option<String>
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

        Some(ExportKeyFormat::Pkcs8Pem)
        | Some(ExportKeyFormat::SpkiPem) => Some(KeyFormatType::PKCS8),

        Some(ExportKeyFormat::Pkcs8Der)
        | Some(ExportKeyFormat::SpkiDer) => Some(KeyFormatType::PKCS8),

        None => None, // Default case for when key_format is None
    };
    let encode_to_ttlv = key_format == Some(ExportKeyFormat::JsonTtlv);

    let wrapping_algorithm= wrapping_algorithm.and_then(|s| {
        WrappingAlgorithm::from_str(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid wrapping algorithm: {e}")))
            .ok()
    });
    let cryptographic_parameters = wrapping_algorithm
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
        wrap_key_id.map(|wrapping_key_id| {
            KeyWrappingSpecification {
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
            }
        }),
        key_format_type,
    );
    to_ttlv(&request)
        .map_err(|e| JsValue::from(e.to_string()))
        .and_then(|objects| {
            serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
        })
}

#[must_use]
/// Return the KMIP tag for a given object
/// This is required to match the Java library behavior which expects
/// the first tag to describe the type of object and not simply equal 'Object'
// TODO: check what is specified by the KMIP norm if any
fn tag_from_object(object: &Object) -> String {
    match &object {
        Object::PublicKey { .. } => "PublicKey",
        Object::SecretData { .. } => "SecretData",
        Object::PGPKey { .. } => "PGPKey",
        Object::SymmetricKey { .. } => "SymmetricKey",
        Object::SplitKey { .. } => "SplitKey",
        Object::Certificate { .. } => "Certificate",
        Object::CertificateRequest { .. } => "CertificateRequest",
        Object::OpaqueObject { .. } => "OpaqueObject",
        Object::PrivateKey { .. } => "PrivateKey",
    }
    .to_string()
}

/// Converts DER bytes to PEM bytes for keys
pub fn der_to_pem(
    bytes: &[u8],
    key_format_type: KeyFormatType,
    object_type: ObjectType,
) -> Result<Zeroizing<Vec<u8>>, JsValue> {
    let pem = match key_format_type {
        KeyFormatType::PKCS1 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "RSA PRIVATE KEY",
                ObjectType::PublicKey => "RSA PUBLIC KEY",
                x => {
                    Err(JsValue::from_str(&format!(
                        "Object type {x:?} not supported for PKCS1. Must be a private key or \
                    //      public key"
                    )))?
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::PKCS8 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "PRIVATE KEY",
                ObjectType::PublicKey => "PUBLIC KEY",
                x => {
                    Err(JsValue::from_str(&format!(
                        "Object type {x:?} not supported for PKCS#8 / SPKI. Must be a private key \
                        PKCS#8) or public key (SPKI)"
                    )))?
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::ECPrivateKey => {
            let tag = match object_type {
                ObjectType::PrivateKey => "EC PRIVATE KEY",
                x => {
                    Err(JsValue::from_str(&format!(
                        "Object type {x:?} not supported for SEC1. Must be a private key."
                    )))?
                }
            };
            pem::Pem::new(tag, bytes)
        }
        _ => {
            Err(JsValue::from_str(&format!(
                "Key format type {key_format_type:?} not supported for PEM conversion"
            )))?
        }
    };
    Ok(Zeroizing::new(
        pem::encode_config(&pem, EncodeConfig::new().set_line_ending(LineEnding::LF)).into_bytes(),
    ))
}


#[wasm_bindgen]
pub fn parse_export_ttlv_response(response: &str, key_format: &str) -> Result<JsValue, JsValue> {
    // let response = parse_ttlv_response::<ExportResponse>(response)?;
    let key_format = ExportKeyFormat::from_str(&key_format)
            .map_err(|e| JsValue::from_str(&format!("Invalid export key format type: {e}")))?;
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let response: ExportResponse = from_ttlv(&ttlv)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let data = match key_format {
        ExportKeyFormat::JsonTtlv => {
            let kmip_object = response.object;
            let mut ttlv = to_ttlv(&kmip_object).map_err(|e| JsValue::from(e.to_string()))?;
            ttlv.tag = tag_from_object(&kmip_object);
            let bytes = serde_json::to_vec::<TTLV>(&ttlv).map_err(|e| JsValue::from_str(&format!("{e}")))?;
            JsValue::from(Uint8Array::from(bytes.as_slice()))
        },
        ExportKeyFormat::Base64 => {
            let key_block = response.object.key_block().map_err(|e| JsValue::from_str(&format!("{e}")))?;
            let string = base64::engine::general_purpose::STANDARD
                .encode(key_block.key_bytes().map_err(|e| JsValue::from_str(&format!("{e}")))?)
                .to_lowercase();
            JsValue::from(string)
        },
        _ => {
            let key_block = response.object.key_block().map_err(|e| JsValue::from_str(&format!("{e}")))?;
            let object_type = response.object.object_type();
            let bytes = {
                let mut bytes = key_block.key_bytes().map_err(|e| JsValue::from_str(&format!("{e}")))?;
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
                    bytes = der_to_pem(
                        bytes.as_slice(),
                        key_format_type.unwrap(),
                        object_type,
                    )?;
                }
                bytes
            };
            JsValue::from(Uint8Array::from(bytes.as_slice()))
        },
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
