use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_client_utils::{
    attributes_utils::{build_selected_attribute, parse_selected_attributes_flatten},
    certificate_utils::{Algorithm, build_certify_request},
    cover_crypt_utils::{
        build_create_covercrypt_master_keypair_request, build_create_covercrypt_usk_request,
    },
    create_utils::{Curve, SymmetricAlgorithm, prepare_sym_key_elements},
    error::UtilsError,
    export_utils::{
        CertificateExportFormat, ExportKeyFormat, WrappingAlgorithm, der_to_pem, export_request,
        get_export_key_format_type, prepare_certificate_export_elements,
        prepare_key_export_elements, tag_from_object,
    },
    import_utils::{
        CertificateInputFormat, ImportKeyFormat, KeyUsage, build_private_key_from_der_bytes,
        build_usage_mask_from_key_usage, prepare_certificate_attributes,
        prepare_key_import_elements, read_object_from_json_ttlv_bytes,
    },
    locate_utils::build_locate_request,
    reexport::cosmian_kmip::{
        kmip_0::{
            self,
            kmip_types::{CertificateType, RevocationReason, RevocationReasonCode, SecretDataType},
        },
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyMaterial, KeyValue},
            kmip_objects::{
                Certificate as KmipCertificate, Object, ObjectType,
                OpaqueObject as KmipOpaqueObject, PrivateKey,
            },
            kmip_operations::{
                CertifyResponse, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Decrypt,
                DecryptResponse, DeleteAttribute, DeleteAttributeResponse, Destroy,
                DestroyResponse, EncryptResponse, ExportResponse, GetAttributes,
                GetAttributesResponse, ImportResponse, LocateResponse, RevokeResponse,
                SetAttribute, SetAttributeResponse, Sign, SignResponse, SignatureVerify,
                SignatureVerifyResponse, Validate, ValidateResponse,
            },
            kmip_types::{
                AttributeReference, CryptographicAlgorithm, CryptographicParameters, KeyFormatType,
                LinkType, LinkedObjectIdentifier, OpaqueDataType, RecommendedCurve, Tag,
                UniqueIdentifier,
            },
            requests::{
                build_revoke_key_request, create_ec_key_pair_request, create_rsa_key_pair_request,
                create_secret_data_kmip_object, create_symmetric_key_kmip_object, decrypt_request,
                encrypt_request, get_ec_private_key_request, get_ec_public_key_request,
                get_rsa_private_key_request, get_rsa_public_key_request, import_object_request,
                secret_data_create_request, symmetric_key_create_request,
            },
        },
        ttlv::{TTLV, from_ttlv, to_ttlv},
    },
    rsa_utils::{HashFn, RsaEncryptionAlgorithm},
    symmetric_utils::{DataEncryptionAlgorithm, parse_decrypt_elements},
};
use js_sys::Uint8Array;
use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;
use x509_cert::{
    Certificate,
    der::{Decode, DecodePem, Encode},
};
use zeroize::Zeroizing;

#[derive(Serialize, Clone)]
struct AlgoOption {
    value: String,
    label: String,
}

// Try to parse KeyFormatType from various string representations (robust to spacing/case)
fn parse_key_format_type_flexible(s: &str) -> Result<KeyFormatType, JsValue> {
    if let Ok(k) = KeyFormatType::from_str(s) {
        return Ok(k);
    }
    let norm = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .collect::<String>()
        .to_lowercase();
    let candidates: &[KeyFormatType] = &[
        KeyFormatType::Raw,
        KeyFormatType::Opaque,
        KeyFormatType::PKCS1,
        KeyFormatType::PKCS8,
        KeyFormatType::X509,
        KeyFormatType::ECPrivateKey,
        KeyFormatType::TransparentSymmetricKey,
        KeyFormatType::TransparentDSAPrivateKey,
        KeyFormatType::TransparentDSAPublicKey,
        KeyFormatType::TransparentRSAPrivateKey,
        KeyFormatType::TransparentRSAPublicKey,
        KeyFormatType::TransparentDHPrivateKey,
        KeyFormatType::TransparentDHPublicKey,
        KeyFormatType::TransparentECPrivateKey,
        KeyFormatType::TransparentECPublicKey,
        KeyFormatType::PKCS12,
        KeyFormatType::PKCS10,
        KeyFormatType::PKCS7,
        KeyFormatType::EnclaveECKeyPair,
        KeyFormatType::EnclaveECSharedKey,
        #[cfg(feature = "non-fips")]
        KeyFormatType::CoverCryptSecretKey,
        #[cfg(feature = "non-fips")]
        KeyFormatType::CoverCryptPublicKey,
    ];
    for v in candidates {
        let display = v.to_string();
        let display_norm = display
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .collect::<String>()
            .to_lowercase();
        if display_norm == norm {
            return Ok(*v);
        }
    }
    Err(JsValue::from("Invalid KeyFormatType"))
}

// Internal helpers to build algorithm option lists that reflect client_utils
fn list_symmetric_algorithms() -> Vec<AlgoOption> {
    // Provide UI labels independent of Display, with values matching `SymmetricAlgorithm::from_str`
    #[allow(unused_mut)]
    let mut algs: Vec<(SymmetricAlgorithm, &'static str)> = vec![
        (SymmetricAlgorithm::Aes, "AES"),
        (SymmetricAlgorithm::Sha3, "SHA3"),
        (SymmetricAlgorithm::Shake, "SHAKE"),
    ];
    #[cfg(feature = "non-fips")]
    {
        algs.push((SymmetricAlgorithm::Chacha20, "ChaCha20"));
    }

    algs.into_iter()
        .map(|(a, label)| {
            // Values use PascalCase variant names expected by `from_str`
            let value = match a {
                SymmetricAlgorithm::Aes => "Aes",
                #[cfg(feature = "non-fips")]
                SymmetricAlgorithm::Chacha20 => "Chacha20",
                SymmetricAlgorithm::Sha3 => "Sha3",
                SymmetricAlgorithm::Shake => "Shake",
            };
            AlgoOption {
                value: value.to_owned(),
                label: label.to_owned(),
            }
        })
        .collect()
}

fn list_ec_algorithms() -> Vec<AlgoOption> {
    // Build from client_utils' Curve enum to ensure feature gating consistency
    #[allow(unused_mut)]
    let mut curves: Vec<Curve> = vec![Curve::NistP256, Curve::NistP384, Curve::NistP521];
    #[cfg(feature = "non-fips")]
    {
        curves.insert(0, Curve::Secp224k1);
        curves.push(Curve::Secp256k1);
        curves.push(Curve::X25519);
        curves.push(Curve::Ed25519);
        curves.push(Curve::X448);
        curves.push(Curve::Ed448);
    }

    curves
        .into_iter()
        .map(|c| {
            // Value must be kebab-case identifier that `Curve::from_str` accepts
            let (value, label): (&'static str, &'static str) = match c {
                Curve::NistP256 => ("nist-p256", "NIST P-256"),
                Curve::NistP384 => ("nist-p384", "NIST P-384"),
                Curve::NistP521 => ("nist-p521", "NIST P-521"),
                #[cfg(feature = "non-fips")]
                Curve::X25519 => ("x25519", "X25519"),
                #[cfg(feature = "non-fips")]
                Curve::Ed25519 => ("ed25519", "Ed25519"),
                #[cfg(feature = "non-fips")]
                Curve::X448 => ("x448", "X448"),
                #[cfg(feature = "non-fips")]
                Curve::Ed448 => ("ed448", "Ed448"),
                #[cfg(feature = "non-fips")]
                Curve::Secp256k1 => ("secp256k1", "SECP256k1"),
                #[cfg(feature = "non-fips")]
                Curve::Secp224k1 => ("secp224k1", "SECP224k1"),
            };
            AlgoOption {
                value: value.to_owned(),
                label: label.to_owned(),
            }
        })
        .collect()
}

#[wasm_bindgen]
pub fn get_symmetric_algorithms() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&list_symmetric_algorithms())
        .map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn get_ec_algorithms() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&list_ec_algorithms()).map_err(|e| JsValue::from(e.to_string()))
}

/// Returns the list of cryptographic algorithms available in this build.
/// Now reuses EC and Symmetric lists for feature-driven consistency.
#[wasm_bindgen]
pub fn get_crypto_algorithms() -> Result<JsValue, JsValue> {
    let sym = list_symmetric_algorithms();
    let ec_list = list_ec_algorithms();

    #[allow(unused_mut)]
    let mut variants: Vec<CryptographicAlgorithm> = vec![
        CryptographicAlgorithm::AES,
        CryptographicAlgorithm::RSA,
        CryptographicAlgorithm::ECDSA,
        CryptographicAlgorithm::ECDH,
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHA3224,
        CryptographicAlgorithm::SHA3256,
        CryptographicAlgorithm::SHA3384,
        CryptographicAlgorithm::SHA3512,
    ];
    #[cfg(feature = "non-fips")]
    {
        variants.push(CryptographicAlgorithm::CoverCrypt);
        variants.push(CryptographicAlgorithm::CoverCryptBulk);
    }

    if ec_list.iter().any(|o| o.value == "ed25519") {
        variants.push(CryptographicAlgorithm::Ed25519);
    }
    if ec_list.iter().any(|o| o.value == "ed448") {
        variants.push(CryptographicAlgorithm::Ed448);
    }

    if sym.iter().any(|o| o.value.eq_ignore_ascii_case("chacha20")) {
        variants.push(CryptographicAlgorithm::ChaCha20);
        variants.push(CryptographicAlgorithm::ChaCha20Poly1305);
    }

    let algorithms: Vec<AlgoOption> = variants
        .into_iter()
        .map(|alg| {
            let value = alg.to_string();
            let label = value.clone();
            AlgoOption { value, label }
        })
        .collect();

    serde_wasm_bindgen::to_value(&algorithms).map_err(|e| JsValue::from(e.to_string()))
}

/// Returns the list of certificate key generation algorithms (RSA sizes and EC curves)
/// mirroring `crate/client_utils/src/certificate_utils.rs` `Algorithm` variants.
#[wasm_bindgen]
pub fn get_certificate_algorithms() -> Result<JsValue, JsValue> {
    #[cfg(feature = "non-fips")]
    let opts: Vec<AlgoOption> = vec![
        // EC curves (keep NIST P-192 first)
        AlgoOption {
            value: "nist-p192".into(),
            label: "NIST P-192".into(),
        },
        AlgoOption {
            value: "nist-p224".into(),
            label: "NIST P-224".into(),
        },
        AlgoOption {
            value: "nist-p256".into(),
            label: "NIST P-256".into(),
        },
        AlgoOption {
            value: "nist-p384".into(),
            label: "NIST P-384".into(),
        },
        AlgoOption {
            value: "nist-p521".into(),
            label: "NIST P-521".into(),
        },
        // Additional EC (non-FIPS)
        AlgoOption {
            value: "ed25519".into(),
            label: "Ed25519".into(),
        },
        AlgoOption {
            value: "ed448".into(),
            label: "Ed448".into(),
        },
        // RSA sizes
        AlgoOption {
            value: "rsa1024".into(),
            label: "RSA 1024".into(),
        },
        AlgoOption {
            value: "rsa2048".into(),
            label: "RSA 2048".into(),
        },
        AlgoOption {
            value: "rsa3072".into(),
            label: "RSA 3072".into(),
        },
        AlgoOption {
            value: "rsa4096".into(),
            label: "RSA 4096".into(),
        },
    ];
    #[cfg(not(feature = "non-fips"))]
    let opts: Vec<AlgoOption> = vec![
        // EC curves (FIPS subset)
        AlgoOption {
            value: "nist-p224".into(),
            label: "NIST P-224".into(),
        },
        AlgoOption {
            value: "nist-p256".into(),
            label: "NIST P-256".into(),
        },
        AlgoOption {
            value: "nist-p384".into(),
            label: "NIST P-384".into(),
        },
        AlgoOption {
            value: "nist-p521".into(),
            label: "NIST P-521".into(),
        },
        // RSA sizes
        AlgoOption {
            value: "rsa2048".into(),
            label: "RSA 2048".into(),
        },
        AlgoOption {
            value: "rsa3072".into(),
            label: "RSA 3072".into(),
        },
        AlgoOption {
            value: "rsa4096".into(),
            label: "RSA 4096".into(),
        },
    ];

    serde_wasm_bindgen::to_value(&opts).map_err(|e| JsValue::from(e.to_string()))
}

/// Returns supported key format types for UI filters.
#[wasm_bindgen]
pub fn get_key_format_types() -> Result<JsValue, JsValue> {
    // Prefer KMIP 2.1 enum variants directly
    let variants: &[KeyFormatType] = &[
        KeyFormatType::Raw,
        KeyFormatType::Opaque,
        KeyFormatType::PKCS1,
        KeyFormatType::PKCS8,
        KeyFormatType::X509,
        KeyFormatType::ECPrivateKey,
        KeyFormatType::TransparentSymmetricKey,
        KeyFormatType::TransparentDSAPrivateKey,
        KeyFormatType::TransparentDSAPublicKey,
        KeyFormatType::TransparentRSAPrivateKey,
        KeyFormatType::TransparentRSAPublicKey,
        KeyFormatType::TransparentDHPrivateKey,
        KeyFormatType::TransparentDHPublicKey,
        KeyFormatType::TransparentECPrivateKey,
        KeyFormatType::TransparentECPublicKey,
        KeyFormatType::PKCS12,
        KeyFormatType::CoverCryptSecretKey,
        KeyFormatType::CoverCryptPublicKey,
    ];

    let formats: Vec<AlgoOption> = variants
        .iter()
        .map(|k| {
            let value = k.to_string();
            let label = match k {
                KeyFormatType::CoverCryptSecretKey => String::from("CoverCrypt Secret Key"),
                KeyFormatType::CoverCryptPublicKey => String::from("CoverCrypt Public Key"),
                _ => value.clone(),
            };
            AlgoOption { value, label }
        })
        .collect();

    serde_wasm_bindgen::to_value(&formats).map_err(|e| JsValue::from(e.to_string()))
}

/// Returns supported KMIP object types for UI filters.
#[wasm_bindgen]
pub fn get_object_types() -> Result<JsValue, JsValue> {
    let variants: &[ObjectType] = &[
        ObjectType::Certificate,
        ObjectType::SymmetricKey,
        ObjectType::PublicKey,
        ObjectType::PrivateKey,
        ObjectType::SplitKey,
        ObjectType::SecretData,
        ObjectType::OpaqueObject,
        ObjectType::PGPKey,
        ObjectType::CertificateRequest,
    ];
    let types: Vec<AlgoOption> = variants
        .iter()
        .map(|v| {
            let value = v.to_string();
            let label = v.to_string();
            AlgoOption { value, label }
        })
        .collect();
    serde_wasm_bindgen::to_value(&types).map_err(|e| JsValue::from(e.to_string()))
}

/// Returns KMIP lifecycle states for UI filters.
#[wasm_bindgen]
pub fn get_object_states() -> Result<JsValue, JsValue> {
    let mut states: Vec<AlgoOption> = Vec::new();
    // Use KMIP 1.0 State enum to derive names/labels
    let variants = [
        kmip_0::kmip_types::State::PreActive,
        kmip_0::kmip_types::State::Active,
        kmip_0::kmip_types::State::Deactivated,
        kmip_0::kmip_types::State::Compromised,
        kmip_0::kmip_types::State::Destroyed,
        kmip_0::kmip_types::State::Destroyed_Compromised,
    ];
    for s in variants {
        let label = s.to_string();
        // Use UI labels for value to keep client-side filtering stable
        states.push(AlgoOption {
            value: label.clone(),
            label,
        });
    }
    serde_wasm_bindgen::to_value(&states).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen(start)]
#[allow(clippy::missing_const_for_fn)]
pub fn init_panic_hook() {
    // Improve error messages for panics in the browser console
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}

/// Returns true when compiled in FIPS mode (default), false in non-FIPS builds.
#[wasm_bindgen]
#[allow(clippy::missing_const_for_fn)]
#[must_use]
pub fn is_fips_mode() -> bool {
    // `non-fips` feature disables FIPS mode
    !cfg!(feature = "non-fips")
}

fn parse_ttlv_response<T: DeserializeOwned + Serialize>(
    response: &str,
) -> Result<JsValue, JsValue> {
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let parsed: T = from_ttlv(ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&parsed).map_err(|e| JsValue::from(e.to_string()))
}

// Locate request
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
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
        .map(parse_key_format_type_flexible)
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_locate_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<LocateResponse>(response)
}

// Create keys Requests
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
pub fn create_rsa_key_pair_ttlv_request(
    private_key_id: Option<String>,
    tags: Vec<String>,
    cryptographic_length: usize,
    sensitive: bool,
    wrapping_key_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let private_key_id = private_key_id.map(UniqueIdentifier::TextString);
    let request: CreateKeyPair = create_rsa_key_pair_request(
        private_key_id,
        tags,
        cryptographic_length,
        sensitive,
        wrapping_key_id.as_ref(),
    )
    .map_err(|e| JsValue::from_str(&format!("Key pair creation failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
pub fn create_ec_key_pair_ttlv_request(
    private_key_id: Option<String>,
    tags: Vec<String>,
    recommended_curve: &str,
    sensitive: bool,
    wrapping_key_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let private_key_id = private_key_id.map(UniqueIdentifier::TextString);
    let recommended_curve: RecommendedCurve = Curve::from_str(recommended_curve)
        .map_err(|e| JsValue::from_str(&format!("Invalid recommended curve: {e}")))?
        .into();
    let request: CreateKeyPair = create_ec_key_pair_request(
        private_key_id,
        tags,
        recommended_curve,
        sensitive,
        wrapping_key_id.as_ref(),
    )
    .map_err(|e| JsValue::from_str(&format!("Key pair creation failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_create_keypair_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<CreateKeyPairResponse>(response)
}

#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
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
        let mut object = create_symmetric_key_kmip_object(
            key_bytes.as_slice(),
            &Attributes {
                cryptographic_algorithm: Some(algorithm),
                ..Default::default()
            },
        )
        .map_err(|e| JsValue::from_str(&format!("Error creating symmetric key: {e}")))?;
        if let Some(wrapping_key_id) = &wrap_key_id {
            let attributes = object.attributes_mut().map_err(|e| {
                JsValue::from_str(&format!("Error creating symmetric key attributes: {e}"))
            })?;
            attributes.set_wrapping_key_id(wrapping_key_id);
        }
        let request = import_object_request(key_id, object, None, false, false, &tags)
            .map_err(|e| JsValue::from_str(&format!("Error forging import request: {e}")))?;
        let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
        serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
        let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
        serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
    }
}

#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn create_secret_data_ttlv_request(
    secret_type: &str,
    secret_value: Option<String>,
    secret_id: Option<String>,
    tags: Vec<String>,
    sensitive: bool,
    wrap_key_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let secret_data_type = SecretDataType::from_str(secret_type)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret data type: {e}")))?;

    if let Some(secret_value) = secret_value {
        let mut object = create_secret_data_kmip_object(
            secret_value.as_bytes(),
            secret_data_type,
            &Attributes::default(),
        )
        .map_err(|e| JsValue::from_str(&format!("Error creating secret data: {e}")))?;
        if let Some(wrapping_key_id) = &wrap_key_id {
            let attributes = object.attributes_mut().map_err(|e| {
                JsValue::from_str(&format!("Error creating secret data attributes: {e}"))
            })?;
            attributes.set_wrapping_key_id(wrapping_key_id);
        }
        let request = import_object_request(secret_id, object, None, false, false, &tags)
            .map_err(|e| JsValue::from_str(&format!("Error forging import request: {e}")))?;

        let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
        serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
    } else {
        let secret_id = secret_id.map(UniqueIdentifier::TextString);
        let request = secret_data_create_request(secret_id, &tags, sensitive, wrap_key_id.as_ref())
            .map_err(|e| JsValue::from_str(&format!("Secret Data request creation failed: {e}")))?;
        let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
        serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
    }
}

#[wasm_bindgen]
pub fn parse_create_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<CreateResponse>(response)
}

/// Create an Opaque Object (via Import) TTLV request.
/// If `object_value` is provided, builds an `OpaqueObject` and forges an `Import` request.
/// Wrapping key id can be provided to set the object wrapping attribute.
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn create_opaque_object_ttlv_request(
    object_value: Option<String>,
    object_id: Option<String>,
    tags: Vec<String>,
    _sensitive: bool,
    wrap_key_id: Option<String>,
) -> Result<JsValue, JsValue> {
    // Allow empty opaque object when value not provided
    #[allow(clippy::redundant_closure_for_method_calls)]
    let data = object_value.map(|v| v.into_bytes()).unwrap_or_default();

    let mut object = Object::OpaqueObject(KmipOpaqueObject {
        opaque_data_type: OpaqueDataType::Unknown,
        opaque_data_value: data,
    });

    if let Some(wrapping_key_id) = &wrap_key_id {
        let attributes = object.attributes_mut().map_err(|e| {
            JsValue::from_str(&format!("Error creating opaque object attributes: {e}"))
        })?;
        attributes.set_wrapping_key_id(wrapping_key_id);
    }

    let request = import_object_request(object_id, object, None, false, false, &tags)
        .map_err(|e| JsValue::from_str(&format!("Error forging import request: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_ec_ttlv_request(
    key_unique_identifier: &str,
    ciphertext: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let request = decrypt_request(key_unique_identifier, None, ciphertext, None, None, None);
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
        cascade: false,
    };
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
        nonce,
        authentication_data,
        cryptographic_parameters,
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
        Some(encryption_algorithm.to_cryptographic_parameters(hash_fn)),
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_ec_ttlv_request(
    key_unique_identifier: &str,
    plaintext: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let request = encrypt_request(key_unique_identifier, None, plaintext, None, None, None)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_encrypt_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<EncryptResponse>(response)
}

// Sign requests
fn js_to_cryptographic_parameters(
    alg: Option<JsValue>,
) -> Result<Option<CryptographicParameters>, JsValue> {
    if alg.is_none() {
        return Ok(None);
    }
    let Some(v) = alg else {
        return Ok(None);
    };
    if v.is_null() || v.is_undefined() {
        return Ok(None);
    }
    if let Some(s) = v.as_string() {
        let s_norm = s.trim().to_lowercase();
        let cp = match s_norm.as_str() {
            // RSA
            "rsassapss" => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(kmip_0::kmip_types::PaddingMethod::None),
                hashing_algorithm: None,
                ..Default::default()
            },
            // ECDSA variants
            "ecdsa-with-sha256" => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(kmip_0::kmip_types::PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha256.into()),
                ..Default::default()
            },
            "ecdsa-with-sha384" => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(kmip_0::kmip_types::PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha384.into()),
                ..Default::default()
            },
            "ecdsa-with-sha512" => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(kmip_0::kmip_types::PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha512.into()),
                ..Default::default()
            },
            _ => {
                return Err(JsValue::from_str(&format!(
                    "Unsupported signature algorithm: '{s}'"
                )));
            }
        };
        return Ok(Some(cp));
    }
    // Try to deserialize a full `CryptographicParameters` object
    let cp: CryptographicParameters = serde_wasm_bindgen::from_value(v).map_err(|e| {
        JsValue::from_str(&format!(
            "Invalid CryptographicParameters value: {e}. Expect string algorithm or CP object."
        ))
    })?;
    Ok(Some(cp))
}

#[wasm_bindgen]
pub fn sign_ttlv_request(
    key_unique_identifier: &str,
    data_or_digest: Vec<u8>,
    cryptographic_parameters: Option<JsValue>,
    digested: bool,
) -> Result<JsValue, JsValue> {
    let cp = js_to_cryptographic_parameters(cryptographic_parameters).map_err(|e| {
        JsValue::from_str(&format!(
            "sign_ttlv_request: invalid cryptographic parameters for key '{key_unique_identifier}': {e:?}"
        ))
    })?;
    let request = if digested {
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(
                key_unique_identifier.to_owned(),
            )),
            cryptographic_parameters: cp,
            data: None,
            digested_data: Some(data_or_digest),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    } else {
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(
                key_unique_identifier.to_owned(),
            )),
            cryptographic_parameters: cp,
            data: Some(data_or_digest.into()),
            digested_data: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    };
    let objects = to_ttlv(&request).map_err(|e| {
        JsValue::from_str(&format!(
            "sign_ttlv_request: failed to serialize TTLV for key '{key_unique_identifier}', digested={digested}, payload_len={}: {e}",
            if digested { request.digested_data.as_ref().map_or(0, std::vec::Vec::len) } else { request.data.as_ref().map_or(0, |v| v.len()) }
        ))
    })?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_sign_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<SignResponse>(response).map_err(|e| {
        JsValue::from_str(&format!(
            "parse_sign_ttlv_response: invalid response: {e:?}"
        ))
    })
}

#[wasm_bindgen]
pub fn signature_verify_ttlv_request(
    key_unique_identifier: &str,
    data_or_digest: Vec<u8>,
    signature: Vec<u8>,
    cryptographic_parameters: Option<JsValue>,
    digested: bool,
) -> Result<JsValue, JsValue> {
    let cp = js_to_cryptographic_parameters(cryptographic_parameters).map_err(|e| {
        JsValue::from_str(&format!(
            "signature_verify_ttlv_request: invalid cryptographic parameters for key '{key_unique_identifier}': {e:?}"
        ))
    })?;
    let request = if digested {
        SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(
                key_unique_identifier.to_owned(),
            )),
            cryptographic_parameters: cp,
            data: None,
            digested_data: Some(data_or_digest),
            signature_data: Some(signature),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    } else {
        SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(
                key_unique_identifier.to_owned(),
            )),
            cryptographic_parameters: cp,
            data: Some(data_or_digest),
            digested_data: None,
            signature_data: Some(signature),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    };
    let objects = to_ttlv(&request).map_err(|e| {
        let payload_len = if digested {
            request.digested_data.as_ref().map_or(0, std::vec::Vec::len)
        } else {
            request.data.as_ref().map_or(0, std::vec::Vec::len)
        };
        let sig_len = request.signature_data.as_ref().map_or(0, std::vec::Vec::len);
        JsValue::from_str(&format!(
            "signature_verify_ttlv_request: failed to serialize TTLV for key '{key_unique_identifier}', digested={digested}, payload_len={payload_len}, signature_len={sig_len}: {e}"
        ))
    })?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_signature_verify_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<SignatureVerifyResponse>(response).map_err(|e| {
        JsValue::from_str(&format!(
            "parse_signature_verify_ttlv_response: invalid response: {e:?}"
        ))
    })
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_export_ttlv_response(response: &str, key_format: &str) -> Result<JsValue, JsValue> {
    // let response = parse_ttlv_response::<ExportResponse>(response)?;
    let key_format = ExportKeyFormat::from_str(key_format)
        .map_err(|e| JsValue::from_str(&format!("Invalid export key format type: {e}")))?;
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let response: ExportResponse = from_ttlv(ttlv).map_err(|e| JsValue::from(e.to_string()))?;
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
            let kmip_object = response.object;
            let string = general_purpose::STANDARD
                .encode(get_object_bytes(&kmip_object)?)
                .to_lowercase();
            JsValue::from(string)
        }
        _ => {
            let kmip_object = response.object;
            let object_type = kmip_object.object_type();
            let bytes = {
                let mut bytes = get_object_bytes(&kmip_object)?;
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
                        .map_err(|e| JsValue::from_str(&format!("{e}")))?
                        .to_vec();
                }
                bytes
            };
            JsValue::from(Uint8Array::from(bytes.as_slice()))
        }
    };
    Ok(data)
}

fn get_object_bytes(object: &Object) -> Result<Vec<u8>, JsValue> {
    let key_block = object
        .key_block()
        .map_err(|e| JsValue::from_str(&format!("{e}")))?;
    match key_block
        .key_value
        .as_ref()
        .ok_or_else(|| JsValue::from_str("Key value is missing"))?
    {
        KeyValue::ByteString(v) => Ok(v.to_vec()),
        KeyValue::Structure { key_material, .. } => match key_material {
            KeyMaterial::ByteString(v) => Ok(v.to_vec()),
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key.to_vec()),
            KeyMaterial::TransparentECPrivateKey { .. }
            | KeyMaterial::TransparentECPublicKey { .. } => key_block
                .ec_raw_bytes()
                .map(|v| v.to_vec())
                .map_err(|e| JsValue::from_str(&e.to_string())),
            x => Err(JsValue::from_str(&format!(
                "Unsupported key material type: {x:?}"
            ))),
        },
    }
}

// Get requests
#[wasm_bindgen]
pub fn get_rsa_private_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_rsa_private_key_request(key_unique_identifier);
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn get_rsa_public_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_rsa_public_key_request(key_unique_identifier);
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn get_ec_private_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_ec_private_key_request(key_unique_identifier);
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn get_ec_public_key_ttlv_request(key_unique_identifier: &str) -> Result<JsValue, JsValue> {
    let request = get_ec_public_key_request(key_unique_identifier);
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    wrapping_key_id: Option<String>,
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
        wrapping_key_id.as_ref(),
    )
    .map_err(|e| JsValue::from(e.to_string()))?;
    let request = import_object_request(
        unique_identifier,
        object,
        Some(import_attributes),
        unwrap,
        replace_existing,
        tags,
    )
    .map_err(|e| JsValue::from_str(&format!("Error forging import request: {e}")))?;

    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_import_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<ImportResponse>(response)
}

// Revoke request
#[wasm_bindgen]
pub fn revoke_ttlv_request(
    unique_identifier: &str,
    revocation_reason_message: String,
) -> Result<JsValue, JsValue> {
    let revocation_reason = RevocationReason {
        revocation_reason_code: RevocationReasonCode::Unspecified,
        revocation_message: Some(revocation_reason_message),
    };
    let request = build_revoke_key_request(unique_identifier, revocation_reason)
        .map_err(|e| JsValue::from_str(&format!("Revocation request creation failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_revoke_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<RevokeResponse>(response)
}

// Covercrypt requests
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn create_cc_master_keypair_ttlv_request(
    access_structure: &str,
    tags: Vec<String>,
    sensitive: bool,
    wrapping_key_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let request = build_create_covercrypt_master_keypair_request(
        access_structure,
        tags,
        sensitive,
        wrapping_key_id.as_ref(),
    )
    .map_err(|e| JsValue::from_str(&format!("Covercrypt master keypair creation failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn create_cc_user_key_ttlv_request(
    master_secret_key_id: &str,
    access_policy: &str,
    tags: Vec<String>,
    sensitive: bool,
    wrapping_key_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let request = build_create_covercrypt_usk_request(
        access_policy,
        master_secret_key_id,
        tags,
        sensitive,
        wrapping_key_id.as_ref(),
    )
    .map_err(|e| JsValue::from_str(&format!("Covercrypt user key creation failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
        authentication_data,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
            let object = Object::Certificate(KmipCertificate {
                certificate_type: CertificateType::X509,
                certificate_value: certificate
                    .to_der()
                    .map_err(|e| JsValue::from(e.to_string()))?,
            });
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
            let object = Object::Certificate(KmipCertificate {
                certificate_type: CertificateType::X509,
                certificate_value: certificate
                    .to_der()
                    .map_err(|e| JsValue::from(e.to_string()))?,
            });
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
    }
    .map_err(|e| JsValue::from_str(&format!("Error forging import request: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let response: ExportResponse = from_ttlv(ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    let object = response.object;
    let object_type = response.object_type;
    match &object {
        Object::Certificate(KmipCertificate {
            certificate_value, ..
        }) => {
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
                #[cfg(feature = "non-fips")]
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
        Object::PrivateKey(PrivateKey { key_block }) => {
            let p12_bytes = key_block
                .pkcs_der_bytes()
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
    unique_identifier: Option<String>,
    validity_time: Option<String>,
) -> Result<JsValue, JsValue> {
    let unique_identifier = unique_identifier.map(|id| vec![UniqueIdentifier::TextString(id)]);
    let request = Validate {
        certificate: None,
        unique_identifier,
        validity_time,
    };
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
        authentication_data,
        Some(cryptographic_parameters),
    )
    .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_certify_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<CertifyResponse>(response)
}

// Attributes request
#[wasm_bindgen]
pub fn get_attributes_ttlv_request(unique_identifier: String) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
    let request = GetAttributes {
        unique_identifier: Some(unique_identifier),
        attribute_reference: None,
    };
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

/// Same as `get_attributes_ttlv_request`, but can force requesting tags.
///
/// Some callers (notably UI/WASM) rely on tags being returned, but the server may not include
/// `Tag::Tag` unless explicitly requested.
#[wasm_bindgen]
pub fn get_attributes_ttlv_request_with_options(
    unique_identifier: String,
    force_tags: bool,
) -> Result<JsValue, JsValue> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);

    let attribute_reference = if force_tags {
        Some(vec![AttributeReference::Standard(Tag::Tag)])
    } else {
        None
    };

    let request = GetAttributes {
        unique_identifier: Some(unique_identifier),
        attribute_reference,
    };

    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn parse_get_attributes_ttlv_response(
    response: &str,
    selected_attributes: Vec<String>,
) -> Result<JsValue, JsValue> {
    let selected_attributes: Vec<&str> = selected_attributes.iter().map(String::as_str).collect();
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let GetAttributesResponse {
        unique_identifier: _,
        attributes,
    } = from_ttlv(ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    let results = parse_selected_attributes_flatten(&attributes, &selected_attributes)
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
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
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier);
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
    let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

#[wasm_bindgen]
pub fn parse_delete_attribute_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
    parse_ttlv_response::<DeleteAttributeResponse>(response)
}
