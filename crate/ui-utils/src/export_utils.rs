use std::fmt::Display;

use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::KeyWrappingSpecification,
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Export, Get},
    kmip_types::{
        BlockCipherMode, CryptographicAlgorithm, CryptographicParameters, EncodingOption,
        EncryptionKeyInformation, HashingAlgorithm, KeyFormatType, PaddingMethod, UniqueIdentifier,
        WrappingMethod,
    },
};
use pem::{EncodeConfig, LineEnding};
use strum::EnumString;
use zeroize::Zeroizing;

use crate::error::UtilsError;

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
pub enum WrappingAlgorithm {
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

#[must_use]
/// Return the KMIP tag for a given object
/// This is required to match the Java library behavior which expects
/// the first tag to describe the type of object and not simply equal 'Object'
// TODO: check what is specified by the KMIP norm if any
pub fn tag_from_object(object: &Object) -> String {
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
) -> Result<Zeroizing<Vec<u8>>, UtilsError> {
    let pem = match key_format_type {
        KeyFormatType::PKCS1 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "RSA PRIVATE KEY",
                ObjectType::PublicKey => "RSA PUBLIC KEY",
                x => Err(UtilsError::Default(format!(
                    "Object type {x:?} not supported for PKCS1. Must be a private key or public \
                     key"
                )))?,
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::PKCS8 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "PRIVATE KEY",
                ObjectType::PublicKey => "PUBLIC KEY",
                x => Err(UtilsError::Default(format!(
                    "Object type {x:?} not supported for PKCS#8 / SPKI. Must be a private key \
                     PKCS#8) or public key (SPKI)"
                )))?,
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::ECPrivateKey => {
            let tag = match object_type {
                ObjectType::PrivateKey => "EC PRIVATE KEY",
                x => Err(UtilsError::Default(format!(
                    "Object type {x:?} not supported for SEC1. Must be a private key."
                )))?,
            };
            pem::Pem::new(tag, bytes)
        }
        _ => Err(UtilsError::Default(format!(
            "Key format type {key_format_type:?} not supported for PEM conversion"
        )))?,
    };
    Ok(Zeroizing::new(
        pem::encode_config(&pem, EncodeConfig::new().set_line_ending(LineEnding::LF)).into_bytes(),
    ))
}

pub fn prepare_key_export_elements(
    key_format: &ExportKeyFormat,
    wrapping_algorithm: &Option<WrappingAlgorithm>,
) -> Result<
    (
        Option<KeyFormatType>,
        bool,
        bool,
        Option<CryptographicParameters>,
    ),
    UtilsError,
> {
    let (key_format_type, encode_to_pem) = match key_format {
        // For Raw: use the default format then do the local extraction of the bytes
        ExportKeyFormat::JsonTtlv | ExportKeyFormat::Raw | ExportKeyFormat::Base64 => (None, false),
        ExportKeyFormat::Sec1Pem => (Some(KeyFormatType::ECPrivateKey), true),
        ExportKeyFormat::Sec1Der => (Some(KeyFormatType::ECPrivateKey), false),
        ExportKeyFormat::Pkcs1Pem => (Some(KeyFormatType::PKCS1), true),
        ExportKeyFormat::Pkcs1Der => (Some(KeyFormatType::PKCS1), false),
        ExportKeyFormat::Pkcs8Pem | ExportKeyFormat::SpkiPem => (Some(KeyFormatType::PKCS8), true),
        ExportKeyFormat::Pkcs8Der | ExportKeyFormat::SpkiDer => (Some(KeyFormatType::PKCS8), false),
    };

    let encode_to_ttlv = *key_format == ExportKeyFormat::JsonTtlv;

    let wrapping_cryptographic_parameters =
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
    Ok((
        key_format_type,
        encode_to_pem,
        encode_to_ttlv,
        wrapping_cryptographic_parameters,
    ))
}

pub fn export_request(
    object_id_or_tags: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
    encoding_to_ttlv: bool,
    wrapping_cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
) -> Export {
    Export::new(
        UniqueIdentifier::TextString(object_id_or_tags.to_string()),
        unwrap,
        wrapping_key_id.map(|wrapping_key_id| {
            key_wrapping_specification(
                wrapping_key_id,
                wrapping_cryptographic_parameters,
                authenticated_encryption_additional_data,
                encoding_to_ttlv,
            )
        }),
        key_format_type,
    )
}

pub fn get_request(
    object_id_or_tags: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
    encoding_to_ttlv: bool,
    wrapping_cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
) -> Get {
    Get::new(
        UniqueIdentifier::TextString(object_id_or_tags.to_string()),
        unwrap,
        wrapping_key_id.map(|wrapping_key_id| {
            key_wrapping_specification(
                wrapping_key_id,
                wrapping_cryptographic_parameters,
                authenticated_encryption_additional_data,
                encoding_to_ttlv,
            )
        }),
        key_format_type,
    )
}

/// Determine the `KeyWrappingSpecification`
fn key_wrapping_specification(
    wrapping_key_id: &str,
    cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
    encode_to_ttlv: bool,
) -> KeyWrappingSpecification {
    KeyWrappingSpecification {
        wrapping_method: WrappingMethod::Encrypt,
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_id.to_string()),
            cryptographic_parameters,
        }),
        attribute_name: authenticated_encryption_additional_data.map(|data| vec![data]),
        encoding_option: Some(if encode_to_ttlv {
            EncodingOption::TTLVEncoding
        } else {
            EncodingOption::NoEncoding
        }),
        ..KeyWrappingSpecification::default()
    }
}
