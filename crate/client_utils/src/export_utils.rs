use clap::ValueEnum;
use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_data_structures::KeyWrappingSpecification,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Export, Get},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, EncodingOption,
            EncryptionKeyInformation, KeyFormatType, UniqueIdentifier, WrappingMethod,
        },
    },
};
use pem::{EncodeConfig, LineEnding};
use strum::EnumString;
use zeroize::Zeroizing;

use crate::error::UtilsError;

#[derive(Default, Debug, Clone, PartialEq, Eq, EnumString, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum ExportKeyFormat {
    #[default]
    JsonTtlv,
    Sec1Pem,
    Sec1Der,
    Pkcs1Pem,
    Pkcs1Der,
    Pkcs8Pem,
    Pkcs8Der,
    Base64,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumString, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum WrappingAlgorithm {
    AESKeyWrapPadding, // RFC 5649
    NistKeyWrap,       // RFC 3394
    AesGCM,
    RsaPkcsV15Sha1,
    RsaPkcsV15,
    RsaOaepSha1,
    RsaOaep,
    RsaAesKeyWrapSha1,
    RsaAesKeyWrap,
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
    .to_owned()
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
                x => {
                    return Err(UtilsError::Default(format!(
                        "Object type {x:?} not supported for PKCS1. Must be a private key or \
                         public key"
                    )));
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::PKCS8 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "PRIVATE KEY",
                ObjectType::PublicKey => "PUBLIC KEY",
                x => {
                    return Err(UtilsError::Default(format!(
                        "Object type {x:?} not supported for PKCS#8. Must be a private key PKCS#8)"
                    )));
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::ECPrivateKey => {
            let tag = match object_type {
                ObjectType::PrivateKey => "EC PRIVATE KEY",
                x => {
                    return Err(UtilsError::Default(format!(
                        "Object type {x:?} not supported for SEC1. Must be a private key."
                    )));
                }
            };
            pem::Pem::new(tag, bytes)
        }
        _ => {
            return Err(UtilsError::Default(format!(
                "Key format type {key_format_type:?} not supported for PEM conversion"
            )));
        }
    };
    Ok(Zeroizing::new(
        pem::encode_config(&pem, EncodeConfig::new().set_line_ending(LineEnding::LF)).into_bytes(),
    ))
}

#[must_use]
pub const fn get_export_key_format_type(
    key_format: &ExportKeyFormat,
) -> (Option<KeyFormatType>, bool) {
    let (key_format_type, encode_to_pem) = match key_format {
        // For Raw: use the default format then do the local extraction of the bytes
        ExportKeyFormat::JsonTtlv | ExportKeyFormat::Raw | ExportKeyFormat::Base64 => (None, false),
        ExportKeyFormat::Sec1Pem => (Some(KeyFormatType::ECPrivateKey), true),
        ExportKeyFormat::Sec1Der => (Some(KeyFormatType::ECPrivateKey), false),
        ExportKeyFormat::Pkcs1Pem => (Some(KeyFormatType::PKCS1), true),
        ExportKeyFormat::Pkcs1Der => (Some(KeyFormatType::PKCS1), false),
        ExportKeyFormat::Pkcs8Pem => (Some(KeyFormatType::PKCS8), true),
        ExportKeyFormat::Pkcs8Der => (Some(KeyFormatType::PKCS8), false),
    };
    (key_format_type, encode_to_pem)
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
    let (key_format_type, encode_to_pem) = get_export_key_format_type(key_format);
    let encode_to_ttlv = *key_format == ExportKeyFormat::JsonTtlv;

    let wrapping_cryptographic_parameters =
        wrapping_algorithm
            .as_ref()
            .map(|wrapping_algorithm| match wrapping_algorithm {
                WrappingAlgorithm::AESKeyWrapPadding => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    block_cipher_mode: Some(BlockCipherMode::AESKeyWrapPadding),
                    ..CryptographicParameters::default()
                },
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
                WrappingAlgorithm::RsaPkcsV15Sha1 => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    padding_method: Some(PaddingMethod::PKCS1v15),
                    hashing_algorithm: Some(HashingAlgorithm::SHA1),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::RsaOaep => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    padding_method: Some(PaddingMethod::OAEP),
                    hashing_algorithm: Some(HashingAlgorithm::SHA256),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::RsaOaepSha1 => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    padding_method: Some(PaddingMethod::OAEP),
                    hashing_algorithm: Some(HashingAlgorithm::SHA1),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::RsaAesKeyWrap => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    padding_method: Some(PaddingMethod::None),
                    hashing_algorithm: Some(HashingAlgorithm::SHA256),
                    ..CryptographicParameters::default()
                },
                WrappingAlgorithm::RsaAesKeyWrapSha1 => CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    padding_method: Some(PaddingMethod::None),
                    hashing_algorithm: Some(HashingAlgorithm::SHA1),
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

#[must_use]
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
        UniqueIdentifier::TextString(object_id_or_tags.to_owned()),
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

#[must_use]
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
        UniqueIdentifier::TextString(object_id_or_tags.to_owned()),
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
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_id.to_owned()),
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

// Certificate utils
#[derive(ValueEnum, Debug, Clone, PartialEq, Eq, EnumString, Default)]
pub enum CertificateExportFormat {
    JsonTtlv,
    #[default]
    Pem,
    Pkcs12,
    #[cfg(feature = "non-fips")]
    Pkcs12Legacy,
    Pkcs7,
}

#[must_use]
pub fn prepare_certificate_export_elements(
    output_format: &CertificateExportFormat,
    pkcs12_password: Option<String>,
) -> (KeyFormatType, Option<String>) {
    match output_format {
        CertificateExportFormat::JsonTtlv | CertificateExportFormat::Pem => {
            (KeyFormatType::X509, None)
        }
        CertificateExportFormat::Pkcs12 => (KeyFormatType::PKCS12, pkcs12_password),
        #[cfg(feature = "non-fips")]
        CertificateExportFormat::Pkcs12Legacy => (KeyFormatType::Pkcs12Legacy, pkcs12_password),
        CertificateExportFormat::Pkcs7 => (KeyFormatType::PKCS7, None),
    }
}
