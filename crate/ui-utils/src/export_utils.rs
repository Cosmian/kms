use cosmian_kmip::kmip_2_1::{
    kmip_objects::{Object, ObjectType},
    kmip_types::KeyFormatType,
};
use pem::{EncodeConfig, LineEnding};
use zeroize::Zeroizing;

use crate::error::UtilsError;

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
