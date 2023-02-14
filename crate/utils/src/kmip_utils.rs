// use cosmian_crypto_base::{kdf::hkdf_256, key_wrapping, typenum};
use cosmian_crypto_core::kdf;
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::KeyBlock,
        kmip_objects::{Object, ObjectType},
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, LinkType, LinkedObjectIdentifier},
    },
};

use crate::crypto::key_wrapping;

pub fn tag_from_object(object: &Object) -> String {
    // this is required to match the Java library behavior which expects
    // the first tag to describe the type of object and not simply equal 'Object'
    // TODO: check what is specified by the KMIP norm if any
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

const WRAPPING_SECRET_LENGTH: usize = 32;

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret = kdf!(WRAPPING_SECRET_LENGTH, wrapping_password.as_bytes());
    key_wrapping::wrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}

/// Unwrap a key using a password
pub fn unwrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret = kdf!(WRAPPING_SECRET_LENGTH, wrapping_password.as_bytes());
    key_wrapping::unwrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}

/// Extract the attributes from the given `KeyBlock`
/// Return an empty set of attributes if none are available
pub fn attributes_from_key_block(
    object_type: ObjectType,
    key_block: &KeyBlock,
) -> Result<Attributes, KmipError> {
    Ok(key_block
        .key_value
        .attributes()
        .map_or(Attributes::new(object_type), |attrs| {
            let mut attributes = attrs.clone();
            attributes.set_object_type(object_type);
            attributes
        }))
}

/// Extract the Key bytes from the given `KeyBlock`
pub fn key_bytes_and_attributes_from_key_block<'a>(
    key_block: &'a KeyBlock,
    uid: &'a str,
) -> Result<(&'a [u8], Option<&'a Attributes>), KmipError> {
    let key = key_block.key_value.raw_bytes().map_err(|e| {
        KmipError::InvalidKmipValue(ErrorReason::Invalid_Data_Type, format!("Uid: {uid} - {e}"))
    })?;
    Ok((key, key_block.key_value.attributes.as_ref()))
}

/// Get public key uid from private key uid
pub fn public_key_unique_identifier_from_private_key(
    private_key: &Object,
) -> Result<String, KmipError> {
    let key_block = match private_key {
        Object::PrivateKey { key_block } => key_block,
        _ => {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "KmipError KMIP Private Key".to_owned(),
            ))
        }
    };

    let attributes = key_block.key_value.attributes()?;
    let links = match &attributes.link {
        Some(links) => links,
        None => {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "Invalid public key. Should at least contain the link to private key".to_string(),
            ))
        }
    };
    if links.is_empty() {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Object_Type,
            "Invalid public key. Should at least contain the link to private key".to_string(),
        ))
    }

    links
        .iter()
        .find(|&link| link.link_type == LinkType::PublicKeyLink)
        .map_or_else(
            || {
                Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    "Private key MUST contain a public key link".to_string(),
                ))
            },
            |link| match &link.linked_object_identifier {
                LinkedObjectIdentifier::TextString(s) => Ok(s.clone()),
                LinkedObjectIdentifier::Enumeration(_) => Err(KmipError::NotSupported(
                    "Enumeration not yet supported".to_owned(),
                )),
                LinkedObjectIdentifier::Index(_) => Err(KmipError::NotSupported(
                    "Index not yet supported".to_owned(),
                )),
            },
        )
}
