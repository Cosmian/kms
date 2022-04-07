#![allow(dead_code)]

use cosmian_kmip::kmip::{
    kmip_data_structures::KeyMaterial,
    kmip_objects::{Object, ObjectType},
    kmip_operations::{CreateKeyPair, ErrorReason, Get},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType,
        RecommendedCurve,
    },
};
use cosmian_kms_utils::crypto::curve_25519::{self, PUBLIC_KEY_LENGTH, Q_LENGTH_BITS};

use crate::{error::KmsError, kms_error, result::KResult};

/// Build a `CreateKeyPairRequest` for a curve 25519 key pair
pub fn create_key_pair_request() -> CreateKeyPair {
    CreateKeyPair {
        common_attributes: Some(Attributes {
            activation_date: None,
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_length: Some(Q_LENGTH_BITS),
            cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                q_length: Some(Q_LENGTH_BITS),
                recommended_curve: Some(RecommendedCurve::CURVE25519),
            }),
            cryptographic_parameters: None,
            cryptographic_usage_mask: None,
            key_format_type: Some(KeyFormatType::ECPrivateKey),
            link: vec![],
            object_type: ObjectType::PrivateKey,
            vendor_attributes: None,
        }),
        private_key_attributes: None,
        public_key_attributes: None,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    }
}

pub fn get_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(uid.to_string()),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_data: None,
    }
}

pub fn get_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(uid.to_string()),
        key_format_type: Some(KeyFormatType::TransparentECPublicKey),
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_data: None,
    }
}

/// parse bytes as a curve 25519 public key
pub fn parse_public_key(bytes: &[u8]) -> KResult<Object> {
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(kms_error!(
            "Invalid public key len: {}, it should be: {} bytes",
            bytes.len(),
            PUBLIC_KEY_LENGTH
        )
        .reason(ErrorReason::Invalid_Message))
    }
    Ok(curve_25519::to_curve_25519_256_public_key(bytes))
}

/// parse bytes as a curve 25519 private key
pub fn parse_private_key(bytes: &[u8]) -> KResult<Object> {
    if bytes.len() != curve_25519::SECRET_KEY_LENGTH {
        return Err(kms_error!(
            "Invalid private key len: {}, it should be: {} bytes",
            bytes.len(),
            curve_25519::SECRET_KEY_LENGTH
        )
        .reason(ErrorReason::Invalid_Message))
    }
    Ok(curve_25519::to_curve_25519_256_private_key(bytes))
}

#[allow(non_snake_case)]
pub fn extract_key_bytes(pk: &Object) -> KResult<Vec<u8>> {
    let key_block = match pk {
        Object::PublicKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Public Key".to_owned(),
            ))
        }
    };
    let (key_material, _) = key_block.key_value.plaintext().ok_or_else(|| {
        KmsError::ServerError("The public key should be a plain text key value".to_owned())
            .reason(ErrorReason::Invalid_Object_Type)
    })?;
    match key_material {
        KeyMaterial::TransparentECPublicKey {
            recommended_curve: _,
            q_string: QString,
        } => Ok(QString.clone()),
        _ => Err(KmsError::ServerError(
            "The provided object is not an Elliptic Curve Public Key".to_owned(),
        )
        .reason(ErrorReason::Invalid_Object_Type)),
    }
}
