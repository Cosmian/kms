use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::KeyMaterial,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{CreateKeyPair, ErrorReason, Get},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType,
            RecommendedCurve,
        },
    },
};

use crate::crypto::curve_25519::operation::{
    to_curve_25519_256_private_key, to_curve_25519_256_public_key, PUBLIC_KEY_LENGTH,
    Q_LENGTH_BITS, SECRET_KEY_LENGTH,
};

/// Build a `CreateKeyPairRequest` for a curve 25519 key pair
#[must_use]
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
            link: None,
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

#[must_use]
pub fn get_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(uid.to_string()),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_data: None,
    }
}

#[must_use]
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
pub fn parse_public_key(bytes: &[u8]) -> Result<Object, KmipError> {
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Message,
            format!(
                "Invalid public key len: {}, it should be: {} bytes",
                bytes.len(),
                PUBLIC_KEY_LENGTH
            ),
        ))
    }
    Ok(to_curve_25519_256_public_key(bytes))
}

/// parse bytes as a curve 25519 private key
pub fn parse_private_key(bytes: &[u8]) -> Result<Object, KmipError> {
    if bytes.len() != SECRET_KEY_LENGTH {
        return Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Message,
            format!(
                "Invalid private key len: {}, it should be: {} bytes",
                bytes.len(),
                SECRET_KEY_LENGTH
            ),
        ))
    }
    Ok(to_curve_25519_256_private_key(bytes))
}

#[allow(non_snake_case)]
pub fn extract_key_bytes(pk: &Object) -> Result<Vec<u8>, KmipError> {
    let key_block = match pk {
        Object::PublicKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Object_Type,
                "Expected a KMIP Public Key".to_owned(),
            ))
        }
    };
    match &key_block.key_value.key_material {
        KeyMaterial::TransparentECPublicKey {
            recommended_curve: _,
            q_string: QString,
        } => Ok(QString.clone()),
        _ => Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Object_Type,
            "The provided object is not an Elliptic Curve Public Key".to_owned(),
        )),
    }
}
