use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::{
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{
                Certificate, Object, OpaqueObject, PGPKey, PrivateKey, PublicKey, SecretData,
                SplitKey, SymmetricKey,
            },
            kmip_types::{Digest, KeyFormatType},
        },
        ttlv::KmipFlavor,
    },
    cosmian_kms_crypto::openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
};
use cosmian_logger::trace;

use super::export_get::{
    openssl_private_key_to_kmip_default_format, openssl_public_key_to_kmip_default_format,
};
use crate::result::KResult;

/// Returns the digest of the object as explained in KMIP 2.1 Digest attribute.
pub(super) fn digest(object: &Object) -> KResult<Option<Digest>> {
    match object {
        Object::PublicKey(PublicKey { key_block })
        | Object::PrivateKey(PrivateKey { key_block })
        | Object::SecretData(SecretData { key_block, .. })
        | Object::PGPKey(PGPKey { key_block, .. })
        | Object::SymmetricKey(SymmetricKey { key_block })
        | Object::SplitKey(SplitKey { key_block, .. }) => {
            if let Some(key_value) = key_block.key_value.as_ref() {
                trace!("processing key_value");
                let bytes = match key_value {
                    KeyValue::ByteString(bytes) => bytes.to_vec(),
                    KeyValue::Structure { key_material, .. } => {
                        trace!("key_material key format: {:?}", key_block.key_format_type);
                        match key_material {
                            // KMIP 2.1 KeyValue::Structure with ByteString
                            KeyMaterial::ByteString(bytes) => bytes.to_vec(),
                            // KMIP 2.1 KeyValue::Structure with Structure
                            _ => key_material
                                .to_ttlv(key_block.key_format_type)?
                                .to_bytes(KmipFlavor::Kmip2)?,
                        }
                    }
                };
                // digest  with openSSL SHA256
                let digest = openssl::sha::sha256(&bytes);
                // Report the digest KeyFormatType according to KMIP profiles expectations.
                // - For RSA Transparent formats, advertise PKCS_1 as the digest key format type.
                // - For Symmetric Keys, KMIP default digest format is Raw.
                let reported_kft = match key_block.key_format_type {
                    KeyFormatType::TransparentRSAPrivateKey
                    | KeyFormatType::TransparentRSAPublicKey => KeyFormatType::PKCS1,
                    other => {
                        if matches!(object, Object::SymmetricKey(_)) {
                            KeyFormatType::Raw
                        } else {
                            other
                        }
                    }
                };
                Ok(Some(Digest {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    digest_value: Some(digest.to_vec()),
                    key_format_type: Some(reported_kft),
                }))
            } else {
                Ok(None)
            }
        }
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => {
            // digest with openSSL SHA256
            let digest = openssl::sha::sha256(certificate_value);
            Ok(Some(Digest {
                hashing_algorithm: HashingAlgorithm::SHA256,
                digest_value: Some(digest.to_vec()),
                key_format_type: None,
            }))
        }
        Object::CertificateRequest(_) => Ok(None),
        Object::OpaqueObject(OpaqueObject {
            opaque_data_value, ..
        }) => {
            // digest with openSSL SHA256
            let digest = openssl::sha::sha256(opaque_data_value);
            Ok(Some(Digest {
                hashing_algorithm: HashingAlgorithm::SHA256,
                digest_value: Some(digest.to_vec()),
                key_format_type: None,
            }))
        }
    }
}

/// KMIP 2.1 §4.21 Digest of a registered object: the mandatory SHA-256 of the Key Material in
/// the default Key Format Type of its object type and algorithm (§4.26 Table 81), preceded, when
/// the key was registered in another format, by the SHA-256 of the Key Material as registered.
/// Asymmetric keys OpenSSL cannot convert get the registered-format digest only; other objects
/// get [`digest`].
pub(super) fn registration_digests(object: &Object) -> KResult<Option<Vec<Digest>>> {
    let default_format = match object {
        Object::PrivateKey(PrivateKey { key_block }) if key_block.key_wrapping_data.is_none() => {
            kmip_private_key_to_openssl(object)
                .ok()
                .and_then(|key| openssl_private_key_to_kmip_default_format(&key, None).ok())
        }
        Object::PublicKey(PublicKey { key_block }) if key_block.key_wrapping_data.is_none() => {
            kmip_public_key_to_openssl(object)
                .ok()
                .and_then(|key| openssl_public_key_to_kmip_default_format(&key, None).ok())
        }
        _ => return Ok(digest(object)?.map(|d| vec![d])),
    };
    let registered = key_block_digest(object.key_block()?)?;
    let default = match default_format {
        Some(default_object) => key_block_digest(default_object.key_block()?)?,
        None => None,
    };
    Ok(match (registered, default) {
        (Some(registered), Some(default))
            if registered.key_format_type != default.key_format_type =>
        {
            Some(vec![registered, default])
        }
        (_, Some(default)) => Some(vec![default]),
        (registered, None) => registered.map(|d| vec![d]),
    })
}

/// SHA-256 of the Key Material of `key_block` (§4.21: the Byte String, else the TTLV-encoded
/// structure), labelled with the key block's own Key Format Type.
fn key_block_digest(key_block: &KeyBlock) -> KResult<Option<Digest>> {
    let bytes = match key_block.key_value.as_ref() {
        None => return Ok(None),
        Some(
            KeyValue::ByteString(bytes)
            | KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                ..
            },
        ) => bytes.to_vec(),
        Some(KeyValue::Structure { key_material, .. }) => key_material
            .to_ttlv(key_block.key_format_type)?
            .to_bytes(KmipFlavor::Kmip2)?,
    };
    Ok(Some(Digest {
        hashing_algorithm: HashingAlgorithm::SHA256,
        digest_value: Some(openssl::sha::sha256(&bytes).to_vec()),
        key_format_type: Some(key_block.key_format_type),
    }))
}
