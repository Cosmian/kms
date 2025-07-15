use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::{
        kmip_data_structures::KeyValue,
        kmip_objects::{
            Certificate, Object, OpaqueObject, PGPKey, PrivateKey, PublicKey, SecretData, SplitKey,
            SymmetricKey,
        },
        kmip_types::Digest,
    },
    ttlv::KmipFlavor,
};

use crate::result::KResult;

/// Returns the digest of the object as explained in KMIP 2.1 Digest attribute.
pub(crate) fn digest(object: &Object) -> KResult<Option<Digest>> {
    match object {
        Object::PublicKey(PublicKey { key_block })
        | Object::PrivateKey(PrivateKey { key_block })
        | Object::SecretData(SecretData { key_block, .. })
        | Object::PGPKey(PGPKey { key_block, .. })
        | Object::SymmetricKey(SymmetricKey { key_block })
        | Object::SplitKey(SplitKey { key_block, .. }) => {
            if let Some(key_value) = key_block.key_value.as_ref() {
                let bytes = match key_value {
                    KeyValue::ByteString(bytes) => bytes.to_vec(),
                    KeyValue::Structure { key_material, .. } => key_material
                        .to_ttlv(key_block.key_format_type)?
                        .to_bytes(KmipFlavor::Kmip2)?,
                };
                // digest  with openSSL SHA256
                let digest = openssl::sha::sha256(&bytes);
                Ok(Some(Digest {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    digest_value: Some(digest.to_vec()),
                    key_format_type: Some(key_block.key_format_type),
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
