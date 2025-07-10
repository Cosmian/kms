use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, HashingAlgorithm, State},
        kmip_2_1::{
            KmipOperation,
            kmip_data_structures::KeyValue,
            kmip_objects::{
                Certificate, Object, OpaqueObject, PGPKey, PrivateKey, PublicKey, SecretData,
                SplitKey, SymmetricKey,
            },
            kmip_types::Digest,
        },
        ttlv::KmipFlavor,
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
use tracing::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

//TODO This function should probably not be a free standing function KMS side,
// and should be refactored as part of Database,

/// Retrieve a single object for a given operation type
/// or the Get operation if not found..
///
/// When tags are provided, the function will return the first object
/// that matches the tags and the operation type.
///
/// This function assumes that if the user can `Get` the object,
/// then it can also do any other operation with it.
pub(crate) async fn retrieve_object_for_operation(
    uid_or_tags: &str,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<ObjectWithMetadata> {
    trace!(
        "get_key: key_uid_or_tags: {uid_or_tags:?}, user: {user}, operation_type: \
         {operation_type:?}"
    );

    for owm in kms
        .database
        .retrieve_objects(uid_or_tags, params.clone())
        .await?
        .values()
    {
        let state = owm.state();
        if !(state == State::Active
            || state == State::PreActive
            || operation_type == KmipOperation::Export)
        {
            continue
        }

        if user_has_permission(user, Some(owm), &operation_type, kms, params.clone()).await? {
            let mut owm = owm.to_owned();
            let mut dgst = None;
            // update the state and the digest on the object attributes if not present
            if owm.attributes().state.is_none() {
                owm.attributes_mut().state = Some(state);
            }
            if owm.attributes().digest.is_none() {
                if let Some(digest) = digest(owm.object())? {
                    dgst = Some(digest.clone());
                    owm.attributes_mut().digest = Some(digest);
                }
            }
            if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                // update the state on the object attributes if not present
                if attributes.state.is_none() {
                    attributes.state = Some(state);
                }
                // update the digest on the object attributes if not present
                if attributes.digest.is_none() {
                    attributes.digest = dgst;
                }
            }
            return Ok(owm)
        }
    }

    Err(KmsError::Kmip21Error(
        ErrorReason::Object_Not_Found,
        format!("object not found for identifier {uid_or_tags}",),
    ))
}

/// Check if a user has permission to perform an operation on an object.
///  If the user is the owner of the object, it will always return true.
///  If the user has the `Get` permission, it will always return true.
///  Otherwise, it will check the permissions in the database.
///  # Arguments
///  * `user` - The user to check the permission for.
///  * `owm` - The object to check the permission on.
///  * `operation_type` - The operation to check the permission for.
///  * `kms` - The KMS instance.
///  * `params` - The extra store params.
///  # Returns
///  * `Ok(true)` if the user has permission to perform the operation on the object.
///  * `Ok(false)` if the user does not have permission to perform the operation on the object.
pub(crate) async fn user_has_permission(
    user: &str,
    owm: Option<&ObjectWithMetadata>,
    operation_type: &KmipOperation,
    kms: &KMS,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<bool> {
    let id = match owm {
        Some(object) if user == object.owner() => return Ok(true),
        Some(object) => object.id(),
        None => "*",
    };

    let permissions = kms
        .database
        .list_user_operations_on_object(id, user, false, params)
        .await?;
    Ok(permissions.contains(operation_type) || permissions.contains(&KmipOperation::Get))
}

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
