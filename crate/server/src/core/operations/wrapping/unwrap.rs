use cosmian_kmip::{
    crypto::wrap::unwrap_key_block,
    kmip::{kmip_data_structures::KeyBlock, kmip_objects::ObjectType, kmip_types::LinkType},
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::debug;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::retrieve_object_for_operation,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Unwrap a key
/// This function is used to unwrap a key before storing it in the database
///
/// # Arguments
/// * `object_key_block`    - the key block of the object to unwrap
/// * `kms`                 - the KMS
/// * `user`                - the user accessing the unwrapping key
/// * `params`              - the extra database parameters
///
/// # Returns
/// * `KResult<()>`         - the result of the operation
pub(crate) async fn unwrap_key(
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    let unwrapping_key_uid = match &object_key_block.key_wrapping_data {
        Some(kwd) => match &kwd.encryption_key_information {
            Some(eki) => eki.unique_identifier.to_string(),
            None => kms_bail!("unwrap_key: unable to unwrap key: unwrapping key uid is missing"),
        },
        None => kms_bail!("unwrap_key: unable to unwrap key: key wrapping data is missing"),
    };

    debug!("unwrapping_key_uid: {unwrapping_key_uid}");
    debug!("user: {user}");

    // fetch the unwrapping key
    let unwrapping_key = retrieve_object_for_operation(
        &unwrapping_key_uid,
        ObjectOperationType::Decrypt,
        kms,
        user,
        params,
    )
    .await?;

    // in the case the key is a PublicKey or Certificate, we need to fetch the corresponding private key
    let object_type = unwrapping_key.object.object_type();
    let unwrapping_key = match object_type {
        ObjectType::PrivateKey | ObjectType::SymmetricKey => unwrapping_key,
        ObjectType::PublicKey | ObjectType::Certificate => {
            let attributes = match object_type {
                ObjectType::PublicKey | ObjectType::Certificate => unwrapping_key.attributes,
                _ => kms_bail!("unwrap_key: unsupported object type: {object_type}"),
            };
            let private_key_uid =
                attributes
                    .get_link(LinkType::PrivateKeyLink)
                    .with_context(|| {
                        format!("no corresponding private key link found for the {object_type}")
                    })?;
            // fetch the private key
            retrieve_object_for_operation(
                &private_key_uid.to_string(),
                ObjectOperationType::Decrypt,
                kms,
                user,
                params,
            )
            .await?
        }
        _ => kms_bail!("unwrap_key: unsupported object type: {}", object_type),
    };

    // Check on key CryptographicUsageMask is done inside `unwrap_key_block`.
    unwrap_key_block(object_key_block, &unwrapping_key.object)?;

    Ok(())
}
