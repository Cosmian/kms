use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::{KeyBlock, KeyWrappingSpecification},
    kmip_objects::ObjectType,
    kmip_types::{CryptographicUsageMask, LinkType, StateEnumeration},
    KmipOperation,
};
use cosmian_kms_crypto::crypto::wrap::{
    key_data_to_wrap, update_key_block_with_wrapped_key, wrap_key_block,
};
use cosmian_kms_server_database::SqlCipherSessionParams;
use tracing::debug;

use crate::{
    core::{uid_utils::has_prefix, KMS},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Wrap a key with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `object_key_block` - the key block of the object to wrap
/// * `key_wrapping_specification` - the key wrapping specification
/// * `kms` - the kms
/// * `user` - the user performing the call
/// * `params` - the extra database parameters
/// # Returns
/// * `KResult<()>` - the result of the operation
pub(crate) async fn wrap_key(
    object_key_block: &mut KeyBlock,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
    params: Option<&SqlCipherSessionParams>,
) -> KResult<()> {
    // recover the wrapping key uid
    let wrapping_key_uid = match &key_wrapping_specification.encryption_key_information {
        Some(eki) => eki
            .unique_identifier
            .as_str()
            .context("unable to wrap key: wrapping key uid is not a string")?,
        None => kms_bail!("unable to wrap key: wrapping key uid is missing"),
    };
    if let Some(prefix) = has_prefix(wrapping_key_uid) {
        debug!(
            "...wrapping the key block with key uid: {wrapping_key_uid} using an encryption \
             oracle, user: {user}"
        );
        wrap_using_encryption_oracle(
            object_key_block,
            key_wrapping_specification,
            kms,
            user,
            params,
            wrapping_key_uid,
            prefix,
        )
        .await?;
    } else {
        debug!(
            "...wrapping the key block with key uid: {wrapping_key_uid} using the KMS, user: \
             {user}"
        );
        wrap_using_kms(
            object_key_block,
            key_wrapping_specification,
            kms,
            user,
            params,
            wrapping_key_uid,
        )
        .await?;
    }
    debug!("Key wrapped successfully by key {}", wrapping_key_uid);
    Ok(())
}

/// Wrap a key with a wrapping key using a KMS
async fn wrap_using_kms(
    object_key_block: &mut KeyBlock,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
    params: Option<&SqlCipherSessionParams>,
    wrapping_key_uid: &str,
) -> Result<(), KmsError> {
    // fetch the wrapping key
    let wrapping_key = kms
        .database
        .retrieve_object(wrapping_key_uid, params)
        .await
        .context("wrap using KMS")?;
    let wrapping_key = wrapping_key.ok_or_else(|| {
        KmsError::NotSupported(format!(
            "The wrapping key {wrapping_key_uid} does not exist or is not accessible"
        ))
    })?;
    // in the case the key is a Private Key, we need to fetch the corresponding private key or certificate
    let object_type = wrapping_key.object().object_type();
    let wrapping_key = match object_type {
        ObjectType::PublicKey | ObjectType::Certificate | ObjectType::SymmetricKey => wrapping_key,
        ObjectType::PrivateKey => {
            let attributes = wrapping_key.attributes();
            let pk_id = attributes.get_link(LinkType::PublicKeyLink);
            let pk_id = pk_id.map_or_else(
                || wrapping_key_uid.to_owned() + "_pk",
                |pk_id| pk_id.to_string(),
            );
            // fetch the private key
            let wrapping_key = kms
                .database
                .retrieve_object(&pk_id, params)
                .await
                .context("wrapping using the KMS")?;
            wrapping_key.ok_or_else(|| {
                KmsError::NotSupported(format!(
                    "The wrapping public key {pk_id} does not exist or is not accessible for the \
                     private key {wrapping_key_uid}"
                ))
            })?
        }
        _ => kms_bail!("wrap_key: unsupported object type: {}", object_type),
    };
    if wrapping_key.state() != StateEnumeration::Active {
        return Err(KmsError::NotSupported(format!(
            "The wrapping key {wrapping_key_uid} is not active"
        )));
    }
    // Check usage mask for non Certificate objects
    //TODO: certs attributes should be checked instead
    if wrapping_key.object().object_type() != ObjectType::Certificate {
        let attributes = wrapping_key
            .object()
            .attributes()
            .cloned()
            .unwrap_or_default();
        if !attributes.is_usage_authorized_for(CryptographicUsageMask::WrapKey)? {
            return Err(KmsError::NotSupported(format!(
                "The key: {wrapping_key_uid} is not meant to wrap keys"
            )));
        }
    }
    if wrapping_key.owner() != user {
        let ops = kms
            .database
            .list_user_operations_on_object(wrapping_key.id(), user, false, params)
            .await?;
        if !ops
            .iter()
            .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
        {
            return Err(KmsError::NotSupported(format!(
                "The user {user} does not have the permission to wrap with the key \
                 {wrapping_key_uid}"
            )));
        }
    }
    debug!(
        "The user {user} can wrap with the key {wrapping_key_uid}. Encoding: {:?}, format: {}",
        key_wrapping_specification.get_encoding(),
        object_key_block.key_format_type
    );

    wrap_key_block(
        object_key_block,
        wrapping_key.object(),
        key_wrapping_specification,
    )?;
    Ok(())
}

/// Wrap a key with a wrapping key using an encryption oracle
async fn wrap_using_encryption_oracle(
    object_key_block: &mut KeyBlock,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
    params: Option<&SqlCipherSessionParams>,
    wrapping_key_uid: &str,
    prefix: &str,
) -> KResult<()> {
    //check permissions
    if !kms
        .database
        .is_object_owned_by(wrapping_key_uid, user, params)
        .await?
    {
        let ops = kms
            .database
            .list_user_operations_on_object(wrapping_key_uid, user, false, params)
            .await?;
        if !ops
            .iter()
            .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
        {
            return Err(KmsError::NotSupported(format!(
                "The user {user} does not have the permission to wrap the using the key \
                 {wrapping_key_uid}"
            )));
        }
    }
    let data_to_wrap = key_data_to_wrap(&object_key_block, key_wrapping_specification)?;
    let lock = kms.encryption_oracles.read().await;
    let encryption_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!(
            "Encrypt: unknown encryption oracle prefix: {prefix}"
        ))
    })?;
    let encrypted_content = encryption_oracle
        .encrypt(
            wrapping_key_uid,
            data_to_wrap.as_slice(),
            None,
            key_wrapping_specification.get_additional_authenticated_data(),
        )
        .await?;
    let wrapped_key = [
        encrypted_content.iv.clone().unwrap_or_default(),
        encrypted_content.ciphertext.clone(),
        encrypted_content.tag.unwrap_or_default(),
    ]
    .concat();
    update_key_block_with_wrapped_key(object_key_block, key_wrapping_specification, wrapped_key);
    Ok(())
}
