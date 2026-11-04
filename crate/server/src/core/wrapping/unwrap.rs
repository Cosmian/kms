use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, State},
        kmip_2_1::{
            KmipOperation,
            extra::tagging::SYSTEM_TAG_PUBLIC_KEY,
            kmip_data_structures::{KeyBlock, KeyValue},
            kmip_objects::{Object, ObjectType},
            kmip_types::LinkType,
        },
    },
    cosmian_kms_crypto::crypto::wrap::{decode_unwrapped_key, unwrap_key_block},
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, warn};

use crate::{
    core::{KMS, uid_utils::ObjectHandle, wrapping::wrap::requested_hsm_algorithm},
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// Unwrap a caller-supplied Object (e.g. `Import` with `KeyWrapType::NotWrapped`).
///
/// The ciphertext is attacker-controlled, so the caller must be allowed to decrypt with the
/// unwrapping key, the server KEK included: otherwise the unwrap is a decryption oracle.
///
/// # Arguments
/// * `object` - the object to unwrap
/// * `kms` - the KMS
/// * `user` - the user accessing the unwrapping key
///
/// # Returns
/// * `KResult<()>` - the result of the operation
pub(crate) async fn unwrap_object(object: &mut Object, kms: &KMS, user: &UserId) -> KResult<()> {
    unwrap(object, kms, user, false).await
}

/// Unwrap an Object read from the server's own storage.
///
/// Same as [`unwrap_object`], except that the server `key_encryption_key`, when the key block
/// names it literally, is usable by every user: it wrapped the object at rest on their behalf
/// (mirrors `wrap_and_cache`).
pub(crate) async fn unwrap_stored_object(
    object: &mut Object,
    kms: &KMS,
    user: &UserId,
) -> KResult<()> {
    unwrap(object, kms, user, true).await
}

/// Check that `user` may unwrap the stored `object`, without unwrapping it.
///
/// Makes the same decision as [`unwrap_stored_object`], recursively for unwrapping keys that
/// are themselves wrapped, so that serving an unwrapped-cache hit is authorized exactly like a
/// cache miss, whoever warmed the cache.
pub(crate) async fn authorize_stored_unwrap(
    object: &Object,
    kms: &KMS,
    user: &UserId,
) -> KResult<()> {
    if !object.is_wrapped() {
        return Ok(());
    }
    let key_block = object.key_block().map_err(|e| {
        KmsError::InvalidRequest(format!(
            "unwrap_object: not key block to unwrap in object: {e}",
        ))
    })?;
    authorize_unwrapping_key(kms, user, &unwrapping_key_uid(key_block)?, true).await
}

/// Check that `user` may unwrap caller-supplied data with the key `unwrapping_key_uid`, the
/// server KEK included: the same decision as [`unwrap_object`], without unwrapping anything.
pub(crate) async fn authorize_unwrap_with(
    kms: &KMS,
    user: &UserId,
    unwrapping_key_uid: &str,
) -> KResult<()> {
    authorize_unwrapping_key(kms, user, unwrapping_key_uid, false).await
}

async fn authorize_unwrapping_key(
    kms: &KMS,
    user: &UserId,
    unwrapping_key_uid: &str,
    allow_server_kek: bool,
) -> KResult<()> {
    if ObjectHandle::from(unwrapping_key_uid).is_hsm() {
        authorize_oracle_unwrap(kms, user, unwrapping_key_uid, allow_server_kek).await?;
    } else {
        let unwrapping_key =
            authorized_kms_unwrapping_key(kms, user, unwrapping_key_uid, allow_server_kek).await?;
        // the unwrapping key is itself a stored object
        if unwrapping_key.object().is_wrapped() {
            Box::pin(authorize_stored_unwrap(unwrapping_key.object(), kms, user)).await?;
        }
    }
    Ok(())
}

async fn unwrap(
    object: &mut Object,
    kms: &KMS,
    user: &UserId,
    allow_server_kek: bool,
) -> KResult<()> {
    if !object.is_wrapped() {
        debug!("object is not wrapped, no need to unwrap");
        return Ok(());
    }
    let object_key_block = object.key_block_mut().map_err(|e| {
        KmsError::InvalidRequest(format!(
            "unwrap_object: not key block to unwrap in object: {e}",
        ))
    })?;
    let unwrapping_key_uid = unwrapping_key_uid(object_key_block)?;

    if let ObjectHandle::Hsm { prefix, .. } = ObjectHandle::from(&unwrapping_key_uid) {
        debug!(
            "...unwrapping the key block with key uid: {unwrapping_key_uid} using an encryption \
             oracle, user: {user}"
        );
        let oracle_key_uid =
            authorize_oracle_unwrap(kms, user, &unwrapping_key_uid, allow_server_kek).await?;
        unwrap_using_crypto_oracle(object_key_block, kms, &oracle_key_uid, prefix).await?;
    } else {
        debug!(
            "...unwrapping the key block with key uid: {unwrapping_key_uid} using the KMS, user: \
             {user}"
        );
        let unwrapping_key =
            authorized_kms_unwrapping_key(kms, user, &unwrapping_key_uid, allow_server_kek).await?;
        Box::pin(unwrap_using_kms(
            object_key_block,
            kms,
            user,
            &unwrapping_key,
        ))
        .await?;
    }
    debug!(
        "Key successfully unwrapped with wrapping key: {}",
        unwrapping_key_uid
    );

    Ok(())
}

/// The unique identifier of the key that wrapped `key_block`.
fn unwrapping_key_uid(key_block: &KeyBlock) -> KResult<String> {
    let key_wrapping_data = key_block.key_wrapping_data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("unwrap_object: key wrapping data is missing".to_owned())
    })?;
    Ok(key_wrapping_data
        .encryption_key_information
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "unwrap_object: encryption key information is missing".to_owned(),
            )
        })?
        .unique_identifier
        .to_string())
}

/// Is `uid`, the wrapping key UID recorded in a stored key block, the server
/// `key_encryption_key` (or its `_pk` public key), usable by every user (stored objects only)?
///
/// Literal match only: the key a UID resolves to through a link is never exempt, since the
/// link of a user-made public key or certificate is caller-controlled.
fn is_exempt_server_kek(kms: &KMS, allow_server_kek: bool, uid: &str) -> bool {
    allow_server_kek
        && kms
            .params
            .key_wrapping_key
            .as_deref()
            .is_some_and(|kek| uid.strip_suffix(SYSTEM_TAG_PUBLIC_KEY).unwrap_or(uid) == kek)
}

/// Fetch the database key `unwrapping_key_uid` (the private key for a public key or
/// certificate) and check `user` may unwrap with it: active, `UnwrapKey` usage, and owner,
/// default user, or `Decrypt`/`Get` grant — except for the server KEK on stored objects.
async fn authorized_kms_unwrapping_key(
    kms: &KMS,
    user: &UserId,
    unwrapping_key_uid: &str,
    allow_server_kek: bool,
) -> KResult<Arc<ObjectWithMetadata>> {
    // fetch the wrapping key
    let unwrapping_key = kms
        .database
        .retrieve_object_arc(unwrapping_key_uid)
        .await
        .context("wrap using KMS")?;
    let unwrapping_key = unwrapping_key.ok_or_else(|| {
        KmsError::NotSupported(format!(
            "The wrapping key {unwrapping_key_uid} does not exist or is not accessible."
        ))
    })?;
    // In the case the key is a PublicKey or Certificate, we need to fetch the corresponding private key
    let object_type = unwrapping_key.object().object_type();
    let unwrapping_key = match object_type {
        ObjectType::PrivateKey | ObjectType::SymmetricKey => unwrapping_key,
        ObjectType::PublicKey | ObjectType::Certificate => {
            // seek if we have a link to a private key
            let private_key_uid = unwrapping_key
                .attributes()
                .get_link(LinkType::PrivateKeyLink);
            let sk_id = if let Some(private_key_uid) = private_key_uid {
                private_key_uid.to_string()
            } else if let Some(stripped) = unwrapping_key_uid.strip_suffix(SYSTEM_TAG_PUBLIC_KEY) {
                stripped.to_owned()
            } else {
                kms_bail!(
                    "unwrap_key: no corresponding private key link found for the public key \
                     {unwrapping_key_uid}"
                );
            };
            let private_key = kms
                .database
                .retrieve_object_arc(&sk_id)
                .await
                .context("wrap using KMS")?
                .ok_or_else(|| {
                    KmsError::NotSupported(format!(
                        "The unwrapping private key {sk_id} does not exist or is not accessible \
                         for the public key {unwrapping_key_uid}"
                    ))
                })?;
            if private_key.object().object_type() != ObjectType::PrivateKey {
                return Err(KmsError::NotSupported(format!(
                    "The key {sk_id} linked to {unwrapping_key_uid} is not a private key"
                )));
            }
            private_key
        }
        _ => kms_bail!("unwrap_key: unsupported object type: {}", object_type),
    };
    // check active state
    if unwrapping_key.state() != State::Active {
        return Err(KmsError::NotSupported(format!(
            "The unwrapping key {unwrapping_key_uid} is not active"
        )));
    }
    // check authorized usage: the stored attributes are authoritative, the ones embedded in the
    // key value are absent when the unwrapping key is itself wrapped (mirrors `wrap_using_kms`)
    if !unwrapping_key
        .attributes()
        .is_usage_authorized_for(CryptographicUsageMask::UnwrapKey)?
    {
        return Err(KmsError::NotSupported(format!(
            "The key: {unwrapping_key_uid}, is not meant to unwrap keys"
        )));
    }
    // check user permissions on the resolved key; the server KEK wrapped stored objects on
    // behalf of every user (mirrors `wrap_using_kms`)
    if !is_exempt_server_kek(kms, allow_server_kek, unwrapping_key_uid)
        && unwrapping_key.owner() != user
        && user != kms.params.default_username.as_str()
    {
        let ops = kms
            .database
            .list_user_operations_on_object(unwrapping_key.id(), user, false)
            .await?;
        if !ops
            .iter()
            .any(|p| [KmipOperation::Decrypt, KmipOperation::Get].contains(p))
        {
            return Err(KmsError::NotSupported(format!(
                "The user {user} does not have the permission to unwrap with the key \
                 {unwrapping_key_uid}"
            )));
        }
    }
    Ok(unwrapping_key)
}

/// Unwrap a key block with an authorized database key (see [`authorized_kms_unwrapping_key`]).
async fn unwrap_using_kms(
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    user: &UserId,
    unwrapping_key: &ObjectWithMetadata,
) -> KResult<()> {
    // If the unwrapping key is itself wrapped (e.g. by the server KEK), unwrap it first
    let unwrapping_key_object = if unwrapping_key.object().is_wrapped() {
        debug!(
            "The unwrapping key {} is itself wrapped, unwrapping it first",
            unwrapping_key.id()
        );
        let mut object = unwrapping_key.object().clone();
        Box::pin(unwrap_stored_object(&mut object, kms, user)).await?;
        // the unwrapped key value carries no attributes: reattach the stored ones, which the
        // crypto layer reads to check the usage mask
        if let Some(KeyValue::Structure { attributes, .. }) = object
            .key_block_mut()
            .ok()
            .and_then(|key_block| key_block.key_value.as_mut())
        {
            if attributes.is_none() {
                *attributes = Some(unwrapping_key.attributes().clone());
            }
        }
        object
    } else {
        unwrapping_key.object().clone()
    };
    // ok => unwrap
    unwrap_key_block(object_key_block, &unwrapping_key_object)?;
    Ok(())
}

/// Check `user` may unwrap with the HSM key `unwrapping_key_uid` and return the key to
/// decrypt with (a public key UID is stripped of its `_pk` suffix).
///
/// Unwrapping decrypts with the HSM key: it requires the same explicit `Decrypt` grant (or HSM
/// ownership) as a direct KMIP Decrypt, except for the server KEK on stored objects.
async fn authorize_oracle_unwrap(
    kms: &KMS,
    user: &UserId,
    unwrapping_key_uid: &str,
    allow_server_kek: bool,
) -> KResult<String> {
    let oracle_key_uid = unwrapping_key_uid
        .strip_suffix(SYSTEM_TAG_PUBLIC_KEY)
        .unwrap_or(unwrapping_key_uid);
    if !is_exempt_server_kek(kms, allow_server_kek, unwrapping_key_uid)
        && !kms
            .is_user_authorized_with_get_wildcard(oracle_key_uid, user, KmipOperation::Decrypt)
            .await?
    {
        return Err(KmsError::Unauthorized(format!(
            "The user {user} does not have the permission to unwrap with the key \
             {oracle_key_uid}"
        )));
    }
    Ok(oracle_key_uid.to_owned())
}

/// Unwrap a key block with the authorized HSM key `unwrapping_key_uid` (see
/// [`authorize_oracle_unwrap`]) using the crypto oracle registered for `prefix`.
async fn unwrap_using_crypto_oracle(
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    unwrapping_key_uid: &str,
    prefix: &str,
) -> KResult<()> {
    // fetch the key wrapping data
    let key_wrapping_data = object_key_block.key_wrapping_data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("unwrap_key: key wrapping data is missing".to_owned())
    })?;

    // recover the wrapped key
    let Some(KeyValue::ByteString(wrapped_key)) = object_key_block.key_value.as_ref() else {
        kms_bail!("unable to unwrap key: key value is not a byte string")
    };

    // decrypt the wrapped key
    let requested = requested_hsm_algorithm(
        key_wrapping_data
            .encryption_key_information
            .as_ref()
            .and_then(|e| e.cryptographic_parameters.as_ref()),
    )?;
    let lock = kms.crypto_oracles.read().await;
    let crypto_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!("Encrypt: unknown crypto oracle prefix: {prefix}"))
    })?;
    let plaintext = match crypto_oracle
        .decrypt(unwrapping_key_uid, wrapped_key, requested.clone(), None)
        .await
    {
        Ok(plaintext) => plaintext,
        Err(e) if requested.is_some() => {
            // GCM tags, the KW/KWP integrity check and OAEP all fail closed on the wrong mode.
            warn!(
                "unwrap: declared {requested:?} failed for key wrapped by {unwrapping_key_uid} \
                 ({e}); retrying with the HSM default for objects wrapped before HSM wrapping \
                 honoured the requested mode"
            );
            crypto_oracle
                .decrypt(unwrapping_key_uid, wrapped_key, None, None)
                .await
                .map_err(|_retry_error| e)?
        }
        Err(e) => return Err(e.into()),
    };
    if let Some(metrics) = &kms.metrics {
        let model =
            crate::core::uid_utils::hsm_model_from_prefix(&kms.params.hsm_instances, prefix);
        metrics.record_hsm_operation("Unwrap", model);
    }

    // decode the unwrapped key
    let key_value = decode_unwrapped_key(
        key_wrapping_data.get_encoding(),
        object_key_block.key_format_type,
        plaintext,
    )?;

    // update the key block with the unwrapped key
    object_key_block.key_value = Some(key_value);
    object_key_block.key_wrapping_data = None;

    Ok(())
}
