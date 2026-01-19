use cosmian_kms_server_database::{
    CachedUnwrappedObject,
    reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::{CryptographicUsageMask, State},
            kmip_2_1::{
                KmipOperation,
                kmip_attributes::Attributes,
                kmip_data_structures::{KeyValue, KeyWrappingSpecification},
                kmip_objects::{Object, ObjectType},
                kmip_types::{
                    EncodingOption, EncryptionKeyInformation, LinkType, UniqueIdentifier,
                },
            },
        },
        cosmian_kms_crypto::crypto::wrap::{key_data_to_wrap, wrap_object_with_key},
    },
};
use cosmian_logger::{debug, trace, warn};

use crate::{
    core::{KMS, uid_utils::has_prefix, wrapping::unwrap_object},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Wrap the object and store the unwrapped object in the unwrapped cache
///
/// This is a Cosmian-specific extension
/// to wrap the key with a wrapping key stored in the database
/// or in the HSM.
/// Either the user has provided a wrapping key ID or a key wrapping key is
/// supplied in the parameters.
///
/// The wrapping key ID is stored in the database
/// or in the HSM.
///
/// The unwrapped object is stored in the unwrapped cache
///
/// # Arguments
///
/// * `kms` - The KMS instance
/// * `owner` - The owner of the object
/// * `params` - The parameters to use
/// * `unique_identifier` - The unique identifier of the object
/// * `object` - The object to wrap
pub(crate) async fn wrap_and_cache(
    kms: &KMS,
    owner: &str,
    unique_identifier: &UniqueIdentifier,
    object: &mut Object,
) -> Result<(), KmsError> {
    if object.is_wrapped() {
        // The object is already wrapped
        return Ok(());
    }

    // This is a Cosmian-specific extension
    // to wrap the key with a wrapping key stored in the database
    // or in the HSM.
    // Either the user has provided a wrapping key ID or a key wrapping key is
    // provided in the parameters.
    let Some(wrapping_key_id) = object
        .attributes_mut()
        .ok()
        .and_then(Attributes::remove_wrapping_key_id)
        .or_else(|| kms.params.key_wrapping_key.clone())
    else {
        // no wrapping key provided
        return Ok(());
    };

    // Cannot wrap yourself
    if wrapping_key_id == unique_identifier.to_string() {
        if kms.params.key_wrapping_key.is_none() {
            warn!("Key {wrapping_key_id} attempted to wrap itself");
        }
        return Ok(());
    }

    // This is useful to store a key on the default data store but wrapped by a key stored in an HSM
    // extract the wrapping key id
    // make a copy of the unwrapped key
    let unwrapped_object = object.clone();

    // The KMIP specification defaults to TTLV encoding,
    // but most HSMs will not be able
    // to handle the larger number of bytes
    // this entails.
    // So If we can recover bytes from a symmetric key, we
    // use the more compact No Encoding, otherwise we use the default TTLV Encoding.
    let encoding = if object
        .key_block()
        .map_err(|e| {
            KmsError::InvalidRequest(format!("wrap_object: no key block to wrap in object: {e}",))
        })?
        .key_bytes()
        .is_ok()
    {
        EncodingOption::NoEncoding
    } else {
        EncodingOption::TTLVEncoding
    };

    trace!("Wrapping key with id: {wrapping_key_id}");
    // wrap the current object
    Box::pin(wrap_object(
        object,
        &KeyWrappingSpecification {
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(wrapping_key_id),
                cryptographic_parameters: None,
            }),
            encoding_option: Some(encoding),
            ..Default::default()
        },
        kms,
        owner,
    ))
    .await?;

    // store the unwrapped object in the unwrapped cache
    kms.database
        .unwrapped_cache()
        .insert(
            unique_identifier.to_string(),
            Ok(CachedUnwrappedObject::new(
                object.fingerprint()?,
                unwrapped_object,
            )),
        )
        .await;
    Ok(())
}

/// Wrap an Object with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `object` - the object to wrap
/// * `key_wrapping_specification` - the key wrapping specification
/// * `kms` - the kms
/// * `user` - the user performing the call
/// * `params` - the extra database parameters
/// # Returns
/// * `KResult<()>` - the result of the operation
pub(crate) async fn wrap_object(
    object: &mut Object,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
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
            object,
            key_wrapping_specification,
            kms,
            user,
            wrapping_key_uid,
            prefix,
        )
        .await?;
    } else {
        debug!(
            "...wrapping the key block with key uid: {wrapping_key_uid} using the KMS, user: \
             {user}"
        );
        Box::pin(wrap_using_kms(
            object,
            key_wrapping_specification,
            kms,
            user,
            wrapping_key_uid,
        ))
        .await?;
    }
    debug!("Key wrapped successfully by key {}", wrapping_key_uid);
    Ok(())
}

/// Wrap a key with a wrapping key using a KMS
async fn wrap_using_kms(
    object: &mut Object,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
    wrapping_key_uid: &str,
) -> KResult<()> {
    trace!("Checking permissions to wrap with key {wrapping_key_uid}");
    // fetch the wrapping key
    let wrapping_key = kms
        .database
        .retrieve_object(wrapping_key_uid)
        .await
        .context("wrap using KMS")?;
    let wrapping_key = wrapping_key.ok_or_else(|| {
        KmsError::NotSupported(format!(
            "The wrapping key {wrapping_key_uid} does not exist or is not accessible"
        ))
    })?;
    trace!("Wrapping key retrieved successfully: {wrapping_key}");

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
                .retrieve_object(&pk_id)
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
    if wrapping_key.state() != State::Active {
        return Err(KmsError::NotSupported(format!(
            "The wrapping key {wrapping_key_uid} is not active"
        )));
    }
    if wrapping_key.owner() != user {
        let ops = kms
            .database
            .list_user_operations_on_object(wrapping_key.id(), user, false)
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

    // If the wrapping key is itself wrapped, we must unwrap it first
    let mut wrapping_key_object = if wrapping_key.object().is_wrapped() {
        debug!("The wrapping key {wrapping_key_uid} is itself wrapped, unwrapping it first");
        let mut wrapping_key_object = wrapping_key.object().clone();
        unwrap_object(&mut wrapping_key_object, kms, user).await?;
        wrapping_key_object.clone()
    } else {
        wrapping_key.object().clone()
    };

    // If unwrap produced a KeyValue::Structure without attributes, reattach attributes
    // from the ObjectWithMetadata (database) when available so lower-level crypto code
    // can read them via KMIP accessors without triggering attribute-missing errors.
    #[allow(clippy::collapsible_match)]
    if let Ok(kb) = wrapping_key_object.key_block_mut() {
        if let Some(kv) = &mut kb.key_value {
            if let KeyValue::Structure { attributes, .. } = kv {
                if attributes.is_none() {
                    // copy object-with-metadata attributes into the unwrapped key value
                    let attrs = wrapping_key.attributes().clone();
                    *attributes = Some(attrs);
                }
            }
        }
    }

    // Check usage mask for non Certificate objects (after potential unwrap)
    trace!("Checking usage mask for wrapping key {wrapping_key_uid}");
    // TODO: certs attributes should be checked instead
    if wrapping_key_object.object_type() != ObjectType::Certificate {
        if !wrapping_key
            .attributes()
            .is_usage_authorized_for(CryptographicUsageMask::WrapKey)?
        {
            return Err(KmsError::NotSupported(format!(
                "The key: {wrapping_key_uid} is not meant to wrap keys"
            )));
        }
        trace!("The wrapping key {wrapping_key_uid} is authorized to wrap keys");
    }

    debug!(
        "The user: {user}, is authorized to wrap with the key {wrapping_key_uid}. Encoding: {:?}, \
         format: {}",
        key_wrapping_specification.get_encoding(),
        object.key_block()?.key_format_type
    );
    // wrap the object
    wrap_object_with_key(object, &wrapping_key_object, key_wrapping_specification)?;
    Ok(())
}

/// Wrap a key with a wrapping key using an encryption oracle
async fn wrap_using_encryption_oracle(
    object: &mut Object,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
    wrapping_key_uid: &str,
    prefix: &str,
) -> KResult<()> {
    // check permissions
    if !kms
        .database
        .is_object_owned_by(wrapping_key_uid, user)
        .await?
    {
        let ops = kms
            .database
            .list_user_operations_on_object(wrapping_key_uid, user, false)
            .await?;
        if !ops
            .iter()
            .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
        {
            return Err(KmsError::NotSupported(format!(
                "The user {user} does not have the permission to wrap using the key \
                 {wrapping_key_uid}"
            )));
        }
    }

    // Determine the key data to wrap based on the key format type and encoding
    let data_to_wrap = key_data_to_wrap(object, key_wrapping_specification)?;

    // encrypt the key using the encryption oracle
    let lock = kms.encryption_oracles.read().await;
    let encryption_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!(
            "Encrypt: unknown encryption oracle prefix: {prefix}"
        ))
    })?;
    let encrypted_content = encryption_oracle
        .encrypt(wrapping_key_uid, data_to_wrap.as_slice(), None, None)
        .await?;

    let wrapped_key = [
        encrypted_content.iv.clone().unwrap_or_default(),
        encrypted_content.ciphertext.clone(),
        encrypted_content.tag.unwrap_or_default(),
    ]
    .concat();

    // update the key block with the wrapped key
    let object_key_block = object.key_block_mut()?;
    object_key_block.key_value = Some(KeyValue::ByteString(wrapped_key.into()));
    object_key_block.key_wrapping_data = Some(key_wrapping_specification.get_key_wrapping_data());

    Ok(())
}
