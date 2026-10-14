use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask, State},
        kmip_2_1::{
            KmipOperation,
            extra::tagging::SYSTEM_TAG_PUBLIC_KEY,
            kmip_data_structures::{KeyValue, KeyWrappingSpecification},
            kmip_objects::{Object, ObjectType},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, EncodingOption,
                EncryptionKeyInformation, LinkType, UniqueIdentifier,
            },
        },
    },
    cosmian_kms_crypto::crypto::wrap::{key_data_to_wrap, wrap_object_with_key},
    cosmian_kms_interfaces::{CryptoAlgorithm, EncryptedContent, KeyType},
};
use cosmian_logger::{debug, info, trace, warn};
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS,
        uid_utils::ObjectHandle,
        wrapping::{authorize_unwrap_with, unwrap_stored_object},
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// Wrap the object using a wrapping key from the database or HSM, then cache the unwrapped copy.
///
/// An object that is already wrapped is stored as-is. If its wrapping key is the server
/// `key_encryption_key`, storing it amounts to asking the server to decrypt it with the KEK
/// (stored objects are unwrapped with the KEK on behalf of any user, see
/// `unwrap_stored_object`): it is only accepted from a user allowed to decrypt with the KEK.
pub(crate) async fn wrap_and_cache(
    kms: &KMS,
    owner: &UserId,
    unique_identifier: &UniqueIdentifier,
    object: &mut Object,
) -> Result<(), KmsError> {
    if object.is_wrapped() {
        reject_server_kek_wrapped(kms, owner, object).await?;
        return Ok(());
    }

    // This is a Cosmian-specific extension
    // to wrap the key with a wrapping key stored in the database
    // or in the HSM.
    // Either the user has provided a wrapping key ID or a key wrapping key is
    // provided in the parameters.
    let uid_str = unique_identifier.to_string();
    let explicit_wrapping_key_id = object
        .attributes_mut()
        .ok()
        .and_then(|attrs| attrs.remove_wrapping_key_id(kms.vendor_id()));
    let wrapping_key_id = if let Some(id) = explicit_wrapping_key_id {
        id
    } else {
        let Some(kek) = kms.params.key_wrapping_key.clone() else {
            // no wrapping key provided
            return Ok(());
        };
        // HSM-resident keys are hardware-protected: skip the server-wide KEK wrapping
        // to avoid creating a circular dependency where the KEK would wrap itself.
        if ObjectHandle::from(&uid_str).is_hsm() {
            return Ok(());
        }
        kek
    };

    // A key cannot be its own wrapping key.
    if wrapping_key_id == uid_str {
        return Err(KmsError::InvalidRequest(format!(
            "Key '{wrapping_key_id}' cannot be used as its own wrapping key: \
             the wrapping key ID must differ from the key ID being created"
        )));
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
            KmsError::InvalidRequest(format!("wrap_object: no key block to wrap in object: {e}"))
        })?
        .key_bytes()
        .is_ok()
    {
        EncodingOption::NoEncoding
    } else {
        EncodingOption::TTLVEncoding
    };

    trace!("Wrapping key with id: {wrapping_key_id}");
    // An operator-selected algorithm applies to the server KEK. Otherwise, HSM wrapping
    // keys default to the HSM's own mode (AES-GCM / RSA-OAEP), and software keys use
    // AESKeyWrapPadding (RFC 5649) at rest: it handles arbitrary key lengths (including
    // < 16 bytes), unlike the Get-with-wrapping default NISTKeyWrap (RFC 3394) which
    // requires input >= 16 bytes.
    let configured = kms
        .params
        .key_wrapping_algorithm
        .as_ref()
        .filter(|_| kms.params.key_wrapping_key.as_deref() == Some(wrapping_key_id.as_str()));
    let cryptographic_parameters = match configured {
        Some(params) => Some(params.clone()),
        None if ObjectHandle::from(wrapping_key_id.as_str()).is_hsm() => None,
        None => Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::AESKeyWrapPadding),
            ..CryptographicParameters::default()
        }),
    };
    // wrap the current object
    Box::pin(wrap_object(
        object,
        &KeyWrappingSpecification {
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(wrapping_key_id),
                cryptographic_parameters,
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
        .insert(unique_identifier.to_string(), object, unwrapped_object)
        .await?;

    Ok(())
}

/// HSM algorithm requested by KMIP parameters; `None` = HSM default (AES-GCM / RSA-OAEP-SHA256).
pub(super) fn requested_hsm_algorithm(
    params: Option<&CryptographicParameters>,
) -> KResult<Option<CryptoAlgorithm>> {
    let Some(params) = params.filter(|p| {
        p.cryptographic_algorithm.is_some()
            || p.block_cipher_mode.is_some()
            || p.padding_method.is_some()
    }) else {
        return Ok(None);
    };
    let mut p = params.clone();
    if p.cryptographic_algorithm.is_none() {
        p.cryptographic_algorithm = Some(if p.block_cipher_mode.is_some() {
            CryptographicAlgorithm::AES
        } else {
            CryptographicAlgorithm::RSA
        });
    }
    Ok(CryptoAlgorithm::from_kmip(&p)?)
}

/// Wrapped-key bytes as stored and as oracle `decrypt` expects them:
/// `[iv ‖ ciphertext ‖ tag]` (AES-KW/KWP and RSA have neither iv nor tag).
fn pack_wrapped(content: &EncryptedContent) -> Vec<u8> {
    let iv = content.iv.as_deref().unwrap_or_default();
    let tag = content.tag.as_deref().unwrap_or_default();
    [iv, content.ciphertext.as_slice(), tag].concat()
}

/// Startup check: an HSM AES key encryption key must be able to wrap with its configured
/// mode (AES-KW, AES-KWP or AES-GCM, the default). For AES-KW/KWP, a failed probe enables
/// `CKA_WRAP`/`CKA_UNWRAP` once on the KEK and retries.
pub(crate) async fn ensure_kek_wrapping(kms: &KMS) -> KResult<()> {
    let Some(kek) = kms.params.key_wrapping_key.as_deref() else {
        return Ok(());
    };
    let ObjectHandle::Hsm { prefix, .. } = ObjectHandle::from(kek) else {
        return Ok(());
    };
    let oracles = kms.crypto_oracles.read().await;
    let oracle = oracles.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!("unknown crypto oracle prefix: {prefix}"))
    })?;
    let alg = match requested_hsm_algorithm(kms.params.key_wrapping_algorithm.as_ref())? {
        Some(
            a @ (CryptoAlgorithm::AesKeyWrap
            | CryptoAlgorithm::AesKeyWrapPad
            | CryptoAlgorithm::AesGcm),
        ) => a,
        // A KEK that does not exist yet keeps failing on first use, as before this check.
        None if matches!(oracle.get_key_type(kek).await, Ok(Some(KeyType::AesKey))) => {
            CryptoAlgorithm::AesGcm
        }
        _ => return Ok(()),
    };
    let probe = async || -> KResult<()> {
        let mut buf = Zeroizing::new(vec![0_u8; 32]);
        kms.rng.fill_bytes(&mut buf)?;
        let ct = oracle
            .encrypt(kek, &buf, Some(alg.clone()), None, None)
            .await?;
        let pt = oracle
            .decrypt(kek, &pack_wrapped(&ct), Some(alg.clone()), None)
            .await?;
        if *pt != *buf {
            kms_bail!("wrap/unwrap probe returned different bytes");
        }
        Ok(())
    };
    let Err(e1) = probe().await else {
        return Ok(());
    };
    if alg == CryptoAlgorithm::AesGcm {
        return Err(KmsError::ServerError(format!(
            "key_encryption_key {kek}: AES-GCM wrapping failed on this HSM: {e1}. Set \
             key_encryption_key_wrapping_algorithm = \"aes-key-wrap-padding\" (NIST SP \
             800-38F) or \"aes-key-wrap\""
        )));
    }
    if let Err(e2) = oracle.set_key_wrap(kek, true).await {
        return Err(KmsError::ServerError(format!(
            "key_encryption_key {kek} cannot wrap with {alg:?}: {e1}; enabling \
             CKA_WRAP/CKA_UNWRAP was refused by the HSM: {e2}. Create a new HSM key \
             encryption key with this KMS version or set \
             key_encryption_key_wrapping_algorithm = \"aes-gcm\""
        )));
    }
    info!("Enabled CKA_WRAP/CKA_UNWRAP on HSM key encryption key {kek} for {alg:?}");
    if let Err(e3) = probe().await {
        // Do not leave a widened key behind when the migration did not fix the wrapping.
        if let Err(e4) = oracle.set_key_wrap(kek, false).await {
            warn!("could not restore CKA_WRAP/CKA_UNWRAP on HSM key {kek}: {e4}");
        }
        return Err(KmsError::ServerError(format!(
            "key_encryption_key {kek} cannot wrap with {alg:?} on this HSM: {e3}. Set \
             key_encryption_key_wrapping_algorithm = \"aes-gcm\""
        )));
    }
    Ok(())
}

/// Refuse an already-wrapped object whose wrapping key is, or resolves to, the server
/// `key_encryption_key` unless `user` may decrypt with the KEK — the same decision as an
/// Import with `KeyWrapType::NotWrapped`.
async fn reject_server_kek_wrapped(kms: &KMS, user: &UserId, object: &Object) -> KResult<()> {
    let Some(kek) = kms.params.key_wrapping_key.as_deref() else {
        return Ok(());
    };
    // `to_string`, as `unwrap` does: a numeric UID must not slip through
    let Some(wrapping_key_uid) = object
        .key_block()
        .ok()
        .and_then(|key_block| key_block.key_wrapping_data.as_ref())
        .and_then(|data| data.encryption_key_information.as_ref())
        .map(|info| info.unique_identifier.to_string())
    else {
        return Ok(());
    };
    if !resolves_to_server_kek(kms, kek, &wrapping_key_uid).await? {
        return Ok(());
    }
    // refusals become the import error; storage or HSM failures propagate unchanged
    authorize_unwrap_with(kms, user, &wrapping_key_uid)
        .await
        .map_err(|e| match e {
            KmsError::Unauthorized(_) | KmsError::NotSupported(_) => KmsError::InvalidRequest(
                "Keys wrapped by the server key encryption key can only be imported by users \
                 allowed to decrypt with it: import the key unwrapped (key wrap type \
                 NotWrapped), or wrapped by another key"
                    .to_owned(),
            ),
            other => other,
        })
}

/// Does unwrapping with `uid` decrypt with the server KEK `kek`: `uid` is the KEK, its `_pk`
/// public key, or a public key / certificate whose `PrivateKeyLink` points at the KEK?
async fn resolves_to_server_kek(kms: &KMS, kek: &str, uid: &str) -> KResult<bool> {
    if uid.strip_suffix(SYSTEM_TAG_PUBLIC_KEY).unwrap_or(uid) == kek {
        return Ok(true);
    }
    if ObjectHandle::from(uid).is_hsm() {
        return Ok(false);
    }
    let Some(key) = kms
        .database
        .retrieve_object_arc(uid)
        .await
        .context("resolve the wrapping key")?
    else {
        return Ok(false);
    };
    Ok(matches!(
        key.object().object_type(),
        ObjectType::PublicKey | ObjectType::Certificate
    ) && key
        .attributes()
        .get_link(LinkType::PrivateKeyLink)
        .is_some_and(|link| link.to_string() == kek))
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
    user: &UserId,
) -> KResult<()> {
    // recover the wrapping key uid
    let wrapping_key_uid = match &key_wrapping_specification.encryption_key_information {
        Some(eki) => eki
            .unique_identifier
            .as_str()
            .context("unable to wrap key: wrapping key uid is not a string")?,
        None => kms_bail!("unable to wrap key: wrapping key uid is missing"),
    };
    if let ObjectHandle::Hsm { prefix, .. } = ObjectHandle::from(wrapping_key_uid) {
        debug!(
            "...wrapping the key block with key uid: {wrapping_key_uid} using an encryption \
             oracle, user: {user}"
        );
        wrap_using_crypto_oracle(
            object,
            key_wrapping_specification,
            kms,
            user,
            ObjectHandle::from(wrapping_key_uid),
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
            ObjectHandle::from(wrapping_key_uid),
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
    user: &UserId,
    handle: ObjectHandle<'_>,
) -> KResult<()> {
    let wrapping_key_uid = handle.as_str();
    trace!("Checking permissions to wrap with key {wrapping_key_uid}");
    // fetch the wrapping key
    let wrapping_key = kms
        .database
        .retrieve_object_arc(wrapping_key_uid)
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
                || wrapping_key_uid.to_owned() + SYSTEM_TAG_PUBLIC_KEY,
                |pk_id| pk_id.to_string(),
            );
            // fetch the private key
            let wrapping_key = kms
                .database
                .retrieve_object_arc(&pk_id)
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
    // The server-configured key_encryption_key is a shared server resource accessible
    // to all users, so skip the ownership check for it (mirrors the bypass in
    // `wrap_using_crypto_oracle` — issue #761).
    let is_server_kek = kms
        .params
        .key_wrapping_key
        .as_deref()
        .is_some_and(|kek| kek == wrapping_key_uid);
    // Permission comes before any check on the key itself (state, usage mask): those errors
    // would otherwise reveal the state of another user's key.
    if !is_server_kek && wrapping_key.owner() != user {
        let ops = kms
            .database
            .list_user_operations_on_object(wrapping_key.id(), user, false)
            .await?;
        if !ops
            .iter()
            .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
        {
            return Err(KmsError::Unauthorized(format!(
                "The user {user} does not have the permission to wrap with the key \
                 {wrapping_key_uid}"
            )));
        }
    }
    if wrapping_key.state() != State::Active {
        return Err(KmsError::NotSupported(format!(
            "The wrapping key {wrapping_key_uid} is not active"
        )));
    }

    // If the wrapping key is itself wrapped, we must unwrap it first
    let mut wrapping_key_object = if wrapping_key.object().is_wrapped() {
        debug!("The wrapping key {wrapping_key_uid} is itself wrapped, unwrapping it first");
        let mut obj = wrapping_key.object().clone();
        Box::pin(unwrap_stored_object(&mut obj, kms, user)).await?;
        obj
    } else {
        wrapping_key.object().clone()
    };

    // If unwrap produced a KeyValue::Structure without attributes, reattach attributes
    // from the ObjectWithMetadata (database) when available so lower-level crypto code
    // can read them via KMIP accessors without triggering attribute-missing errors.
    if let Ok(kb) = wrapping_key_object.key_block_mut() {
        if let Some(KeyValue::Structure { attributes, .. }) = &mut kb.key_value {
            if attributes.is_none() {
                // copy object-with-metadata attributes into the unwrapped key value
                let attrs = wrapping_key.attributes().clone();
                *attributes = Some(attrs);
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
    wrap_object_with_key(
        object,
        &wrapping_key_object,
        key_wrapping_specification,
        &kms.rng,
    )?;
    Ok(())
}

/// Wrap a key with a wrapping key using a crypto oracle
async fn wrap_using_crypto_oracle(
    object: &mut Object,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &UserId,
    handle: ObjectHandle<'_>,
    prefix: &str,
) -> KResult<()> {
    let wrapping_key_uid = handle.as_str();
    // The server-configured key_encryption_key is a shared server resource accessible
    // to all users, so skip the ownership check for it (issue #761).
    let is_server_kek = kms
        .params
        .key_wrapping_key
        .as_deref()
        .is_some_and(|kek| kek == wrapping_key_uid);
    // Wrapping encrypts with the HSM key: require the same explicit `Encrypt` grant (or HSM
    // ownership) as a direct KMIP Encrypt — `Get` is no wildcard for HSM keys.
    if !is_server_kek
        && !kms
            .is_user_authorized_with_get_wildcard(wrapping_key_uid, user, KmipOperation::Encrypt)
            .await?
    {
        return Err(KmsError::Unauthorized(format!(
            "The user {user} does not have the permission to wrap using the key \
             {wrapping_key_uid}"
        )));
    }

    // Determine the key data to wrap based on the key format type and encoding
    let data_to_wrap = key_data_to_wrap(object, key_wrapping_specification)?;
    let requested = requested_hsm_algorithm(
        key_wrapping_specification
            .encryption_key_information
            .as_ref()
            .and_then(|e| e.cryptographic_parameters.as_ref()),
    )?;

    // encrypt the key using the crypto oracle
    let lock = kms.crypto_oracles.read().await;
    let crypto_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!("Encrypt: unknown crypto oracle prefix: {prefix}"))
    })?;
    let encrypted_content = crypto_oracle
        .encrypt(
            wrapping_key_uid,
            data_to_wrap.as_slice(),
            requested,
            None,
            None,
        )
        .await?;
    if let Some(ref metrics) = kms.metrics {
        let model =
            crate::core::uid_utils::hsm_model_from_prefix(&kms.params.hsm_instances, prefix);
        metrics.record_hsm_operation("Wrap", model);
    }

    let wrapped_key = pack_wrapped(&encrypted_content);

    // record the mode actually used, which may be the HSM default
    let mut key_wrapping_data = key_wrapping_specification.get_key_wrapping_data();
    if let Some(algorithm) = &encrypted_content.cryptographic_algorithm {
        key_wrapping_data.encryption_key_information = Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_uid.to_owned()),
            cryptographic_parameters: Some(algorithm.to_kmip()),
        });
    }

    // update the key block with the wrapped key
    let object_key_block = object.key_block_mut()?;
    object_key_block.key_value = Some(KeyValue::ByteString(wrapped_key.into()));
    object_key_block.key_wrapping_data = Some(key_wrapping_data);

    Ok(())
}
