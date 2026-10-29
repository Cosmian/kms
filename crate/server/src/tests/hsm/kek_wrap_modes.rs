//! HSM wrapping keys honour the requested wrapping mode and record the mode actually used.

use std::sync::Arc;

use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{BlockCipherMode, KeyWrapType},
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyValue, KeyWrappingSpecification},
            kmip_objects::{Object, ObjectType},
            kmip_operations::{Export, Import},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, EncodingOption,
                EncryptionKeyInformation, UniqueIdentifier, WrappingMethod,
            },
        },
    },
    cosmian_kms_crypto::crypto::symmetric::{rfc3394::rfc3394_unwrap, rfc5649::rfc5649_unwrap},
};
use uuid::Uuid;

use crate::{
    core::{KMS, wrapping::ensure_kek_wrapping},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::{
        hsm::{create_kek, create_sym_key, export_object, hsm_clap_config},
        test_utils::{get_tmp_sqlite_path, test_kms_with_config},
    },
};

pub(super) async fn test_hsm_kek_wrap_modes() -> KResult<()> {
    let owner = Uuid::new_v4().to_string();
    let mut clap_config = hsm_clap_config(&owner, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = test_kms_with_config(clap_config).await?;

    let kek_uid = as_hsm_uid!(slot, Uuid::new_v4());
    create_kek(&kek_uid, &owner, &kms).await?;
    let kek_bytes = key_bytes(&export_object(&kms, &owner, &kek_uid).await?)?;

    let dek_uid = Uuid::new_v4().to_string();
    create_sym_key(&dek_uid, &owner, &kms).await?;
    let dek_bytes = key_bytes(&export_object(&kms, &owner, &dek_uid).await?)?;

    let mut gcm_export = None;
    for (requested, expected) in [
        (None, BlockCipherMode::GCM),
        (
            Some(BlockCipherMode::NISTKeyWrap),
            BlockCipherMode::NISTKeyWrap,
        ),
        (
            Some(BlockCipherMode::AESKeyWrapPadding),
            BlockCipherMode::AESKeyWrapPadding,
        ),
        (Some(BlockCipherMode::GCM), BlockCipherMode::GCM),
    ] {
        let wrapped = export_wrapped(&kms, &owner, &dek_uid, &kek_uid, requested).await?;
        let params = wrapping_params(&wrapped)?;
        assert_eq!(params.block_cipher_mode, Some(expected), "{requested:?}");
        assert_eq!(
            params.cryptographic_algorithm,
            Some(CryptographicAlgorithm::AES)
        );

        let wrapped_bytes = wrapped_bytes(&wrapped)?;
        match expected {
            BlockCipherMode::AESKeyWrapPadding => {
                assert_eq!(*rfc5649_unwrap(&wrapped_bytes, &kek_bytes)?, dek_bytes);
            }
            BlockCipherMode::NISTKeyWrap => {
                assert_eq!(*rfc3394_unwrap(&wrapped_bytes, &kek_bytes)?, dek_bytes);
            }
            _ => {}
        }

        assert_eq!(
            import_unwrapped(&kms, &owner, wrapped.clone()).await?,
            dek_bytes
        );
        if requested == Some(BlockCipherMode::GCM) {
            gcm_export = Some(wrapped);
        }
    }

    // Objects wrapped before HSM wrapping honoured the requested mode claim AES-KWP but
    // hold AES-GCM bytes: unwrapping falls back to the HSM default.
    let mut legacy = gcm_export.ok_or_else(|| KmsError::Default("no GCM export".to_owned()))?;
    if let Some(eki) = legacy
        .key_block_mut()?
        .key_wrapping_data
        .as_mut()
        .and_then(|kwd| kwd.encryption_key_information.as_mut())
    {
        eki.cryptographic_parameters = Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::AESKeyWrapPadding),
            ..Default::default()
        });
    }
    assert_eq!(import_unwrapped(&kms, &owner, legacy).await?, dek_bytes);
    drop(kms);

    // At rest, the server KEK records the HSM default it actually used.
    let kek_uuid = Uuid::new_v4();
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    let server_kek = as_hsm_uid!(slot, kek_uuid);
    let kms = test_kms_with_config(clap_config).await?;
    create_kek(&server_kek, &owner, &kms).await?;
    let key_uid = Uuid::new_v4().to_string();
    create_sym_key(&key_uid, &owner, &kms).await?;
    let stored = stored_object(&kms, &key_uid).await?;
    let params = wrapping_params(&stored)?;
    assert_eq!(
        params.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(params.block_cipher_mode, Some(BlockCipherMode::GCM));
    drop(kms);

    // At rest with an operator-selected AES-KWP: the stored bytes are RFC 5649 under the KEK.
    // The KEK, created by this KMS version, already carries CKA_WRAP/CKA_UNWRAP.
    let kek_uuid = Uuid::new_v4();
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    clap_config.key_encryption_key_wrapping_algorithm = Some("aes-key-wrap-padding".to_owned());
    let server_kek = as_hsm_uid!(slot, kek_uuid);
    let kms = test_kms_with_config(clap_config).await?;
    create_kek(&server_kek, &owner, &kms).await?;
    ensure_kek_wrapping(&kms).await?;
    let kek_bytes = key_bytes(&export_object(&kms, &owner, &server_kek).await?)?;
    let key_uid = Uuid::new_v4().to_string();
    create_sym_key(&key_uid, &owner, &kms).await?;
    let stored = stored_object(&kms, &key_uid).await?;
    let params = wrapping_params(&stored)?;
    assert_eq!(
        params.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(
        params.block_cipher_mode,
        Some(BlockCipherMode::AESKeyWrapPadding)
    );
    let key_bytes_plain = key_bytes(&export_unwrapped(&kms, &owner, &key_uid).await?)?;
    assert_eq!(
        *rfc5649_unwrap(&wrapped_bytes(&stored)?, &kek_bytes)?,
        key_bytes_plain
    );
    drop(kms);

    // A KEK created before AES templates carried CKA_WRAP/CKA_UNWRAP gets them at startup.
    let kek_uuid = Uuid::new_v4();
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    clap_config.key_encryption_key_wrapping_algorithm = Some("aes-key-wrap-padding".to_owned());
    let legacy_kek = as_hsm_uid!(slot, kek_uuid);
    let kms = test_kms_with_config(clap_config).await?;
    create_kek(&legacy_kek, &owner, &kms).await?;
    // `as_hsm_uid!` builds legacy `hsm::<slot>::<id>` UIDs, routed to the `hsm` oracle.
    kms.crypto_oracles
        .read()
        .await
        .get("hsm")
        .ok_or_else(|| KmsError::Default("no crypto oracle for prefix hsm".to_owned()))?
        .set_key_wrap(&legacy_kek, false)
        .await?;
    ensure_kek_wrapping(&kms).await?;
    let key_uid = Uuid::new_v4().to_string();
    create_sym_key(&key_uid, &owner, &kms).await?;
    let stored = stored_object(&kms, &key_uid).await?;
    assert_eq!(
        wrapping_params(&stored)?.block_cipher_mode,
        Some(BlockCipherMode::AESKeyWrapPadding)
    );
    assert_eq!(
        key_bytes(&export_unwrapped(&kms, &owner, &key_uid).await?)?.len(),
        32
    );

    Ok(())
}

async fn export_unwrapped(kms: &Arc<KMS>, owner: &str, uid: &str) -> KResult<Object> {
    let request = Export {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_wrapping_specification: None,
    };
    Ok(kms.export(request, &UserId::from(owner)).await?.object)
}

fn wrapped_bytes(object: &Object) -> KResult<Vec<u8>> {
    let Some(KeyValue::ByteString(bytes)) = &object.key_block()?.key_value else {
        return Err(KmsError::Default(
            "wrapped key is not a byte string".to_owned(),
        ));
    };
    Ok(bytes.to_vec())
}

fn key_bytes(object: &Object) -> KResult<Vec<u8>> {
    Ok(object.key_block()?.key_bytes()?.to_vec())
}

fn wrapping_params(object: &Object) -> KResult<CryptographicParameters> {
    object
        .key_block()?
        .key_wrapping_data
        .as_ref()
        .and_then(|kwd| kwd.encryption_key_information.as_ref())
        .and_then(|eki| eki.cryptographic_parameters.clone())
        .ok_or_else(|| KmsError::Default("missing wrapping parameters".to_owned()))
}

async fn stored_object(kms: &Arc<KMS>, uid: &str) -> KResult<Object> {
    Ok(kms
        .database
        .retrieve_object(uid)
        .await?
        .ok_or_else(|| KmsError::Default(format!("{uid} not stored")))?
        .object()
        .clone())
}

async fn export_wrapped(
    kms: &Arc<KMS>,
    owner: &str,
    uid: &str,
    kek_uid: &str,
    mode: Option<BlockCipherMode>,
) -> KResult<Object> {
    let request = Export {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: None,
        key_wrapping_specification: Some(KeyWrappingSpecification {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(kek_uid.to_owned()),
                cryptographic_parameters: mode.map(|m| CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    block_cipher_mode: Some(m),
                    ..Default::default()
                }),
            }),
            encoding_option: Some(EncodingOption::NoEncoding),
            ..Default::default()
        }),
    };
    Ok(kms.export(request, &UserId::from(owner)).await?.object)
}

/// Import `wrapped` with server-side unwrap and return the plaintext key bytes.
async fn import_unwrapped(kms: &Arc<KMS>, owner: &str, wrapped: Object) -> KResult<Vec<u8>> {
    let uid = Uuid::new_v4().to_string();
    kms.import(
        Import {
            unique_identifier: UniqueIdentifier::TextString(uid.clone()),
            object_type: ObjectType::SymmetricKey,
            replace_existing: Some(true),
            key_wrap_type: Some(KeyWrapType::NotWrapped),
            attributes: Attributes::default(),
            object: wrapped,
        },
        &UserId::from(owner),
    )
    .await?;
    key_bytes(&export_object(kms, owner, &uid).await?)
}
