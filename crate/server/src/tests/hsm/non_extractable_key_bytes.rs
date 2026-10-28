use std::sync::Arc;

use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        kmip_data_structures::KeyWrappingSpecification,
        kmip_operations::{Export, Get},
        kmip_types::{EncryptionKeyInformation, UniqueIdentifier, WrappingMethod},
    },
};
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::{
        hsm::{
            delete_key,
            export_key_bytes::create_hsm_aes_key,
            export_object, hsm_clap_config,
            symmetric_dek::{symmetric_decrypt, symmetric_encrypt},
        },
        test_utils::get_tmp_sqlite_path,
    },
};

/// The error a caller must see when asking for the bytes of a non-extractable HSM key.
fn assert_sensitive_denied<T>(result: KResult<T>, what: &str) {
    match result {
        Err(KmsError::Kmip21Error(ErrorReason::Sensitive, _)) => {}
        Err(e) => panic!("{what}: expected a KMIP Sensitive error, got: {e}"),
        Ok(_) => panic!("{what}: a non-extractable HSM key must not be exportable"),
    }
}

/// An HSM AES key created with `sensitive = true` (`CKA_SENSITIVE=true`,
/// `CKA_EXTRACTABLE=false`) never leaves the HSM:
/// - `Export` and `Get`, plain or wrapped, are refused with a KMIP `Sensitive` error;
/// - the HSM refuses to hand over `CKA_VALUE`, so the object the server holds for it is a
///   metadata-only stub with an empty key value;
/// - the key stays usable through the HSM (encrypt/decrypt) without its bytes ever being read.
pub(super) async fn test_hsm_non_extractable_key_bytes() -> KResult<()> {
    let owner = Uuid::new_v4().to_string();
    let user = UserId::from(owner.as_str());
    let mut clap_config = hsm_clap_config(&owner, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    let uid = as_hsm_uid!(slot, Uuid::new_v4());
    create_hsm_aes_key(&kms, &owner, &uid, true).await?;

    // plain Export and Get are refused
    assert_sensitive_denied(export_object(&kms, &owner, &uid).await, "Export");
    assert_sensitive_denied(
        kms.get(
            Get::new(UniqueIdentifier::TextString(uid.clone()), false, None, None),
            &user,
        )
        .await,
        "Get",
    );

    // the HSM itself refused the read: what the server holds is an empty stub, not the key
    let stub = kms
        .database
        .retrieve_object_arc(&uid)
        .await?
        .ok_or_else(|| KmsError::ServerError("HSM key not found".to_owned()))?;
    assert_eq!(stub.attributes().sensitive, Some(true));
    assert!(
        stub.object().key_block()?.key_bytes()?.is_empty(),
        "the server must not hold the bytes of a non-extractable HSM key"
    );

    // the key is still usable inside the HSM
    let data = b"use the HSM key without extracting it";
    let ciphertext = symmetric_encrypt(&uid, &owner, &kms, data).await?;
    assert_eq!(ciphertext.len(), 12 + 16 + data.len());
    assert_eq!(
        symmetric_decrypt(&uid, &owner, &kms, &ciphertext).await?,
        data
    );

    // wrapping the key with another HSM key must not get it out either
    let wrapping_uid = as_hsm_uid!(slot, Uuid::new_v4());
    create_hsm_aes_key(&kms, &owner, &wrapping_uid, false).await?;
    let wrapped = kms
        .export(
            Export {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                key_format_type: None,
                key_compression_type: None,
                key_wrap_type: None,
                key_wrapping_specification: Some(KeyWrappingSpecification {
                    wrapping_method: WrappingMethod::Encrypt,
                    encryption_key_information: Some(EncryptionKeyInformation {
                        unique_identifier: UniqueIdentifier::TextString(wrapping_uid.clone()),
                        cryptographic_parameters: None,
                    }),
                    ..Default::default()
                }),
            },
            &user,
        )
        .await;
    assert_sensitive_denied(wrapped, "wrapped Export");

    delete_key(&wrapping_uid, &owner, &kms).await?;
    delete_key(&uid, &owner, &kms).await?;
    Ok(())
}
