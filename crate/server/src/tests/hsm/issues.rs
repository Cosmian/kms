/// Server-side regression tests for HSM-related GitHub issues.
///
/// - Issue #761: Non-admin users could not wrap keys using the server-configured
///   `key_encryption_key` because `wrap_using_crypto_oracle()` incorrectly
///   checked ownership rather than whether the key is the shared server KEK.
///
/// - Issue #762: `ckms sym keys unwrap -i hsm::<slot>::<label>` would fail with
///   "This key is sensitive and cannot be exported from the HSM" because the CLI
///   tried to export the HSM wrapping key locally.  The server-side fix routes
///   the unwrap through an `Import` operation with `key_wrap_type = NotWrapped`
///   so the KMS crypto-oracle handles the decryption transparently.
use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType as Kmip21ObjectType,
        kmip_operations::{Destroy, Export, Import, Operation},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::{
        hsm::{
            EMPTY_TAGS, create_kek, delete_key, export_object, hsm_clap_config, revoke_key,
            send_message,
        },
        test_utils::get_tmp_sqlite_path,
    },
};

/// Issue #761 — Non-admin users are allowed to wrap keys using a server-level KEK.
///
/// Before the fix, `wrap_using_crypto_oracle()` checked `is_object_owned_by(kek, user)` which
/// returned `false` for any non-hsm-admin user, causing "permission denied" errors when a regular
/// user tried to create a DEK with `wrapping_key_id = server_kek`.
pub(super) async fn test_non_admin_kek_wrapping() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let admin = Uuid::new_v4().to_string();
    let non_admin = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();
    let mut clap_config = hsm_clap_config(&admin, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Admin creates the KEK on the HSM.
    create_kek(&kek_uid, &admin, &kms).await?;

    // Non-admin user creates a DEK wrapped with the shared server KEK.
    // Before fix #761 this would fail with a permission-denied error.
    let dek_uid = Uuid::new_v4().to_string();
    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(dek_uid.clone())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        Some(&kek_uid),
    )?;
    let response = send_message(
        kms.clone(),
        &non_admin,
        vec![Operation::Create(create_request)],
    )
    .await?;
    let Operation::CreateResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert_eq!(
        create_response.unique_identifier,
        UniqueIdentifier::TextString(dek_uid.clone())
    );

    // Export the DEK — it must be wrapped.
    let exported = export_object(&kms, &non_admin, &dek_uid).await?;
    assert_eq!(exported.object_type(), ObjectType::SymmetricKey);
    assert!(
        exported.is_wrapped(),
        "DEK must be stored wrapped by the server KEK"
    );

    // Cleanup.
    revoke_key(&dek_uid, &non_admin, &kms).await?;
    delete_key(&dek_uid, &non_admin, &kms).await?;
    delete_key(&kek_uid, &admin, &kms).await?;

    Ok(())
}

/// Issue #762 — A key wrapped by an HSM KEK can be unwrapped server-side via Import.
///
/// The previous CLI path tried to export the HSM KEK locally (which fails for sensitive keys).
/// The fix uses `Import` with `key_wrap_type = NotWrapped` so the server's crypto oracle
/// handles decryption without ever exposing the KEK material.
pub(super) async fn test_server_side_unwrap() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let admin = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();
    let mut clap_config = hsm_clap_config(&admin, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Admin creates the KEK on the HSM.
    create_kek(&kek_uid, &admin, &kms).await?;

    // Create a DEK wrapped by the HSM KEK.
    let dek_uid = Uuid::new_v4().to_string();
    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(dek_uid.clone())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        Some(&kek_uid),
    )?;
    send_message(kms.clone(), &admin, vec![Operation::Create(create_request)]).await?;

    // Export the wrapped DEK — it must be wrapped.
    let wrapped_dek = export_object(&kms, &admin, &dek_uid).await?;
    assert!(
        wrapped_dek.is_wrapped(),
        "DEK must be wrapped at this point"
    );

    // Re-import the wrapped DEK with key_wrap_type=NotWrapped.
    // The server crypto oracle unwraps it transparently using the HSM KEK.
    let tmp_uid = Uuid::new_v4().to_string();
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(tmp_uid.clone()),
        object_type: Kmip21ObjectType::SymmetricKey,
        replace_existing: Some(true),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        attributes: Attributes::default(),
        object: wrapped_dek,
    };
    let import_response = kms.import(import_request, &admin, None).await?;
    assert_eq!(
        import_response.unique_identifier,
        UniqueIdentifier::TextString(tmp_uid.clone())
    );

    // Export the re-imported key requesting the plaintext form.
    // The server may have re-wrapped the key for secure storage (when key_wrapping_key is
    // configured), so we must explicitly request key_wrap_type=NotWrapped on export to
    // retrieve the plaintext from the server's unwrapped cache.
    let export_request = Export {
        unique_identifier: Some(UniqueIdentifier::TextString(tmp_uid.clone())),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_wrapping_specification: None,
    };
    let unwrapped_dek = kms.export(export_request, &admin).await?.object;
    assert_eq!(unwrapped_dek.object_type(), ObjectType::SymmetricKey);
    assert!(
        !unwrapped_dek.is_wrapped(),
        "DEK must be unwrapped after server-side import with NotWrapped"
    );

    // Cleanup.
    revoke_key(&dek_uid, &admin, &kms).await?;
    delete_key(&dek_uid, &admin, &kms).await?;
    delete_key(&tmp_uid, &admin, &kms).await?;
    delete_key(&kek_uid, &admin, &kms).await?;

    Ok(())
}

/// Issue #763 — Destroying an HSM key is guarded by `expected_object_type`.
///
/// When `Destroy.expected_object_type` is provided and the target UID is an HSM key
/// (prefixed with `hsm::`), the server performs a PKCS#11 roundtrip to verify the
/// actual key type before proceeding. A mismatch (e.g. trying to destroy an AES key
/// with `expected_object_type = PrivateKey`) must be rejected with `Invalid_Object_Type`.
pub(super) async fn test_hsm_destroy_type_guard() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let admin = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();
    let mut clap_config = hsm_clap_config(&admin, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path;
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Create a symmetric (AES) key on the HSM.
    create_kek(&kek_uid, &admin, &kms).await?;

    // Attempt to destroy the AES key with the wrong expected type (PrivateKey).
    // The server must reject this via the PKCS#11 type-check roundtrip.
    let destroy_wrong_type = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
        remove: true,
        cascade: true,
        expected_object_type: Some(Kmip21ObjectType::PrivateKey),
    };
    let result = send_message(
        kms.clone(),
        &admin,
        vec![Operation::Destroy(destroy_wrong_type)],
    )
    .await;
    assert!(
        result.is_err(),
        "Expected type-mismatch error when destroying an AES key with PrivateKey expected type"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid_Object_Type") || err_msg.contains("object type"),
        "Expected Invalid_Object_Type error, got: {err_msg}"
    );

    // Destroy the AES key with the correct expected type (SymmetricKey). Must succeed.
    let destroy_correct_type = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
        remove: true,
        cascade: true,
        expected_object_type: Some(Kmip21ObjectType::SymmetricKey),
    };
    send_message(
        kms.clone(),
        &admin,
        vec![Operation::Destroy(destroy_correct_type)],
    )
    .await?;

    Ok(())
}
