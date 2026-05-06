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
///
/// - Issue #933: `ModifyAttribute(Name)` failed for non-extractable (sensitive)
///   HSM-backed keys because `HsmStore::retrieve` tried to export key material.
///   The fix falls back to `get_key_metadata` for sensitive keys to build a stub.
use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::{Attribute, Attributes},
        kmip_objects::ObjectType as Kmip21ObjectType,
        kmip_operations::{Destroy, Export, Import, ModifyAttribute, Operation},
        kmip_types::{CryptographicAlgorithm, Name, NameType, UniqueIdentifier},
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
            EMPTY_TAGS, create_kek, create_sym_key, delete_key, export_object, hsm_clap_config,
            locate_keys, revoke_key, send_message,
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

/// Issue #933 — `ModifyAttribute(Name)` must succeed for non-extractable HSM keys.
///
/// Synology DSM calls `ModifyAttribute(Name)` immediately after `Register` to replace
/// the initial SHA-512 name with the canonical volume UUID.  When the KMS is configured
/// with an HSM and the wrapping key is marked sensitive (non-extractable), the original
/// `HsmStore::retrieve` tried to export the key material, which triggered:
/// "This key is sensitive and cannot be exported from the HSM."
///
/// The fix in `HsmStore::retrieve` catches the sensitive-export error and falls back to
/// `get_key_metadata()` (no material export), building a metadata-only stub that allows
/// attribute-only KMIP operations to succeed.  `HsmStore::update_object` was also
/// changed to return `Ok(())` for attribute updates instead of an error.
pub(super) async fn test_hsm_modify_attribute_sensitive_key() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let admin = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();
    let mut clap_config = hsm_clap_config(&admin, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path;
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Create a sensitive (non-extractable) AES-256 key on the HSM.
    // `create_sym_key` internally sets `sensitive = true`.
    create_sym_key(&kek_uid, &admin, &kms).await?;

    // Call ModifyAttribute(Name) — before the fix this would fail with:
    // "This key is sensitive and cannot be exported from the HSM."
    let new_name = "volume-2e043205-f1e7-48bb-a615-d331f2f84751";
    let response = send_message(
        kms.clone(),
        &admin,
        vec![Operation::ModifyAttribute(ModifyAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
            new_attribute: Attribute::Name(Name {
                name_value: new_name.to_owned(),
                name_type: NameType::UninterpretedTextString,
            }),
        })],
    )
    .await;

    // The response must succeed — not an error.
    assert!(
        response.is_ok(),
        "ModifyAttribute failed for sensitive HSM key (issue #933): {:?}",
        response.unwrap_err()
    );

    // Cleanup.
    delete_key(&kek_uid, &admin, &kms).await?;

    Ok(())
}

/// Issue #935 — Locate with a Name filter must NOT return the server KEK.
///
/// Before the fix, HSM locate with a Name attribute would silently ignore
/// the filter and return any available key — including the internal KEK —
/// which was unexpected from both security and integration perspectives.
/// The fix rejects Name-based filters for HSM keys (since PKCS#11 doesn't
/// store KMIP Name attributes) and returns empty rather than leaking keys.
pub(super) async fn test_hsm_locate_name_filter_does_not_leak_kek() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let admin = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();
    let mut clap_config = hsm_clap_config(&admin, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path;
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Create the KEK in the HSM (simulates server-configured wrapping key).
    create_kek(&kek_uid, &admin, &kms).await?;

    // Locate with a Name filter that doesn't match anything: the server must
    // NOT return the KEK or any other unrelated object.
    let attrs_with_name = Attributes {
        name: Some(vec![Name {
            name_value: "nonexistent-key-name".to_owned(),
            name_type: NameType::UninterpretedTextString,
        }]),
        ..Default::default()
    };
    let found = locate_keys(&admin, &kms, Some(attrs_with_name)).await?;
    assert!(
        found.is_empty(),
        "Locate with Name filter must return empty for HSM keys (issue #935), \
         but got: {found:?}"
    );

    // Also verify that a locate WITHOUT Name filter still returns the KEK
    // (to confirm we didn't break basic locate functionality).
    let found_all = locate_keys(&admin, &kms, None).await?;
    assert!(
        !found_all.is_empty(),
        "Locate without Name filter should return at least the KEK"
    );

    // Cleanup.
    delete_key(&kek_uid, &admin, &kms).await?;

    Ok(())
}
