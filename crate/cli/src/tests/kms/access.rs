use std::path::PathBuf;

use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{KmipOperation, kmip_types::UniqueIdentifier},
    reexport::cosmian_kms_client_utils::symmetric_utils::DataEncryptionAlgorithm,
};
use cosmian_logger::{log_init, trace};
use serial_test::serial;
use test_kms_server::{
    start_default_test_kms_server_with_cert_auth,
    start_default_test_kms_server_with_privileged_users,
};

use crate::{
    actions::kms::{
        access::{
            GrantAccess, ListAccessRightsObtained, ListAccessesGranted, ListOwnedObjects,
            RevokeAccess,
        },
        rsa::keys::create_key_pair::CreateKeyPairAction,
        shared::{ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction},
        symmetric::keys::{
            create_key::CreateKeyAction, destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
        },
    },
    error::result::KmsCliResult,
    tests::kms::symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
};

/// Generates a symmetric key
async fn gen_key(kms_client: &KmsClient) -> KmsCliResult<UniqueIdentifier> {
    CreateKeyAction::default().run(kms_client.clone()).await
}

/// Generates a key pair
async fn gen_keypair(kms_client: &KmsClient) -> KmsCliResult<(UniqueIdentifier, UniqueIdentifier)> {
    CreateKeyPairAction::default().run(kms_client.clone()).await
}

/// Export and import symmetric key
async fn export_import_sym_key(key_id: &str, kms_client: &KmsClient) -> KmsCliResult<String> {
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_owned()),
        key_file: PathBuf::from("/tmp/output.export"),
        ..Default::default()
    }
    .run(kms_client.clone())
    .await?;

    Ok(ImportSecretDataOrKeyAction {
        key_file: PathBuf::from("/tmp/output.export"),
        ..Default::default()
    }
    .run(kms_client.clone())
    .await?
    .to_string())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_ownership_and_grant() -> KmsCliResult<()> {
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    // the owner should have access
    ExportSecretDataOrKeyAction {
        key_file: PathBuf::from("/tmp/output.json"),
        key_id: Some(key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )
    .await?;

    // the user should not be able to export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should not be able to encrypt or decrypt
    assert!(
        run_encrypt_decrypt_test(
            &ctx.get_user_client(),
            &key_id,
            DataEncryptionAlgorithm::AesGcm,
            None,
            0
        )
        .await
        .is_err()
    );
    // the user should not be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "failed revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should not be able to destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // switch back to owner
    // grant encrypt and decrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Decrypt, KmipOperation::Encrypt],
    }
    .run(ctx.get_owner_client())
    .await?;

    // switch to user
    // the user should still not be able to export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // the user should now be able to encrypt or decrypt
    run_encrypt_decrypt_test(
        &ctx.get_user_client(),
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )
    .await?;
    // the user should still not be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "failed revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should still not be able to destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // switch back to owner
    // grant encrypt and decrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // switch to user
    // the user should now be able to export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    // the user should still not be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "failed revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should still not be able to destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // grant revoke access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Revoke],
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user should now be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "user revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await?;

    // grant destroy access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Destroy],
    }
    .run(ctx.get_owner_client())
    .await?;

    // Destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_grant_error() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    // bad object ID
    assert!(
        GrantAccess {
            object_uid: Some("BAD ID".to_owned()),
            user: "user.client@acme.com".to_owned(),
            operations: vec![KmipOperation::Get],
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    // grant to myself
    assert!(
        GrantAccess {
            object_uid: Some(key_id.to_string()),
            user: "owner.client@acme.com".to_owned(),
            operations: vec![KmipOperation::Get],
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_revoke_access() -> KmsCliResult<()> {
    log_init(None);
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    /*    // the user should not be able to export
    assert!(
        export(
            &ctx.user_client_conf_path,
            "sym",
            &key_id,
            "/tmp/output.json",
            None,
            false,
            None,
            false,
        )
        .is_err()
    );*/

    // switch back to owner
    // grant encrypt and decrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // switch to user
    // the user should now be able to export
    ExportSecretDataOrKeyAction {
        key_file: PathBuf::from("/tmp/output.json"),
        key_id: Some(key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;

    // switch back to owner
    // revoke access to user
    RevokeAccess {
        user: "user.client@acme.com".to_owned(),
        object_uid: Some(key_id.to_string()),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user should not be able to export anymore
    ExportSecretDataOrKeyAction {
        key_file: PathBuf::from("/tmp/output.json"),
        key_id: Some(key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // revoke errors
    // switch back to owner
    assert!(
        RevokeAccess {
            object_uid: Some("BAD KEY".to_owned()),
            user: "user.client@acme.com".to_owned(),
            operations: vec![KmipOperation::Get],
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    // this will not error
    assert!(
        RevokeAccess {
            object_uid: Some(key_id.to_string()),
            user: "BAD USER".to_owned(),
            operations: vec![KmipOperation::Get],
        }
        .run(ctx.get_user_client())
        .await
        .is_err()
    );

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_list_access_rights() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    // grant encrypt and decrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // the owner can list access rights granted
    let owner_list = ListAccessesGranted {
        object_uid: key_id.to_string(),
    }
    .run(ctx.get_owner_client())
    .await?;

    trace!("owner list {owner_list:?}");

    assert!(
        owner_list
            .iter()
            .map(|x| x.user_id.clone())
            .any(|x| x == *"user.client@acme.com")
    );

    // The user is not the owner and thus should not be able to list accesses on this object
    ListAccessesGranted {
        object_uid: key_id.to_string(),
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_list_access_rights_error() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    ListAccessesGranted {
        object_uid: "BAD KEY".to_owned(),
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();
    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_list_owned_objects() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    // grant encrypt and decrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // The user is not the owner and thus should not have the object in the list
    let user_list = ListOwnedObjects.run(ctx.get_user_client()).await?;
    assert!(
        user_list
            .iter()
            .map(|x| x.object_id.clone())
            .all(|x| x != key_id)
    );

    let owner_list = ListOwnedObjects.run(ctx.get_owner_client()).await?;
    assert!(
        owner_list
            .iter()
            .map(|x| x.object_id.clone())
            .any(|x| x == key_id)
    );

    // create a key using the user
    let user_key_id = gen_key(&ctx.get_user_client()).await?;

    // the user should have the object in the list
    let user_list = ListOwnedObjects.run(ctx.get_user_client()).await?;
    assert!(
        user_list
            .iter()
            .map(|x| x.object_id.clone())
            .any(|x| x == user_key_id)
    );

    // The 'owner' is not the owner of this object and thus should not have the object in the list
    let owner_list = ListOwnedObjects.run(ctx.get_owner_client()).await?;
    assert!(
        !owner_list
            .iter()
            .map(|x| x.object_id.clone())
            .any(|x| x == user_key_id)
    );
    // ... but the list should still contain the other key
    assert!(
        owner_list
            .iter()
            .map(|x| x.object_id.clone())
            .any(|x| x == key_id)
    );

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_access_right_obtained() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    let list = ListAccessRightsObtained.run(ctx.get_owner_client()).await?;
    trace!("owner list {list:?}");
    assert!(
        list.iter()
            .map(|x| x.object_id.clone())
            .all(|x| x != key_id)
    );

    // grant get access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user should have the "get" access granted
    let list = ListAccessRightsObtained.run(ctx.get_user_client()).await?;
    trace!("user list {list:?}");
    assert!(
        list.iter()
            .map(|x| x.object_id.clone())
            .any(|x| x == key_id)
    );
    assert!(
        list.iter()
            .flat_map(|x| x.operations.clone())
            .any(|x| x == KmipOperation::Get)
    );

    // The owner has not been granted access rights on this object (it owns it)
    let list = ListAccessRightsObtained.run(ctx.get_owner_client()).await?;
    assert!(
        !list
            .iter()
            .map(|x| x.object_id.clone())
            .any(|x| x == key_id)
    );

    // same test but grant get access to the wildcard user
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    // the owner should not have access rights (it owns it)
    let list = ListAccessRightsObtained.run(ctx.get_owner_client()).await?;
    assert!(!list.iter().any(|x| x.object_id == key_id));

    // grant get access to the wildcard user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "*".to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // grant encrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Encrypt],
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user should have the "get" and "encrypt" access granted
    let list = ListAccessRightsObtained.run(ctx.get_user_client()).await?;
    trace!("user list {list:?}");
    assert!(list.iter().any(|x| x.object_id == key_id));
    assert!(
        list.iter()
            .flat_map(|x| x.operations.clone())
            .any(|x| x == KmipOperation::Get)
    );
    assert!(
        list.iter()
            .flat_map(|x| x.operations.clone())
            .any(|x| x == KmipOperation::Encrypt)
    );

    // The owner should not have access rights (since they own the object)
    let list = ListAccessRightsObtained.run(ctx.get_owner_client()).await?;
    assert!(!list.iter().any(|x| x.object_id == key_id));

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_ownership_and_grant_wildcard_user() -> KmsCliResult<()> {
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    // the owner should have access
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.json"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )
    .await?;

    // the user should not be able to export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should not be able to encrypt or decrypt
    assert!(
        run_encrypt_decrypt_test(
            &ctx.get_user_client(),
            &key_id,
            DataEncryptionAlgorithm::AesGcm,
            None,
            0
        )
        .await
        .is_err()
    );
    // the user should not be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "failed revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should not be able to destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // switch back to owner
    // grant encrypt and decrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Encrypt],
    }
    .run(ctx.get_owner_client())
    .await?;
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Decrypt],
    }
    .run(ctx.get_owner_client())
    .await?;

    // switch to user
    // the user should still not be able to export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // the user should now be able to encrypt or decrypt
    run_encrypt_decrypt_test(
        &ctx.get_user_client(),
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )
    .await?;
    // the user should still not be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "failed revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should still not be able to destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // switch back to owner
    // grant encrypt and decrypt access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    // switch to user
    // the user should now be able to export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.json"),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    // the user should still not be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "failed revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();
    // the user should still not be able to destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await
    .unwrap_err();

    // switch back to owner
    // grant revoke access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Revoke],
    }
    .run(ctx.get_owner_client())
    .await?;

    // switch to user
    // the user should now be able to revoke the key
    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "user revoke".to_owned(),
        tags: None,
    }
    .run(ctx.get_user_client())
    .await?;

    // switch back to owner
    // grant destroy access to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Destroy],
    }
    .run(ctx.get_owner_client())
    .await?;

    // switch to user
    // destroy the key
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_user_client())
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_grant_multiple_operations() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.get_owner_client()).await?;

    // grant multiple access to user
    // Grant multiple operations to user
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![
            KmipOperation::Get,
            KmipOperation::Revoke,
            KmipOperation::Encrypt,
        ],
    }
    .run(ctx.get_owner_client())
    .await?;

    // Check granted rights
    let owner_list = ListAccessesGranted {
        object_uid: key_id.to_string(),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(
        owner_list
            .iter()
            .any(|x| x.user_id == "user.client@acme.com")
    );

    // Revoke multiple operations from user
    RevokeAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get, KmipOperation::Revoke],
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify only Encrypt remains
    let owner_list = ListAccessesGranted {
        object_uid: key_id.to_string(),
    }
    .run(ctx.get_owner_client())
    .await?;

    // Find the user's access rights
    let user_rights = owner_list
        .iter()
        .find(|x| x.user_id == "user.client@acme.com")
        .unwrap();

    // Should only have Encrypt operation remaining
    assert_eq!(user_rights.operations.len(), 1);
    assert!(user_rights.operations.contains(&KmipOperation::Encrypt));

    Ok(())
}

#[tokio::test]
#[serial]
pub(crate) async fn test_grant_with_without_object_uid() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // grant create access to user - without object id
    // Grant create access to user without object ID
    GrantAccess {
        object_uid: None,
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Create],
    }
    .run(ctx.get_owner_client())
    .await?;

    // Try to grant create and get access without object ID - should fail
    assert!(
        GrantAccess {
            object_uid: None,
            user: "user.client@acme.com".to_owned(),
            operations: vec![KmipOperation::Create, KmipOperation::Get],
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    Ok(())
}

#[tokio::test]
#[serial]
#[expect(clippy::large_stack_frames)]
pub(crate) async fn test_privileged_users() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms=debug"));
    let ctx = start_default_test_kms_server_with_privileged_users(vec![
        "tech@cosmian.com".to_owned(),
        "user.privileged@acme.com".to_owned(),
    ])
    .await;

    //By default privileged users can create or import objects
    let key_id = gen_key(&ctx.get_owner_client()).await?;
    //The owner should be able to grant access
    GrantAccess {
        object_uid: Some(key_id.to_string()),
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Get, KmipOperation::Export],
    }
    .run(ctx.get_owner_client())
    .await?;

    let (_pub_key, _priv_key) = gen_keypair(&ctx.get_owner_client()).await?;
    let _imported_key = export_import_sym_key(&key_id.to_string(), &ctx.get_owner_client()).await?;

    // non-privileged users can't create or import by default
    gen_key(&ctx.get_user_client()).await.unwrap_err();
    gen_keypair(&ctx.get_user_client()).await.unwrap_err();
    export_import_sym_key(&key_id.to_string(), &ctx.get_user_client())
        .await
        .unwrap_err();

    // privileged user can grant create access
    GrantAccess {
        object_uid: None,
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Create],
    }
    .run(ctx.get_owner_client())
    .await?;

    // now user can create objects
    gen_key(&ctx.get_user_client()).await.unwrap();
    gen_keypair(&ctx.get_user_client()).await.unwrap();
    export_import_sym_key(&key_id.to_string(), &ctx.get_user_client())
        .await
        .unwrap();

    // non-privileged user can't grant create access
    assert!(
        GrantAccess {
            object_uid: None,
            user: "user2.client@acme.com".to_owned(),
            operations: vec![KmipOperation::Create],
        }
        .run(ctx.get_user_client())
        .await
        .is_err()
    );

    // can't grant create access to privileged user
    assert!(
        GrantAccess {
            object_uid: None,
            user: "user.privileged@acme.com".to_owned(),
            operations: vec![KmipOperation::Create],
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    // privileged user can revoke create access
    RevokeAccess {
        object_uid: None,
        user: "user.client@acme.com".to_owned(),
        operations: vec![KmipOperation::Create],
    }
    .run(ctx.get_owner_client())
    .await?;

    // user can't create objects anymore
    gen_key(&ctx.get_user_client()).await.unwrap_err();
    gen_keypair(&ctx.get_user_client()).await.unwrap_err();
    export_import_sym_key(&key_id.to_string(), &ctx.get_user_client())
        .await
        .unwrap_err();

    // can't revoke create access from privileged user
    assert!(
        RevokeAccess {
            object_uid: None,
            user: "user.privileged@acme.com".to_owned(),
            operations: vec![KmipOperation::Create],
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    Ok(())
}
