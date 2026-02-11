use std::path::PathBuf;

use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        cover_crypt::{
            access_structure::{
                AddQualifiedAttributeAction, DisableAttributeAction, RemoveAttributeAction,
                RenameAttributeAction, ViewAction,
            },
            decrypt::DecryptAction,
            encrypt::EncryptAction,
            keys::{
                create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
            },
        },
        shared::ExportSecretDataOrKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_view_access_structure() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some(
    //     "info,cosmian_kms_server::core::operations=trace,cosmian_kmip=trace",
    // ));

    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (_master_secret_key_id, master_public_key_id) = Box::pin(
        CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let public_key_path = tmp_path.join("public_key.json");

    ExportSecretDataOrKeyAction {
        key_id: Some(master_public_key_id.to_string()),
        key_file: format!("{}", public_key_path.display()).into(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let view_access_structure = ViewAction {
        key_id: None,
        key_file: Some(format!("{}", public_key_path.display()).into()),
    }
    .run(ctx.get_owner_client())
    .await?;

    let output = format!("{view_access_structure:?}",);
    assert!(output.contains("Security Level"));
    assert!(output.contains("Top Secret"));
    assert!(output.contains("RnD"));
    assert!(
        output.contains(
            "Attribute { id: 6, security_mode: Classic, encryption_status: EncryptDecrypt }"
        )
    );

    Ok(())
}

#[tokio::test]
async fn test_edit_access_structure() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let cipher_file = tmp_path.join("cipher.enc");
    let new_cipher_file = tmp_path.join("cipher.new.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_secret_key_id, master_public_key_id) = Box::pin(
        CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    let user_decryption_key = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.to_string(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_owned(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    EncryptAction {
        input_files: vec![input_file.clone()],
        encryption_policy: "Department::MKG && Security Level::Confidential".to_owned(),
        key_id: Some(master_public_key_id.to_string()),
        tags: None,
        output_file: Some(cipher_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![cipher_file.clone()],
        key_id: Some(user_decryption_key.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // Rename MKG to Marketing
    RenameAttributeAction {
        attribute: "Department::MKG".to_owned(),
        new_name: "Marketing".to_owned(),
        master_secret_key_id: Some(master_secret_key_id.to_string()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should still be able to decrypt marketing file
    DecryptAction {
        input_files: vec![cipher_file.clone()],
        key_id: Some(user_decryption_key.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // Adding new attribute "Department::Sales"
    AddQualifiedAttributeAction {
        attribute: "Department::Sales".to_owned(),
        hybridized: false,
        secret_key_id: Some(master_secret_key_id.to_string()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // Encrypt message for the new attribute
    EncryptAction {
        input_files: vec![input_file.clone()],
        encryption_policy: "Department::Sales && Security Level::Confidential".to_owned(),
        key_id: Some(master_public_key_id.to_string()),
        tags: None,
        output_file: Some(new_cipher_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // Create a new user key with access to both the new and the renamed attribute
    let sales_mkg_user_decryption_key = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.to_string(),
        access_policy: "(Department::Sales || Department::Marketing) && Security \
                        Level::Confidential"
            .to_owned(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // finance and marketing user can not decrypt the sales file
    DecryptAction {
        input_files: vec![new_cipher_file.clone()],
        key_id: Some(user_decryption_key.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // sales and marketing user can decrypt the sales file
    DecryptAction {
        input_files: vec![new_cipher_file.clone()],
        key_id: Some(sales_mkg_user_decryption_key.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // disable attribute Sales
    DisableAttributeAction {
        attribute: "Department::Sales".to_owned(),
        master_secret_key_id: Some(master_secret_key_id.to_string()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // can no longer encrypt for this attribute
    EncryptAction {
        input_files: vec![input_file],
        encryption_policy: "Department::Sales && Security Level::Confidential".to_owned(),
        key_id: Some(master_public_key_id.to_string()),
        tags: None,
        output_file: None,
        authentication_data: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // can still decrypt existing sales files
    DecryptAction {
        input_files: vec![new_cipher_file.clone()],
        key_id: Some(sales_mkg_user_decryption_key.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // remove attribute Sales
    RemoveAttributeAction {
        attribute: "Department::Sales".to_owned(),
        master_secret_key_id: Some(master_secret_key_id.to_string()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // can no longer decrypt message for this attribute
    DecryptAction {
        input_files: vec![new_cipher_file],
        key_id: Some(sales_mkg_user_decryption_key.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}
