use std::{fs, path::PathBuf};

use cosmian_kms_client::read_bytes_from_file;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::elliptic_curves::{
        decrypt::DecryptAction, encrypt::EncryptAction, keys::create_key_pair::CreateKeyPairAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_encrypt_decrypt_using_ids() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file,
        key_id: Some(private_key_id.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_using_tags() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = CreateKeyPairAction {
        tags: vec!["tag_ec".to_string()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: Some(vec!["[\"tag_ec\"]".to_owned()]),
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file,
        key_id: Some(private_key_id.to_string()),
        tags: Some(vec!["[\"tag_ec\"]".to_owned()]),
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}
