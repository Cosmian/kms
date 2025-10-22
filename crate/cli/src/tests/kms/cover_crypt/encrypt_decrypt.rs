use std::{fs, path::PathBuf};

use cosmian_kms_client::read_bytes_from_file;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::cover_crypt::{
        decrypt::DecryptAction,
        encrypt::EncryptAction,
        keys::{create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction},
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_encrypt_decrypt_using_object_ids() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (master_secret_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    EncryptAction {
        input_files: vec![input_file.clone()],
        encryption_policy: "Department::MKG && Security Level::Confidential".to_string(),
        key_id: Some(master_public_key_id),
        output_file: Some(output_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // create a user decryption key
    let user_ok_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![output_file.clone()],
        key_id: Some(user_ok_key_id),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    // this user key should not be able to decrypt the file
    let user_ko_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "Department::FIN && Security Level::Top Secret".to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    DecryptAction {
        input_files: vec![output_file.clone()],
        key_id: Some(user_ko_key_id),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_bulk_using_object_ids() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file1 = PathBuf::from("../../test_data/plain.txt");
    let input_file2 = PathBuf::from("../../test_data/plain2.txt");
    let input_file3 = PathBuf::from("../../test_data/plain3.txt");

    let output_file1 = tmp_path.join("plain.enc");
    let output_file2 = tmp_path.join("plain2.enc");
    let output_file3 = tmp_path.join("plain3.enc");

    let recovered_file1 = tmp_path.join("plain.plain");
    let recovered_file2 = tmp_path.join("plain2.plain");
    let recovered_file3 = tmp_path.join("plain3.plain");

    fs::remove_file(&output_file1).ok();
    assert!(!output_file1.exists());

    fs::remove_file(&output_file2).ok();
    assert!(!output_file2.exists());

    fs::remove_file(&output_file3).ok();
    assert!(!output_file3.exists());

    let (master_secret_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    EncryptAction {
        input_files: vec![
            input_file1.clone(),
            input_file2.clone(),
            input_file3.clone(),
        ],
        encryption_policy: "Department::MKG && Security Level::Confidential".to_string(),
        key_id: Some(master_public_key_id),
        output_file: Some(tmp_path.to_path_buf()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(output_file1.exists());
    assert!(output_file2.exists());
    assert!(output_file3.exists());

    // create a user decryption key
    let user_ok_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![
            output_file1.clone(),
            output_file2.clone(),
            output_file3.clone(),
        ],
        key_id: Some(user_ok_key_id.clone()),
        output_file: None, // Will use default output naming
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(recovered_file1.exists());
    assert!(recovered_file2.exists());
    assert!(recovered_file3.exists());

    let original_content = read_bytes_from_file(&input_file1)?;
    let recovered_content = read_bytes_from_file(&recovered_file1)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file3)?;
    let recovered_content = read_bytes_from_file(&recovered_file3)?;
    assert_eq!(original_content, recovered_content);

    // this user key should not be able to decrypt the file
    let user_ko_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "Department::FIN && Security Level::Top Secret".to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    DecryptAction {
        input_files: vec![output_file1.clone()],
        key_id: Some(user_ko_key_id),
        output_file: Some(recovered_file1.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // Test encrypted files have their own encrypted header
    // along the data and can be decrypted alone
    fs::remove_file(&recovered_file2).ok();
    assert!(!recovered_file2.exists());

    DecryptAction {
        input_files: vec![output_file2.clone()],
        key_id: Some(user_ok_key_id),
        output_file: None, // Will use default output naming
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(recovered_file2.exists());

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
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

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("tag_cc_{ts}");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (master_secret_key_id, _master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![base_tag.clone()],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    EncryptAction {
        input_files: vec![input_file.clone()],
        encryption_policy: "Department::MKG && Security Level::Confidential".to_string(),
        key_id: None,
        output_file: Some(output_file.clone()),
        tags: Some(vec![base_tag.clone()]),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // create a user decryption key
    let user_ok_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![base_tag.clone()],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![output_file.clone()],
        key_id: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: Some(vec![base_tag.clone()]),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    // TODO Left here but this has become undefined behavior in the new version:
    // TODO if the first key found is the correct one, decryption will work, else it will fail

    // // decrypt fails because two keys with same tag exist
    // let _user_ko_key_id = create_user_decryption_key(
    //     &ctx.owner_client_conf_path,
    //     "[\"tag\"]",
    //     "Department::FIN && Security Level::Top Secret",
    //     &["tag"], false
    // )?;
    // assert!(
    //     decrypt(
    //         &ctx.owner_client_conf_path,
    //         &[output_file.to_str().unwrap()],
    //         "[\"tag\"]",
    //         Some(recovered_file.to_str().unwrap()),
    //         Some("myid"),
    //     )
    //     .is_err()
    // );

    // this user key should not be able to decrypt the file
    let _user_ko_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "Department::FIN && Security Level::Top Secret".to_string(),
        tags: vec!["tag_ko".to_string()],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    DecryptAction {
        input_files: vec![output_file.clone()],
        key_id: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: Some(vec!["tag_ko".to_string()]),
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    fs::remove_file(&recovered_file).ok();
    assert!(!recovered_file.exists());
    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![output_file.clone()],
        key_id: Some(user_ok_key_id),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_bulk_using_tags() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file1 = PathBuf::from("../../test_data/plain.txt");
    let input_file2 = PathBuf::from("../../test_data/plain2.txt");
    let input_file3 = PathBuf::from("../../test_data/plain3.txt");

    let output_file1 = tmp_path.join("plain.enc");
    let output_file2 = tmp_path.join("plain2.enc");
    let output_file3 = tmp_path.join("plain3.enc");

    let recovered_file1 = tmp_path.join("plain.plain");
    let recovered_file2 = tmp_path.join("plain2.plain");
    let recovered_file3 = tmp_path.join("plain3.plain");

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("tag_bulk_{ts}");

    fs::remove_file(&output_file1).ok();
    assert!(!output_file1.exists());

    fs::remove_file(&output_file2).ok();
    assert!(!output_file2.exists());

    fs::remove_file(&output_file3).ok();
    assert!(!output_file3.exists());

    let (master_secret_key_id, _master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![base_tag.clone()],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    EncryptAction {
        input_files: vec![
            input_file1.clone(),
            input_file2.clone(),
            input_file3.clone(),
        ],
        encryption_policy: "Department::MKG && Security Level::Confidential".to_string(),
        key_id: None,
        output_file: Some(tmp_path.join("")),
        tags: Some(vec![base_tag.clone()]),
        authentication_data: Some("myid".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(output_file1.exists());
    assert!(output_file2.exists());
    assert!(output_file3.exists());

    // create a user decryption key
    let user_ok_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![base_tag.clone()],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![
            output_file1.clone(),
            output_file2.clone(),
            output_file3.clone(),
        ],
        key_id: None,
        output_file: None, // Will use default output naming
        authentication_data: Some("myid".to_owned()),
        tags: Some(vec![base_tag.clone()]),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(recovered_file1.exists());
    assert!(recovered_file2.exists());
    assert!(recovered_file3.exists());

    let original_content = read_bytes_from_file(&input_file1)?;
    let recovered_content = read_bytes_from_file(&recovered_file1)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file3)?;
    let recovered_content = read_bytes_from_file(&recovered_file3)?;
    assert_eq!(original_content, recovered_content);

    // TODO Left here but this has become undefined behavior in the new version:
    // TODO if the first key found is the correct one, decryption will work, else it will fail

    // // decrypt fails because two keys with same tag exist
    // let _user_ko_key_id = create_user_decryption_key(
    //     &ctx.owner_client_conf_path,
    //     "[\"tag_bulk\"]",
    //     "Department::FIN && Security Level::Top Secret",
    //     &["tag_bulk"],
    // )?;
    // assert!(
    //     decrypt(
    //         &ctx.owner_client_conf_path,
    //         &[output_file1.to_str().unwrap()],
    //         "[\"tag_bulk\"]",
    //         Some(recovered_file1.to_str().unwrap()),
    //         Some("myid"),
    //     )
    //     .is_err()
    // );

    // Test encrypted files have their own encrypted header
    // along the data and can be decrypted alone
    fs::remove_file(&recovered_file2).ok();
    assert!(!recovered_file2.exists());

    DecryptAction {
        input_files: vec![output_file2.clone()],
        key_id: Some(user_ok_key_id),
        output_file: None, // Will use default output naming
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(recovered_file2.exists());

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}
