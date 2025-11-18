use std::{fs, path::PathBuf};

use cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::rsa_utils::{HashFn, RsaEncryptionAlgorithm},
};
use cosmian_logger::{log_init, trace};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;
#[cfg(feature = "non-fips")]
use test_kms_server::start_default_test_kms_server_with_utimaco_and_kek;

use crate::{
    actions::kms::rsa::{
        decrypt::DecryptAction, encrypt::EncryptAction, keys::create_key_pair::CreateKeyPairAction,
    },
    error::result::KmsCliResult,
};

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_ckm_rsa_pkcs() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_and_kek().await;

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

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");

    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcs,
        hash_fn: HashFn::Sha256,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcs,
        hash_fn: HashFn::Sha256,
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        DecryptAction {
            input_file: output_file.clone(),
            key_id: Some(private_key_id.to_string()),
            tags: None,
            encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
            hash_fn: HashFn::Sha256,
            output_file: Some(recovered_file.clone()),
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_ckm_rsa_pkcs_oaep() -> KmsCliResult<()> {
    log_init(None);
    // to enable this, add cosmian_logger = { workspace = true } to dev-dependencies in Cargo.toml
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=info,cosmian_kms_server::core::operations=trace,\
    //      cosmian_kms_utils=trace,cosmian_kmip=info",
    // );
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

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");

    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        hash_fn: HashFn::Sha256,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        hash_fn: HashFn::Sha256,
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        DecryptAction {
            input_file: output_file.clone(),
            key_id: Some(private_key_id.to_string()),
            tags: None,
            encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
            hash_fn: HashFn::Sha256,
            output_file: Some(recovered_file.clone()),
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    // ... or another hash function
    assert!(
        DecryptAction {
            input_file: output_file.clone(),
            key_id: Some(private_key_id.to_string()),
            tags: None,
            encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
            hash_fn: HashFn::Sha1,
            output_file: Some(recovered_file.clone()),
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_rsa_aes_key_wrap() -> KmsCliResult<()> {
    // log_init(
    //     "cosmian_kms_cli=trace,cosmian_kms_server=trace,cosmian_kms_utils=trace,cosmian_kmip=trace",
    // );
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

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
        hash_fn: HashFn::Sha256,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
        hash_fn: HashFn::Sha256,
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        DecryptAction {
            input_file: output_file.clone(),
            key_id: Some(private_key_id.to_string()),
            tags: None,
            encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
            hash_fn: HashFn::Sha256,
            output_file: Some(recovered_file.clone()),
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    // ... or another hash function
    assert!(
        DecryptAction {
            input_file: output_file.clone(),
            key_id: Some(private_key_id.to_string()),
            tags: None,
            encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
            hash_fn: HashFn::Sha1,
            output_file: Some(recovered_file.clone()),
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_rsa_encrypt_decrypt_using_tags() -> KmsCliResult<()> {
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
        tags: vec!["tag_rsa".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        hash_fn: HashFn::Sha256,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        hash_fn: HashFn::Sha256,
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
