use std::{fs, path::PathBuf};

use cosmian_kms_client::read_bytes_from_file;
use cosmian_logger::log_init;
use kms_test_server::start_default_test_kms_server_with_utimaco_hsm;
use tempfile::TempDir;
use tracing::trace;
use uuid::Uuid;

use crate::{
    actions::{
        rsa::{HashFn, RsaEncryptionAlgorithm},
        symmetric::{
            keys::create_key::{CreateKeyAction, SymmetricAlgorithm},
            DataEncryptionAlgorithm, KeyEncryptionAlgorithm,
        },
    },
    error::result::CliResult,
    tests::{
        rsa::{
            create_key_pair::{create_rsa_key_pair, RsaKeyPairOptions},
            encrypt_decrypt::{decrypt, encrypt},
        },
        symmetric::{create_key::create_symmetric_key, encrypt_decrypt::run_encrypt_decrypt_test},
    },
};

#[tokio::test]
pub(crate) async fn test_aes_gcm() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* tag */
    )
}

#[tokio::test]
pub(crate) async fn test_rsa_pkcs_oaep() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = create_rsa_key_pair(
        &ctx.owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            ..Default::default()
        },
    )?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        Some(HashFn::Sha256),
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            output_file.to_str().unwrap(),
            &private_key_id,
            RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
            Some(HashFn::Sha256),
            Some(recovered_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    //TODO: The Proteccio HSM only offers SH256 as hash function; maybe this test should be revisited
    // // ... or another hash function
    // assert!(
    //     decrypt(
    //         KSM_HSM_CLIENT_CONF,
    //         output_file.to_str().unwrap(),
    //         &private_key_id,
    //         EncryptionAlgorithm::CkmRsaPkcsOaep,
    //         Some(HashFn::Sha1),
    //         Some(recovered_file.to_str().unwrap()),
    //         None,
    //     )
    //     .is_err()
    // );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_rsa_pkcs_v15() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = create_rsa_key_pair(
        &ctx.owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            ..Default::default()
        },
    )?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &public_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcs,
        Some(HashFn::Sha256),
        Some(output_file.to_str().unwrap()),
        None,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        output_file.to_str().unwrap(),
        &private_key_id,
        RsaEncryptionAlgorithm::CkmRsaPkcs,
        Some(HashFn::Sha256),
        Some(recovered_file.to_str().unwrap()),
        None,
    )?;
    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}
