use cosmian_logger::log_init;
use kms_test_server::start_default_test_kms_server_with_utimaco_hsm;
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    actions::{
        shared::ExportKeyFormat,
        symmetric::{
            keys::create_key::{CreateKeyAction, SymmetricAlgorithm},
            DataEncryptionAlgorithm, KeyEncryptionAlgorithm,
        },
    },
    error::result::CliResult,
    tests::{
        rsa::create_key_pair::{create_rsa_key_pair, RsaKeyPairOptions},
        shared::{export_key, ExportKeyParams},
        symmetric::{create_key::create_symmetric_key, encrypt_decrypt::run_encrypt_decrypt_test},
    },
};

#[tokio::test]
pub(crate) async fn test_wrap_with_aes_gcm() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let wrapping_key_id = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            sensitive: true,
            ..Default::default()
        },
    )?;
    // println!("Wrapping key id: {wrapping_key_id}" );
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(wrapping_key_id),
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
            + 12 /* nonce */  + 16, /* ag */
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[tokio::test]
pub(crate) async fn test_wrap_with_rsa_oaep() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &ctx.owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {public_key_id}");
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(public_key_id),
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
            + 12 /* nonce */  + 16, /* ag */
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[tokio::test]
pub(crate) async fn test_unwrap_on_export() -> CliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &ctx.owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {public_key_id}");
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(public_key_id),
            ..Default::default()
        },
    )?;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: dek,
        key_file: tmp_path.join("dek.pem").to_str().unwrap().to_owned(),
        unwrap: true,
        key_format: Some(ExportKeyFormat::Raw),
        ..Default::default()
    })?;
    Ok(())
}
