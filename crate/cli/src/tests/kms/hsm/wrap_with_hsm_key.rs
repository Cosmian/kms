use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    create_utils::SymmetricAlgorithm, export_utils::ExportKeyFormat,
    symmetric_utils::DataEncryptionAlgorithm,
};
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server_with_utimaco_hsm;
use tracing::info;
use uuid::Uuid;

use crate::{
    actions::kms::{
        rsa::keys::create_key_pair::CreateKeyPairAction,
        shared::ExportKeyAction,
        symmetric::{KeyEncryptionAlgorithm, keys::create_key::CreateKeyAction},
    },
    error::result::KmsCliResult,
    tests::kms::symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
};

#[tokio::test]
pub(crate) async fn test_wrap_with_aes_gcm() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let wrapping_key_id = CreateKeyAction {
        key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("Created wrapping key: {wrapping_key_id}");

    let dek = CreateKeyAction {
        key_id: Some(Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    info!("Created DEK: {dek}");
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
    .await?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
    .await
}

#[tokio::test]
pub(crate) async fn test_wrap_with_rsa_oaep() -> KmsCliResult<()> {
    log_init(None);
    // log_init(Some("debug"));
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let (_private_key_id, public_key_id) = CreateKeyPairAction {
        key_size: 2048,
        private_key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    println!("Wrapping key id: {public_key_id}");

    let dek = CreateKeyAction {
        key_id: Some(Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        wrapping_key_id: Some(public_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
    .await?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
    .await
}

#[tokio::test]
pub(crate) async fn test_unwrap_on_export() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let (_private_key_id, public_key_id) = CreateKeyPairAction {
        key_size: 2048,
        private_key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("===> Wrapping key id: {public_key_id}");

    let dek = CreateKeyAction {
        key_id: Some(Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        wrapping_key_id: Some(public_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("===> DEK id: {dek}");

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // TODO: Replace with equivalent export action when available
    ExportKeyAction {
        key_file: tmp_path.join("dek.pem"),
        key_id: Some(dek.to_string()),
        key_format: ExportKeyFormat::Raw,
        unwrap: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    Ok(())
}
