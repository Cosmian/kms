#[cfg(feature = "non-fips")]
use cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat;
use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    create_utils::SymmetricAlgorithm, symmetric_utils::DataEncryptionAlgorithm,
};
use cosmian_logger::{info, log_init};
#[cfg(feature = "non-fips")]
use tempfile::TempDir;
use test_kms_server::TestsContext;
use uuid::Uuid;

use crate::{
    actions::kms::symmetric::{KeyEncryptionAlgorithm, keys::create_key::CreateKeyAction},
    error::result::KmsCliResult,
    tests::kms::symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
};

pub(super) async fn test_wrap_with_aes_gcm(ctx: &TestsContext) -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));

    let wrapping_key_id = CreateKeyAction {
        key_id: Some("hsm::0::".to_owned() + &Uuid::new_v4().to_string()),
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
            + 12 /* nonce */  + 16, // ag
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
            + 12 /* nonce */  + 16, // ag
    )
    .await
}

#[cfg(feature = "non-fips")]
pub(super) async fn test_wrap_with_rsa_oaep(ctx: &TestsContext) -> KmsCliResult<()> {
    use crate::{
        actions::kms::rsa::keys::create_key_pair::CreateKeyPairAction,
        tests::kms::symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
    };

    log_init(None);
    // log_init(Some("debug"));

    let (_private_key_id, public_key_id) = CreateKeyPairAction {
        key_size: 2048,
        private_key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("Wrapping key id: {public_key_id}");

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
            + 12 /* nonce */  + 16, // ag
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
            + 12 /* nonce */  + 16, // ag
    )
    .await
}

#[cfg(feature = "non-fips")]
pub(super) async fn test_unwrap_on_export(ctx: &TestsContext) -> KmsCliResult<()> {
    use crate::actions::kms::{
        rsa::keys::create_key_pair::CreateKeyPairAction, shared::ExportSecretDataOrKeyAction,
    };

    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

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
    ExportSecretDataOrKeyAction {
        key_file: tmp_path.join("dek.pem"),
        key_id: Some(dek.to_string()),
        export_format: ExportKeyFormat::Raw,
        unwrap: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    Ok(())
}
