#[cfg(feature = "non-fips")]
use cosmian_kms_cli::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat;
use cosmian_kms_cli::{actions::kms::symmetric::{keys::create_key::CreateKeyAction, KeyEncryptionAlgorithm}, reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    create_utils::SymmetricAlgorithm, symmetric_utils::DataEncryptionAlgorithm,
}};
use cosmian_logger::log_init;
#[cfg(feature = "non-fips")]
use tempfile::TempDir;
#[cfg(feature = "non-fips")]
use cosmian_logger::info;
use uuid::Uuid;

#[cfg(feature = "non-fips")]
use crate::tests::kms::{
    rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
    shared::{ExportKeyParams, export_key},
};
use crate::{
    error::result::CosmianResult,
    tests::{
        kms::symmetric::{
            create_key::create_symmetric_key, encrypt_decrypt::run_encrypt_decrypt_test,
        },
        save_kms_cli_config,
    },
};
use test_kms_server::TestsContext;

pub(crate) fn test_wrap_with_aes_gcm(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let wrapping_key_id = create_symmetric_key(
        &owner_client_conf_path,
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
        &owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(wrapping_key_id),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
}

#[cfg(feature = "non-fips")]
pub(crate) fn test_wrap_with_rsa_oaep(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(None);
    // log_init(Some("debug"));
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {public_key_id}");
    let dek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(public_key_id),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
}

#[cfg(feature = "non-fips")]
pub(crate) fn test_unwrap_on_export(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    info!("===> Wrapping key id: {public_key_id}");
    let dek = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(public_key_id),
            ..Default::default()
        },
    )?;
    info!("===> DEK id: {dek}");
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path,
        sub_command: "sym".to_owned(),
        key_id: dek,
        key_file: tmp_path.join("dek.pem").to_str().unwrap().to_owned(),
        unwrap: true,
        key_format: Some(ExportKeyFormat::Raw),
        ..Default::default()
    })?;
    Ok(())
}
