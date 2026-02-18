use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::WrappingAlgorithm,
};
use cosmian_logger::{debug, log_init};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        kms::{
            shared::{ExportKeyParams, ImportKeyParams, export_key, import_key},
            symmetric::create_key::create_symmetric_key,
        },
        save_kms_cli_config,
    },
};

#[tokio::test]
pub(crate) async fn test_wrap_on_export_unwrap_on_import() -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Generate a symmetric wrapping key
    let kek_id = create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;

    // Generate a symmetric key to wrap
    let dek_path = tmp_path.join("dek.key");
    let dek_file = dek_path.to_str().unwrap().to_string();
    let dek_id = create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;

    // Export and import the key with different block cipher modes
    for wrapping_algorithm in [WrappingAlgorithm::AesGCM, WrappingAlgorithm::NistKeyWrap] {
        debug!("wrapping algorithm: {:?}", wrapping_algorithm);
        export_key(ExportKeyParams {
            cli_conf_path: user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: dek_id.clone(),
            key_file: dek_file.clone(),
            wrap_key_id: Some(kek_id.clone()),
            wrapping_algorithm: Some(wrapping_algorithm.clone()),
            ..Default::default()
        })?;

        let imported_key_id = import_key(ImportKeyParams {
            cli_conf_path: user_client_conf_path.clone(),
            sub_command: "sym".to_string(),
            key_file: dek_file.clone(),
            key_id: Some(dek_id.clone()),
            unwrap: true,
            replace_existing: true,
            ..Default::default()
        })?;
        debug!("imported key id: {imported_key_id}",);
    }

    Ok(())
}
