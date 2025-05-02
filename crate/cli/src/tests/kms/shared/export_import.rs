use std::path::PathBuf;

use cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::WrappingAlgorithm;
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;
use tracing::debug;

use crate::{
    actions::kms::{
        shared::{ExportKeyAction, ImportKeyAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_wrap_on_export_unwrap_on_import() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Generate a symmetric wrapping key
    let kek_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // Generate a symmetric key to wrap
    let dek_path = tmp_path.join("dek.key");
    let dek_file = dek_path.to_str().unwrap().to_string();
    let dek_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // Export and import the key with different block cipher modes
    for wrapping_algorithm in [WrappingAlgorithm::AesGCM, WrappingAlgorithm::NistKeyWrap] {
        debug!("wrapping algorithm: {wrapping_algorithm}",);
        ExportKeyAction {
            key_id: Some(dek_id.clone()),
            key_file: dek_path.clone(),
            wrap_key_id: Some(kek_id.clone()),
            wrapping_algorithm: Some(wrapping_algorithm),
            ..Default::default()
        }
        .run(ctx.get_user_client())
        .await?;

        let imported_key_id = ImportKeyAction {
            key_file: PathBuf::from(&dek_file),
            key_id: Some(dek_id.clone()),
            unwrap: true,
            replace_existing: true,
            key_usage: None,
            ..Default::default()
        }
        .run(ctx.get_user_client())
        .await?
        .to_string();
        debug!("imported key id: {imported_key_id}",);
    }

    Ok(())
}
