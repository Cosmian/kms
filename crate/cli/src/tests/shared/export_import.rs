use cosmian_kms_client::kmip::kmip_types::BlockCipherMode;
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;
use tracing::{debug, trace};

use crate::{
    error::result::CliResult,
    tests::{
        shared::{export_key, import_key, ExportKeyParams, ImportKeyParams},
        symmetric::create_key::create_symmetric_key,
    },
};

#[tokio::test]
pub(crate) async fn test_wrap_export_import() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // Generate a symmetric wrapping key
    let wrap_key_path = tmp_path.join("wrap.key");
    let key_file = wrap_key_path.to_str().unwrap().to_string();

    let sym_wrapping_key_id =
        create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;

    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;

    // Export and import the key with different block cipher modes
    for block_cipher_mode in [BlockCipherMode::GCM, BlockCipherMode::NISTKeyWrap] {
        debug!("block_cipher_mode: {block_cipher_mode}",);
        export_key(ExportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.to_string(),
            key_file: key_file.clone(),
            wrap_key_id: Some(sym_wrapping_key_id.clone()),
            block_cipher_mode: Some(block_cipher_mode.to_string()),
            ..Default::default()
        })?;

        let imported_key_id = import_key(ImportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_string(),
            key_file: key_file.clone(),
            key_id: Some(key_id.clone()),
            unwrap: true,
            replace_existing: true,
            ..Default::default()
        })?;
        trace!("imported key id: {imported_key_id}",);
    }

    // Export/import using GCM block cipher mode and different authenticated additional data
    for authenticated_additional_data in [None, Some("aad".to_string())] {
        export_key(ExportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.to_string(),
            key_file: key_file.clone(),
            wrap_key_id: Some(sym_wrapping_key_id.clone()),
            block_cipher_mode: Some(BlockCipherMode::GCM.to_string()),
            authenticated_additional_data: authenticated_additional_data.clone(),
            ..Default::default()
        })?;

        let imported_key_id = import_key(ImportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_string(),
            key_file: key_file.clone(),
            key_id: Some(key_id.clone()),
            unwrap: true,
            authenticated_additional_data: authenticated_additional_data.clone(),
            replace_existing: true,
            ..Default::default()
        })?;
        trace!("imported key id: {imported_key_id}",);
    }

    // Export with GCM + AAD but incorrect AAD on import
    export_key(ExportKeyParams {
        cli_conf_path: ctx.user_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.to_string(),
        key_file: key_file.clone(),
        wrap_key_id: Some(sym_wrapping_key_id),
        block_cipher_mode: Some(BlockCipherMode::GCM.to_string()),
        authenticated_additional_data: Some("aad".to_string()),
        ..Default::default()
    })?;

    assert!(
        import_key(ImportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_string(),
            key_file: key_file.clone(),
            key_id: Some(key_id.clone()),
            unwrap: true,
            replace_existing: true,
            ..Default::default()
        })
        .is_err()
    );

    assert!(
        import_key(ImportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_string(),
            key_file,
            key_id: Some(key_id),
            unwrap: true,
            replace_existing: true,
            authenticated_additional_data: Some("this is very bad".to_string()),
            ..Default::default()
        })
        .is_err()
    );

    Ok(())
}
