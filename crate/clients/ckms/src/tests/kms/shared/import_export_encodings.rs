use std::path::PathBuf;

use cosmian_kms_cli::reexport::cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::{
        export_utils::ExportKeyFormat, import_utils::ImportKeyFormat,
    },
};
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        kms::shared::{ExportKeyParams, ImportKeyParams, export_key, import_key},
        save_kms_cli_config,
    },
};

#[tokio::test]
async fn test_import_export_encodings() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    test_pems(
        &owner_client_conf_path,
        "../../../test_data/key_encodings/ec_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        &owner_client_conf_path,
        "../../../test_data/key_encodings/ec_private_key_sec1.pem",
        ExportKeyFormat::Sec1Pem,
    )?;
    test_pems(
        &owner_client_conf_path,
        "../../../test_data/key_encodings/rsa_private_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        &owner_client_conf_path,
        "../../../test_data/key_encodings/rsa_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        &owner_client_conf_path,
        "../../../test_data/key_encodings/rsa_public_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        &owner_client_conf_path,
        "../../../test_data/key_encodings/rsa_public_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;

    Ok(())
}

fn test_pems(
    owner_client_conf_path: &str,
    key_file_path: &str,
    export_format: ExportKeyFormat,
) -> CosmianResult<()> {
    // import the  key
    let key_uid = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.to_string(),
        sub_command: "ec".to_string(),
        key_file: key_file_path.to_string(),
        key_format: Some(ImportKeyFormat::Pem),
        replace_existing: true,
        ..Default::default()
    })?;
    // Read imported bytes and normalize line endings to match platform-specific exports
    // On Windows, some writers may emit CRLF; align both sides before assert
    #[cfg(windows)]
    let mut imported_bytes = read_bytes_from_file(&PathBuf::from(&key_file_path))?;
    #[cfg(not(windows))]
    let imported_bytes = read_bytes_from_file(&PathBuf::from(&key_file_path))?;
    #[cfg(windows)]
    {
        let as_string = String::from_utf8_lossy(&imported_bytes).replace("\r\n", "\n");
        imported_bytes = as_string.replace("\n", "\r\n").into_bytes();
    }
    // export the key
    let export_key_file = tempfile::NamedTempFile::new()?;

    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.to_string(),
        sub_command: "ec".to_owned(),
        key_id: key_uid.clone(),
        key_file: export_key_file.path().to_str().unwrap().to_string(),
        key_format: Some(export_format.clone()),
        allow_revoked: true,
        ..Default::default()
    })?;

    #[cfg(windows)]
    let mut export_bytes = read_bytes_from_file(&export_key_file.path())?;
    #[cfg(not(windows))]
    let export_bytes = read_bytes_from_file(&export_key_file.path())?;
    #[cfg(windows)]
    {
        let as_string = String::from_utf8_lossy(&export_bytes).replace("\r\n", "\n");
        export_bytes = as_string.replace("\n", "\r\n").into_bytes();
    }
    assert_eq!(imported_bytes, export_bytes);
    // Get the key
    let get_key_file = tempfile::NamedTempFile::new()?;
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.to_string(),
        sub_command: "ec".to_owned(),
        key_id: key_uid,
        key_file: get_key_file.path().to_str().unwrap().to_string(),
        key_format: Some(export_format),
        ..Default::default()
    })?;
    #[cfg(windows)]
    let mut get_bytes = read_bytes_from_file(&get_key_file.path())?;
    #[cfg(not(windows))]
    let get_bytes = read_bytes_from_file(&get_key_file.path())?;
    #[cfg(windows)]
    {
        let as_string = String::from_utf8_lossy(&get_bytes).replace("\r\n", "\n");
        get_bytes = as_string.replace("\n", "\r\n").into_bytes();
    }
    assert_eq!(imported_bytes, get_bytes);

    Ok(())
}
