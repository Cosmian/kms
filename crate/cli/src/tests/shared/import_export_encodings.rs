use std::path::PathBuf;

use cosmian_kms_client::read_bytes_from_file;
use kms_test_server::{start_default_test_kms_server, TestsContext};

use crate::{
    actions::shared::{import_key::ImportKeyFormat, ExportKeyFormat},
    error::result::CliResult,
    tests::shared::{export_key, import_key, ExportKeyParams, ImportKeyParams},
};

#[tokio::test]
async fn test_import_export_encodings() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    test_pems(
        ctx,
        "test_data/key_encodings/ec_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        ctx,
        "test_data/key_encodings/ec_private_key_sec1.pem",
        ExportKeyFormat::Sec1Pem,
    )?;
    test_pems(
        ctx,
        "test_data/key_encodings/ec_public_key_spki.pem",
        ExportKeyFormat::SpkiPem,
    )?;
    test_pems(
        ctx,
        "test_data/key_encodings/rsa_private_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        ctx,
        "test_data/key_encodings/rsa_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        ctx,
        "test_data/key_encodings/rsa_public_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        ctx,
        "test_data/key_encodings/rsa_public_key_spki.pem",
        ExportKeyFormat::SpkiPem,
    )?;

    Ok(())
}

fn test_pems(
    ctx: &TestsContext,
    key_file_path: &str,
    export_format: ExportKeyFormat,
) -> CliResult<()> {
    // import the  key
    let key_uid = import_key(ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_string(),
        key_file: key_file_path.to_string(),
        key_format: Some(ImportKeyFormat::Pem),
        replace_existing: true,
        ..Default::default()
    })?;
    // PEM Line Endings are LF in both cases
    let imported_bytes = read_bytes_from_file(&PathBuf::from(&key_file_path))?;
    // export the key
    let export_key_file = tempfile::NamedTempFile::new()?;

    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: key_uid.clone(),
        key_file: export_key_file.path().to_str().unwrap().to_string(),
        key_format: Some(export_format.clone()),
        allow_revoked: true,
        ..Default::default()
    })?;

    let export_bytes = read_bytes_from_file(&export_key_file.path())?;
    assert_eq!(imported_bytes, export_bytes);
    // Get the key
    let get_key_file = tempfile::NamedTempFile::new()?;
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: key_uid,
        key_file: get_key_file.path().to_str().unwrap().to_string(),
        key_format: Some(export_format),
        ..Default::default()
    })?;
    let get_bytes = read_bytes_from_file(&get_key_file.path())?;
    assert_eq!(imported_bytes, get_bytes);

    Ok(())
}
