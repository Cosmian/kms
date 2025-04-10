use std::path::PathBuf;

use cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::{
        export_utils::ExportKeyFormat, import_utils::ImportKeyFormat,
    },
};
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    error::result::CosmianResult,
    tests::kms::shared::{ExportKeyParams, ImportKeyParams, export_key, import_key},
};

#[tokio::test]
async fn test_import_export_encodings() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    test_pems(
        ctx,
        "../../test_data/key_encodings/ec_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/ec_private_key_sec1.pem",
        ExportKeyFormat::Sec1Pem,
    )?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_private_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_public_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_public_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;

    Ok(())
}

fn test_pems(
    ctx: &TestsContext,
    key_file_path: &str,
    export_format: ExportKeyFormat,
) -> CosmianResult<()> {
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
