use std::path::PathBuf;

use cosmian_kms_client::read_bytes_from_file;
use cosmian_kms_client_tests::{start_default_test_kms_server, TestsContext, ONCE};

use crate::{
    actions::shared::{import_key::ImportKeyFormat, ExportKeyFormat},
    error::CliError,
    tests::shared::{export_key, import_key},
};

#[tokio::test]
async fn test_import_export_encodings() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    test_pems(
        &ctx,
        "test_data/key_encodings/ec_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        &ctx,
        "test_data/key_encodings/ec_private_key_sec1.pem",
        ExportKeyFormat::Sec1Pem,
    )?;
    test_pems(
        &ctx,
        "test_data/key_encodings/ec_public_key_spki.pem",
        ExportKeyFormat::SpkiPem,
    )?;
    test_pems(
        &ctx,
        "test_data/key_encodings/rsa_private_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        &ctx,
        "test_data/key_encodings/rsa_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )?;
    test_pems(
        &ctx,
        "test_data/key_encodings/rsa_public_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )?;
    test_pems(
        &ctx,
        "test_data/key_encodings/rsa_public_key_spki.pem",
        ExportKeyFormat::SpkiPem,
    )?;

    Ok(())
}

fn test_pems(
    ctx: &&TestsContext,
    key_file_path: &str,
    export_format: ExportKeyFormat,
) -> Result<(), CliError> {
    // import the  key
    let key_uid = import_key(
        &ctx.owner_client_conf_path,
        "ec",
        key_file_path,
        Some(ImportKeyFormat::Pem),
        None,
        &[],
        false,
        true,
    )?;
    // PEM Line Endings are LF in both cases
    let imported_bytes = read_bytes_from_file(&PathBuf::from(&key_file_path))?;
    // export the key
    let export_key_file = tempfile::NamedTempFile::new()?;
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &key_uid,
        export_key_file.path().to_str().unwrap(),
        Some(export_format.clone()),
        false,
        None,
        true,
    )?;
    let export_bytes = read_bytes_from_file(&export_key_file.path())?;
    assert_eq!(imported_bytes, export_bytes);
    // Get the key
    let get_key_file = tempfile::NamedTempFile::new()?;
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &key_uid,
        get_key_file.path().to_str().unwrap(),
        Some(export_format),
        false,
        None,
        false,
    )?;
    let get_bytes = read_bytes_from_file(&get_key_file.path())?;
    assert_eq!(imported_bytes, get_bytes);

    Ok(())
}
