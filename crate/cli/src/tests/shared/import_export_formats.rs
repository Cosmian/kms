use std::path::PathBuf;

use crate::{
    actions::shared::{import_key::ImportKeyFormat, utils::read_bytes_from_file, ExportKeyFormat},
    error::CliError,
    tests::{
        shared::{export_key, import_key},
        utils::{start_default_test_kms_server, ONCE},
    },
};

#[tokio::test]
async fn test_import_export_pkcs8() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    let key_file_path = "test_data/key_encodings/ec_private_key_pkcs8.pem";
    let export_format = ExportKeyFormat::Pkcs8Pem;

    // import the  key
    let key_uid = import_key(
        &ctx.owner_cli_conf_path,
        "ec",
        key_file_path,
        Some(ImportKeyFormat::Pem),
        None,
        &[],
        false,
        false,
    )?;
    // export the key
    let exported_key_file = tempfile::NamedTempFile::new()?;
    export_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &key_uid,
        exported_key_file.path().to_str().unwrap(),
        Some(export_format),
        false,
        None,
        true,
    )?;
    // PEM Line Endings are LF in both cases
    let imported_bytes = read_bytes_from_file(&PathBuf::from(&key_file_path))?;
    let exported_bytes = read_bytes_from_file(&exported_key_file.path())?;
    assert_eq!(imported_bytes, exported_bytes);
    Ok(())
}
