use std::path::PathBuf;

use cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::{
        export_utils::ExportKeyFormat, import_utils::ImportKeyFormat,
    },
};
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::kms::shared::{ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction},
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_import_export_encodings() -> KmsCliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    test_pems(
        ctx,
        "../../test_data/key_encodings/ec_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )
    .await?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/ec_private_key_sec1.pem",
        ExportKeyFormat::Sec1Pem,
    )
    .await?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_private_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )
    .await?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_private_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )
    .await?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_public_key_pkcs1.pem",
        ExportKeyFormat::Pkcs1Pem,
    )
    .await?;
    test_pems(
        ctx,
        "../../test_data/key_encodings/rsa_public_key_pkcs8.pem",
        ExportKeyFormat::Pkcs8Pem,
    )
    .await?;

    Ok(())
}

async fn test_pems(
    ctx: &TestsContext,
    key_file_path: &str,
    export_format: ExportKeyFormat,
) -> KmsCliResult<()> {
    // import the key
    let key_uid = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(&key_file_path.to_string()),
        key_format: ImportKeyFormat::Pem,
        replace_existing: true,
        key_usage: None,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // PEM Line Endings are LF in both cases
    let imported_bytes = read_bytes_from_file(&PathBuf::from(&key_file_path))?;

    // export the key
    let export_key_file = tempfile::NamedTempFile::new()?;
    ExportSecretDataOrKeyAction {
        key_id: Some(key_uid.clone()),
        key_file: export_key_file.path().to_path_buf(),
        key_format: export_format.clone(),
        allow_revoked: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let export_bytes = read_bytes_from_file(&export_key_file.path())?;
    assert_eq!(imported_bytes, export_bytes);

    // Get the key
    let get_key_file = tempfile::NamedTempFile::new()?;
    ExportSecretDataOrKeyAction {
        key_id: Some(key_uid),
        key_file: get_key_file.path().to_path_buf(),
        key_format: export_format,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let get_bytes = read_bytes_from_file(&get_key_file.path())?;
    assert_eq!(imported_bytes, get_bytes);

    Ok(())
}
