use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;

use crate::{
    actions::shared::utils::read_key_from_file,
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        elliptic_curve::create_key_pair::create_ec_key_pair,
        shared::export::export,
        symmetric::create_key::create_symmetric_key,
        test_utils::{init_test_server, ONCE},
        utils::extract_uids::extract_imported_key_id,
        CONF_PATH, PROG_NAME,
    },
};

pub async fn import(
    sub_command: &str,
    key_file: &str,
    key_id: Option<String>,
    unwrap: bool,
    replace_existing: bool,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    let mut args: Vec<String> = vec!["keys".to_owned(), "import".to_owned(), key_file.to_owned()];
    if let Some(key_id) = key_id {
        args.push(key_id);
    }
    if unwrap {
        args.push("-u".to_owned());
    }
    if replace_existing {
        args.push("-r".to_owned());
    }
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        let import_output = std::str::from_utf8(&output.stdout)?;
        let imported_key_id = extract_imported_key_id(import_output)
            .ok_or_else(|| CliError::Default("failed extracting the imported key id".to_owned()))?
            .to_owned();
        return Ok(imported_key_id)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_import_cover_crypt() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    let uid: String = import("cc", "test_data/ttlv_public_key.json", None, false, false).await?;
    assert_eq!(uid.len(), 36);

    // reimporting the same key  with the same id should fail
    assert!(
        import(
            "cc",
            "test_data/ttlv_public_key.json",
            Some(uid.clone()),
            false,
            false,
        )
        .await
        .is_err()
    );

    //...unless we force it with replace_existing
    let uid_: String = import(
        "cc",
        "test_data/ttlv_public_key.json",
        Some(uid.clone()),
        false,
        true,
    )
    .await?;
    assert_eq!(uid_, uid);

    Ok(())
}

#[tokio::test]
pub async fn test_generate_export_import() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    // Generate
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;
    export_import_test("cc", &private_key_id, CryptographicAlgorithm::CoverCrypt).await?;

    // generate a new key pair
    let (private_key_id, _public_key_id) = create_ec_key_pair().await?;
    export_import_test("ec", &private_key_id, CryptographicAlgorithm::ECDH).await?;

    // generate a symmetric key
    let key_id = create_symmetric_key(None, None, None).await?;
    export_import_test("sym", &key_id, CryptographicAlgorithm::AES).await?;

    Ok(())
}

pub async fn export_import_test(
    sub_command: &str,
    private_key_id: &str,
    algorithm: CryptographicAlgorithm,
) -> Result<(), CliError> {
    // Export
    export(
        sub_command,
        private_key_id,
        "/tmp/output.export",
        false,
        false,
        None,
        false,
    )
    .await?;
    let object = read_key_from_file(&PathBuf::from("/tmp/output.export"))?;
    let key_bytes = object.key_block()?.key_bytes()?.to_owned();

    // import and re-export
    let uid: String = import(sub_command, "/tmp/output.export", None, false, false).await?;
    export(
        sub_command,
        &uid,
        "/tmp/output.export",
        false,
        false,
        None,
        false,
    )
    .await?;
    let object = read_key_from_file(&PathBuf::from("/tmp/output.export"))?;
    assert_eq!(object.key_block()?.key_bytes()?, key_bytes);
    assert_eq!(object.key_block()?.cryptographic_algorithm, algorithm);
    assert!(object.key_block()?.key_wrapping_data.is_none());

    Ok(())
}
