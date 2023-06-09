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
        utils::{extract_uids::extract_imported_key_id, init_test_server, ONCE},
        PROG_NAME,
    },
};

pub fn import(
    cli_conf_path: &str,
    sub_command: &str,
    key_file: &str,
    key_id: Option<String>,
    unwrap: bool,
    replace_existing: bool,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
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
    let ctx = ONCE.get_or_init(init_test_server).await;

    let uid: String = import(
        &ctx.owner_cli_conf_path,
        "cc",
        "test_data/ttlv_public_key.json",
        None,
        false,
        false,
    )?;
    assert_eq!(uid.len(), 36);

    // reimporting the same key  with the same id should fail
    assert!(
        import(
            &ctx.owner_cli_conf_path,
            "cc",
            "test_data/ttlv_public_key.json",
            Some(uid.clone()),
            false,
            false,
        )
        .is_err()
    );

    //...unless we force it with replace_existing
    let uid_: String = import(
        &ctx.owner_cli_conf_path,
        "cc",
        "test_data/ttlv_public_key.json",
        Some(uid.clone()),
        false,
        true,
    )?;
    assert_eq!(uid_, uid);

    Ok(())
}

#[tokio::test]
pub async fn test_generate_export_import() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    // Generate
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )?;
    export_import_test(
        &ctx.owner_cli_conf_path,
        "cc",
        &private_key_id,
        CryptographicAlgorithm::CoverCrypt,
    )?;

    // generate a new key pair
    let (private_key_id, _public_key_id) = create_ec_key_pair(&ctx.owner_cli_conf_path)?;
    export_import_test(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_id,
        CryptographicAlgorithm::ECDH,
    )?;

    // generate a symmetric key
    let key_id = create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None)?;
    export_import_test(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_id,
        CryptographicAlgorithm::AES,
    )?;

    Ok(())
}

pub fn export_import_test(
    cli_conf_path: &str,
    sub_command: &str,
    private_key_id: &str,
    algorithm: CryptographicAlgorithm,
) -> Result<(), CliError> {
    // Export
    export(
        cli_conf_path,
        sub_command,
        private_key_id,
        "/tmp/output.export",
        false,
        false,
        None,
        false,
    )?;
    let object = read_key_from_file(&PathBuf::from("/tmp/output.export"))?;
    let key_bytes = object.key_block()?.key_bytes()?;

    // import and re-export
    let uid: String = import(
        cli_conf_path,
        sub_command,
        "/tmp/output.export",
        None,
        false,
        false,
    )?;
    export(
        cli_conf_path,
        sub_command,
        &uid,
        "/tmp/output.export",
        false,
        false,
        None,
        false,
    )?;
    let object = read_key_from_file(&PathBuf::from("/tmp/output.export"))?;
    assert_eq!(object.key_block()?.key_bytes()?, key_bytes);
    assert_eq!(object.key_block()?.cryptographic_algorithm, algorithm);
    assert!(object.key_block()?.key_wrapping_data.is_none());

    Ok(())
}
