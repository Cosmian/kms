use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{
    cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm, read_object_from_json_ttlv_file,
    KMS_CLI_CONF_ENV,
};
#[cfg(not(feature = "fips"))]
use kms_test_server::start_default_test_kms_server;

#[cfg(not(feature = "fips"))]
use crate::tests::{
    cover_crypt::master_key_pair::create_cc_master_key_pair,
    elliptic_curve::create_key_pair::create_ec_key_pair,
    symmetric::create_key::create_symmetric_key,
};
use crate::{
    actions::shared::{import_key::ImportKeyFormat, utils::KeyUsage},
    error::{result::CliResult, CliError},
    tests::{
        shared::{export::export_key, ExportKeyParams},
        utils::{extract_uids::extract_unique_identifier, recover_cmd_logs},
        PROG_NAME,
    },
};

#[derive(Default, Debug)]
pub(crate) struct ImportKeyParams {
    // TODO: should be replaced by ImportKeyAction
    pub(crate) cli_conf_path: String,
    pub(crate) sub_command: String,
    pub(crate) key_file: String,
    pub(crate) key_format: Option<ImportKeyFormat>,
    pub(crate) key_id: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) key_usage_vec: Option<Vec<KeyUsage>>,
    pub(crate) unwrap: bool,
    pub(crate) replace_existing: bool,
    pub(crate) authenticated_additional_data: Option<String>,
}

pub(crate) fn import_key(params: ImportKeyParams) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, params.cli_conf_path);

    let mut args: Vec<String> = vec![
        "keys".to_owned(),
        "import".to_owned(),
        params.key_file.clone(),
    ];
    if let Some(key_id) = params.key_id {
        args.push(key_id);
    }
    for tag in params.tags {
        args.push("--tag".to_owned());
        args.push(tag.clone());
    }
    if let Some(key_format) = params.key_format {
        args.push("--key-format".to_owned());
        let kfs = match key_format {
            ImportKeyFormat::JsonTtlv => "json-ttlv",
            ImportKeyFormat::Pem => "pem",
            ImportKeyFormat::Sec1 => "sec1",
            ImportKeyFormat::Pkcs1Priv => "pkcs1-priv",
            ImportKeyFormat::Pkcs1Pub => "pkcs1-pub",
            ImportKeyFormat::Pkcs8 => "pkcs8",
            ImportKeyFormat::Spki => "spki",
            ImportKeyFormat::Aes => "aes",
            ImportKeyFormat::Chacha20 => "chacha20",
        };
        args.push(kfs.to_string());
    }
    if let Some(key_usage_vec) = params.key_usage_vec {
        for key_usage in key_usage_vec {
            args.push("--key-usage".to_owned());
            args.push(key_usage.into());
        }
    }
    if params.unwrap {
        args.push("-u".to_owned());
    }
    if let Some(aad) = params.authenticated_additional_data {
        args.push("--authenticated-additional-data".to_owned());
        args.push(aad);
    }
    if params.replace_existing {
        args.push("-r".to_owned());
    }
    cmd.arg(params.sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let import_output = std::str::from_utf8(&output.stdout)?;
        let imported_key_id = extract_unique_identifier(import_output)
            .ok_or_else(|| CliError::Default("failed extracting the imported key id".to_owned()))?
            .to_owned();
        return Ok(imported_key_id)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_import_cover_crypt() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;

    let import_params = ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "cc".to_string(),
        key_file: "test_data/ttlv_public_key.json".to_string(),
        ..Default::default()
    };

    let uid: String = import_key(import_params)?;
    assert_eq!(uid.len(), 36);

    // reimporting the same key  with the same id should fail
    assert!(
        import_key(ImportKeyParams {
            cli_conf_path: ctx.owner_client_conf_path.clone(),
            sub_command: "cc".to_string(),
            key_file: "test_data/ttlv_public_key.json".to_string(),
            key_id: Some(uid.clone()),
            ..Default::default()
        })
        .is_err()
    );

    //...unless we force it with replace_existing
    let uid_: String = import_key(ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "cc".to_string(),
        key_file: "test_data/ttlv_public_key.json".to_string(),
        key_id: Some(uid.clone()),
        replace_existing: true,
        ..Default::default()
    })?;
    assert_eq!(uid_, uid);

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_generate_export_import() -> CliResult<()> {
    cosmian_logger::log_utils::log_init(Some("cosmian_kms_server=debug,cosmian_kms_utils=debug"));
    let ctx = start_default_test_kms_server().await;

    // Covercrypt import/export test
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;
    export_import_test(
        &ctx.owner_client_conf_path,
        "cc",
        &private_key_id,
        CryptographicAlgorithm::CoverCrypt,
    )?;

    // Test import/export of an EC Key Pair
    let (private_key_id, _public_key_id) =
        create_ec_key_pair(&ctx.owner_client_conf_path, "nist-p256", &[])?;
    export_import_test(
        &ctx.owner_client_conf_path,
        "ec",
        &private_key_id,
        CryptographicAlgorithm::ECDH,
    )?;

    // generate a symmetric key
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    export_import_test(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        CryptographicAlgorithm::AES,
    )?;

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn export_import_test(
    cli_conf_path: &str,
    sub_command: &str,
    private_key_id: &str,
    algorithm: CryptographicAlgorithm,
) -> CliResult<()> {
    // Export
    export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_owned(),
        key_id: private_key_id.to_string(),
        key_file: "/tmp/output.export".to_owned(),
        ..Default::default()
    })?;

    let object = read_object_from_json_ttlv_file(&PathBuf::from("/tmp/output.export"))?;
    let key_bytes = object.key_block()?.key_bytes()?;

    // import and re-export
    let import_params = ImportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_string(),
        key_file: "/tmp/output.export".to_string(),
        ..Default::default()
    };

    let uid: String = import_key(import_params)?;
    export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_owned(),
        key_id: uid,
        key_file: "/tmp/output2.export".to_owned(),
        ..Default::default()
    })?;
    let object2 = read_object_from_json_ttlv_file(&PathBuf::from("/tmp/output2.export"))?;
    assert_eq!(object2.key_block()?.key_bytes()?, key_bytes);
    assert_eq!(
        object2.key_block()?.cryptographic_algorithm,
        Some(algorithm)
    );
    assert!(object2.key_block()?.key_wrapping_data.is_none());

    Ok(())
}
