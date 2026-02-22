#[cfg(feature = "non-fips")]
use std::path::PathBuf;
use std::process::Command;

use assert_cmd::prelude::*;
#[cfg(feature = "non-fips")]
use cosmian_kms_cli::reexport::cosmian_kms_client::{
    kmip_2_1::kmip_types::CryptographicAlgorithm, read_object_from_json_ttlv_file,
};
use cosmian_kms_cli::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::{
    ImportKeyFormat, KeyUsage,
};
#[cfg(feature = "non-fips")]
use cosmian_logger::log_init;
#[cfg(feature = "non-fips")]
use test_kms_server::start_default_test_kms_server;

#[cfg(feature = "non-fips")]
use crate::tests::kms::{
    cover_crypt::master_key_pair::create_cc_master_key_pair,
    elliptic_curve::create_key_pair::create_ec_key_pair,
    shared::{ExportKeyParams, export_key},
    symmetric::create_key::create_symmetric_key,
};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            utils::{extract_uids::extract_unique_identifier, recover_cmd_logs},
        },
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
    pub(crate) public_key_id: Option<String>,
    pub(crate) private_key_id: Option<String>,
    pub(crate) certificate_id: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) key_usage_vec: Option<Vec<KeyUsage>>,
    pub(crate) unwrap: bool,
    pub(crate) replace_existing: bool,
    pub(crate) authenticated_additional_data: Option<String>,
}

pub(crate) fn import_key(params: ImportKeyParams) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, params.cli_conf_path);

    let mut args: Vec<String> = vec![
        "keys".to_owned(),
        "import".to_owned(),
        params.key_file.clone(),
    ];
    if let Some(key_id) = params.key_id {
        args.push(key_id);
    }
    if let Some(public_key_id) = params.public_key_id {
        args.push("--public-key-id".to_owned());
        args.push(public_key_id);
    }
    if let Some(private_key_id) = params.private_key_id {
        args.push("--private-key-id".to_owned());
        args.push(private_key_id);
    }
    if let Some(certificate_id) = params.certificate_id {
        args.push("--certificate-id".to_owned());
        args.push(certificate_id);
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
            ImportKeyFormat::Pkcs8Priv => "pkcs8-priv",
            ImportKeyFormat::Pkcs8Pub => "pkcs8-pub",
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
    cmd.arg(KMS_SUBCOMMAND).arg(params.sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let import_output = std::str::from_utf8(&output.stdout)?;
        let imported_key_id = extract_unique_identifier(import_output)
            .ok_or_else(|| {
                CosmianError::Default("failed extracting the imported key id".to_owned())
            })?
            .to_owned();
        return Ok(imported_key_id);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_import_cover_crypt() -> CosmianResult<()> {
    use tempfile::TempDir;

    use crate::tests::save_kms_cli_config;

    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new master key pair
    let (_master_secret_key_id, master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let public_key_path = format!("{}", tmp_path.join("public_key.json").display());

    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "cc".to_owned(),
        key_id: master_public_key_id.clone(),
        key_file: public_key_path.clone(),
        ..Default::default()
    })?;

    // reimporting the same key  with the same id should fail
    assert!(
        import_key(ImportKeyParams {
            cli_conf_path: owner_client_conf_path.clone(),
            sub_command: "cc".to_string(),
            key_file: public_key_path.clone(),
            key_id: Some(master_public_key_id.clone()),
            ..Default::default()
        })
        .is_err()
    );

    //...unless we force it with replace_existing
    let master_public_key_id_: String = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path,
        sub_command: "cc".to_string(),
        key_file: public_key_path,
        key_id: Some(master_public_key_id.clone()),
        replace_existing: true,
        ..Default::default()
    })?;
    assert_eq!(master_public_key_id_, master_public_key_id);

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_generate_export_import() -> CosmianResult<()> {
    use cosmian_kms_cli::{
        actions::kms::symmetric::keys::create_key::CreateKeyAction,
        reexport::cosmian_kms_client::kmip_2_1::kmip_types::CryptographicAlgorithm,
    };

    use crate::tests::save_kms_cli_config;

    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));

    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Covercrypt import/export test
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    export_import_test(
        &owner_client_conf_path,
        "cc",
        &private_key_id,
        CryptographicAlgorithm::CoverCrypt,
    )?;

    // Test import/export of an EC Key Pair
    let (private_key_id, _public_key_id) =
        create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;
    export_import_test(
        &owner_client_conf_path,
        "ec",
        &private_key_id,
        CryptographicAlgorithm::ECDH,
    )?;

    // generate a symmetric key
    let key_id = create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;
    export_import_test(
        &owner_client_conf_path,
        "sym",
        &key_id,
        CryptographicAlgorithm::AES,
    )?;

    Ok(())
}

#[cfg(feature = "non-fips")]
pub(crate) fn export_import_test(
    cli_conf_path: &str,
    sub_command: &str,
    private_key_id: &str,
    algorithm: CryptographicAlgorithm,
) -> CosmianResult<()> {
    // Export
    let export1 = std::env::temp_dir()
        .join("output.export")
        .to_string_lossy()
        .into_owned();
    let export2 = std::env::temp_dir()
        .join("output2.export")
        .to_string_lossy()
        .into_owned();
    export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_owned(),
        key_id: private_key_id.to_string(),
        key_file: export1.clone(),
        ..Default::default()
    })?;

    let object = read_object_from_json_ttlv_file(&PathBuf::from(&export1))?;
    let key_bytes = match algorithm {
        CryptographicAlgorithm::AES => object.key_block()?.key_bytes()?,
        CryptographicAlgorithm::ECDH => object.key_block()?.ec_raw_bytes()?,
        CryptographicAlgorithm::CoverCrypt => object.key_block()?.covercrypt_key_bytes()?,
        x => {
            return Err(CosmianError::Default(format!(
                "unsupported algorithm for export: {x:?}"
            )));
        }
    };

    // import and re-export
    let import_params = ImportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_string(),
        key_file: export1,
        ..Default::default()
    };

    let uid: String = import_key(import_params)?;
    export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_owned(),
        key_id: uid,
        key_file: export2.clone(),
        ..Default::default()
    })?;
    let object2 = read_object_from_json_ttlv_file(&PathBuf::from(&export2))?;
    let object2_key_bytes = match algorithm {
        CryptographicAlgorithm::AES => object2.key_block()?.key_bytes()?,
        CryptographicAlgorithm::ECDH => object2.key_block()?.ec_raw_bytes()?,
        CryptographicAlgorithm::CoverCrypt => object2.key_block()?.covercrypt_key_bytes()?,
        x => {
            return Err(CosmianError::Default(format!(
                "unsupported algorithm for export: {x:?}"
            )));
        }
    };
    assert_eq!(object2_key_bytes, key_bytes);
    assert_eq!(
        object2.key_block()?.cryptographic_algorithm,
        Some(algorithm)
    );
    assert!(object2.key_block()?.key_wrapping_data.is_none());

    Ok(())
}
