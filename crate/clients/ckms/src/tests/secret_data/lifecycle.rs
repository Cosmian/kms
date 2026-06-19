
use cosmian_kms_cli_actions::{
    actions::secret_data::create_secret::CreateSecretDataAction,
    reexport::cosmian_kms_client::{
        kmip_2_1::{kmip_objects::Object, kmip_types::KeyFormatType},
        read_object_from_json_ttlv_file,
        reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat,
    },
};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::tests::utils::{ckms_bin, owner_config};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, secret_data::create_secret::create_secret_data, utils::recover_cmd_logs},
};

fn destroy_secret_data(cli_conf_path: &str, secret_id: &str, remove: bool) -> CosmianResult<()> {
    let mut args: Vec<String> = vec![
        "destroy".to_owned(),
        "--key-id".to_owned(),
        secret_id.to_owned(),
    ];
    if remove {
        args.push("--remove".to_owned());
    }
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg("secret-data").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn revoke_secret_data(cli_conf_path: &str, secret_id: &str, reason: &str) -> CosmianResult<()> {
    let args: Vec<String> = vec![
        "revoke".to_owned(),
        reason.to_owned(),
        "--secret-data-id".to_owned(),
        secret_id.to_owned(),
    ];
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg("secret-data").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn export_secret_data(
    cli_conf_path: &str,
    secret_id: &str,
    key_file: &str,
    export_format: Option<ExportKeyFormat>,
) -> CosmianResult<()> {
    let mut args: Vec<String> = vec![
        "export".to_owned(),
        key_file.to_owned(),
        "--key-id".to_owned(),
        secret_id.to_owned(),
    ];
    if let Some(format) = export_format {
        args.push("--key-format".to_owned());
        let arg_value = match format {
            ExportKeyFormat::JsonTtlv => "json-ttlv",
            ExportKeyFormat::Sec1Pem => "sec1-pem",
            ExportKeyFormat::Sec1Der => "sec1-der",
            ExportKeyFormat::Pkcs1Pem => "pkcs1-pem",
            ExportKeyFormat::Pkcs1Der => "pkcs1-der",
            ExportKeyFormat::Pkcs8Pem => "pkcs8-pem",
            ExportKeyFormat::Pkcs8Der => "pkcs8-der",
            ExportKeyFormat::Base64 => "base64",
            ExportKeyFormat::Raw => "raw",
        };
        args.push(arg_value.to_owned());
    }
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg("secret-data").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_destroy_secret_data() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create secret data
    let secret_id =
        create_secret_data(&owner_client_conf_path, &CreateSecretDataAction::default())?;

    // destroy should not work when not revoked
    assert!(destroy_secret_data(&owner_client_conf_path, &secret_id, false).is_err());

    // revoke then destroy
    revoke_secret_data(&owner_client_conf_path, &secret_id, "revocation test")?;
    destroy_secret_data(&owner_client_conf_path, &secret_id, false)?;

    // assert fails since a destroyed key cannot be exported
    let tmp_dir = TempDir::new()?;
    let export_file = tmp_dir.path().join("output.export");
    assert!(
        export_secret_data(
            &owner_client_conf_path,
            &secret_id,
            export_file.to_str().unwrap(),
            None,
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn test_revoke_secret_data() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let secret_id =
        create_secret_data(&owner_client_conf_path, &CreateSecretDataAction::default())?;

    revoke_secret_data(&owner_client_conf_path, &secret_id, "revocation test")?;

    // after revocation, export should fail without --allow-revoked
    let tmp_dir = TempDir::new()?;
    let export_file = tmp_dir.path().join("output.export");
    assert!(
        export_secret_data(
            &owner_client_conf_path,
            &secret_id,
            export_file.to_str().unwrap(),
            None,
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn test_export_secret_data() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create secret data
    let secret_id =
        create_secret_data(&owner_client_conf_path, &CreateSecretDataAction::default())?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    let tmp_dir = TempDir::new()?;
    let export_file = tmp_dir.path().join("output.export");
    export_secret_data(
        &owner_client_conf_path,
        &secret_id,
        export_file.to_str().unwrap(),
        None,
    )?;

    // Read and verify the exported object
    let object = read_object_from_json_ttlv_file(&export_file)?;
    let Object::SecretData(secret_data) = object else {
        panic!("Expected SecretData object");
    };
    let key_block = &secret_data.key_block;
    assert_eq!(key_block.key_format_type, KeyFormatType::Raw);
    let key_bytes = key_block.secret_data_bytes()?;
    assert_eq!(key_bytes.len(), 32);

    // Export as raw bytes
    let raw_export_file = tmp_dir.path().join("output.raw");
    export_secret_data(
        &owner_client_conf_path,
        &secret_id,
        raw_export_file.to_str().unwrap(),
        Some(ExportKeyFormat::Raw),
    )?;
    let raw_bytes = std::fs::read(&raw_export_file)?;
    assert_eq!(key_bytes.as_slice(), raw_bytes.as_slice());

    // Wrong export format should fail
    let bad_export_file = tmp_dir.path().join("output.bad");
    assert!(
        export_secret_data(
            &owner_client_conf_path,
            &secret_id,
            bad_export_file.to_str().unwrap(),
            Some(ExportKeyFormat::Pkcs1Pem),
        )
        .is_err()
    );

    Ok(())
}
