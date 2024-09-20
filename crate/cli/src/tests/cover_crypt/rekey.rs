use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;

use crate::{
    actions::shared::utils::KeyUsage,
    error::{result::CliResult, CliError},
    tests::{
        cover_crypt::{
            encrypt_decrypt::{decrypt, encrypt},
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key,
            SUB_COMMAND,
        },
        shared::{export_key, import_key, ExportKeyParams, ImportKeyParams},
        symmetric::create_key::create_symmetric_key,
        utils::recover_cmd_logs,
        PROG_NAME,
    },
};

pub(crate) async fn rekey(
    cli_conf_path: &str,
    master_private_key_id: &str,
    access_policy: &str,
) -> CliResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let args = vec![
        "keys",
        "rekey",
        "--key-id",
        master_private_key_id,
        access_policy,
    ];
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("were rekeyed") {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) async fn prune(
    cli_conf_path: &str,
    master_private_key_id: &str,
    access_policy: &str,
) -> CliResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let args = vec![
        "keys",
        "prune",
        "--key-id",
        master_private_key_id,
        access_policy,
    ];
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("were pruned") {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_rekey_error() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;
    let _user_decryption_key = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
    );

    // bad attributes
    assert!(
        rekey(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "bad_access_policy"
        )
        .await
        .is_err()
    );

    // bad keys
    assert!(
        rekey(
            &ctx.owner_client_conf_path,
            "bad_key",
            "Department::MKG || Department::FIN"
        )
        .await
        .is_err()
    );

    // Import a wrapped key

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // create a symmetric key
    let symmetric_key_id =
        create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    // export a wrapped key
    let exported_wrapped_key_file = tmp_path.join("exported_wrapped_master_private.key");
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_id: master_private_key_id.to_string(),
        key_file: exported_wrapped_key_file.to_str().unwrap().to_string(),
        wrap_key_id: Some(symmetric_key_id),
        ..Default::default()
    })?;

    // import it wrapped
    let wrapped_key_id = import_key(ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_string(),
        key_file: exported_wrapped_key_file.to_string_lossy().to_string(),
        replace_existing: true,
        ..Default::default()
    })?;

    // Rekeying wrapped keys is not allowed
    assert!(
        rekey(
            &ctx.owner_client_conf_path,
            &wrapped_key_id,
            "Department::MKG || Department::FIN"
        )
        .await
        .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn test_rekey_prune() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file_before = tmp_path.join("plain.before.enc");
    let output_file_after = tmp_path.join("plain.after.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;
    let user_decryption_key = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
    )?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file_before.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file_before.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // export the user_decryption_key
    let exported_user_decryption_key_file = tmp_path.join("exported_user_decryption.key");
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_id: user_decryption_key.to_string(),
        key_file: exported_user_decryption_key_file
            .to_str()
            .unwrap()
            .to_string(),
        ..Default::default()
    })?;

    // rekey the attributes
    rekey(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::MKG || Department::FIN",
    )
    .await?;

    // encrypt again after rekeying
    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file_after.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the new file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file_after.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    // ... and the old file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file_before.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // import the non rotated user_decryption_key
    let old_user_decryption_key = import_key(ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_file: exported_user_decryption_key_file
            .to_string_lossy()
            .to_string(),
        replace_existing: false,
        key_usage_vec: Some(vec![KeyUsage::Unrestricted]),
        ..Default::default()
    })?;
    // the imported user key should not be able to decrypt the new file
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            &[output_file_after.to_str().unwrap()],
            &old_user_decryption_key,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );
    // ... but should decrypt the old file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file_before.to_str().unwrap()],
        &old_user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // prune the attributes
    prune(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::MKG || Department::FIN",
    )
    .await?;

    // the user key should be able to decrypt the new file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file_after.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // but no longer the old file
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            &[output_file_before.to_str().unwrap()],
            &user_decryption_key,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    Ok(())
}
