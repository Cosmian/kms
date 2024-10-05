use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{write_json_object_to_file, KMS_CLI_CONF_ENV};
use cosmian_logger::log_utils::log_init;
use kms_test_server::{
    generate_invalid_conf, start_default_test_kms_server, start_test_server_with_options,
    AuthenticationOptions, DBConfig, DEFAULT_SQLITE_PATH,
};
use predicates::prelude::*;
use tempfile::TempDir;
use tracing::info;

use crate::{
    error::result::CliResult,
    tests::{
        shared::{export_key, ExportKeyParams},
        symmetric::create_key::create_symmetric_key,
        utils::recover_cmd_logs,
        PROG_NAME,
    },
};

#[tokio::test]
pub(crate) async fn test_new_database() -> CliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;

    if ctx.owner_client_conf.kms_database_secret.is_none() {
        info!("Skipping test_new_database as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_client_conf_path);

    cmd.arg("new-database");
    recover_cmd_logs(&mut cmd);
    cmd.assert().success().stdout(predicate::str::contains(
        "A new user encrypted database is configured",
    ));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secrets_bad() -> CliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;

    if ctx.owner_client_conf.kms_database_secret.is_none() {
        info!("Skipping test_secrets_bad as backend not sqlite-enc");
        return Ok(());
    }

    let bad_conf_path = generate_invalid_conf(&ctx.owner_client_conf);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, bad_conf_path);

    cmd.arg("ec").args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Database secret is wrong"));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_conf_does_not_exist() -> CliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;

    if ctx.owner_client_conf.kms_database_secret.is_none() {
        info!("Skipping test_conf_does_not_exist as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/configs/kms_bad_group_id.bad");

    cmd.arg("ec").args(vec!["keys", "create"]);
    let output = recover_cmd_logs(&mut cmd);
    assert!(!output.status.success());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secrets_key_bad() -> CliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;

    if ctx.owner_client_conf.kms_database_secret.is_none() {
        info!("Skipping test_secrets_key_bad as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_client_conf_path);
    cmd.arg("ec").args(vec!["keys", "create"]);
    cmd.assert().success();

    let invalid_conf_path = generate_invalid_conf(&ctx.owner_client_conf);
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, invalid_conf_path);

    cmd.arg("ec").args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    Ok(())
}

#[tokio::test]
async fn test_multiple_databases() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    // since we are going to rewrite the conf, use a different port
    let ctx = start_test_server_with_options(
        DBConfig {
            database_type: Some("sqlite-enc".to_owned()),
            sqlite_path: PathBuf::from(DEFAULT_SQLITE_PATH),
            clear_database: true,
            ..DBConfig::default()
        },
        9997,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: false,
            use_client_cert: false,
            api_token_id: None,
            api_token: None,
        },
    )
    .await?;

    // create a symmetric key in the default encrypted database
    let key_1 = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    // export the key 1
    // Export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_1.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })
    .unwrap();

    // create a new encrypted database
    let kms_client = ctx
        .owner_client_conf
        .initialize_kms_client(None, None, false)?;
    let new_database_secret = kms_client.new_database().await?;

    // update the CLI conf
    let mut new_conf = ctx.owner_client_conf.clone();
    new_conf.kms_database_secret = Some(new_database_secret);
    write_json_object_to_file(&new_conf, &ctx.owner_client_conf_path)
        .expect("Can't write the new conf");

    // create a symmetric key in the default encrypted database
    let key_2 = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    // export the key 1
    // Export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_2.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })
    .unwrap();

    // go back to original conf
    write_json_object_to_file(&ctx.owner_client_conf, &ctx.owner_client_conf_path)
        .expect("Can't rewrite the original conf");
    // we should be able to export key_1 again
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_1.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    // go to new conf
    write_json_object_to_file(&new_conf, &ctx.owner_client_conf_path)
        .expect("Can't rewrite the new conf");
    // we should be able to export key_2 again
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_2.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    // stop that server
    ctx.stop_server().await?;
    Ok(())
}
