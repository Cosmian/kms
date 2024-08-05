use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::{write_json_object_to_file, KMS_CLI_CONF_ENV};
use kms_test_server::{
    generate_invalid_conf, start_default_test_kms_server, start_test_server_with_options,
};
use predicates::prelude::*;
use tempfile::TempDir;

use crate::{
    error::CliError,
    tests::{
        shared::export_key, symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs,
        PROG_NAME,
    },
};

#[tokio::test]
pub(crate) async fn test_new_database() -> Result<(), CliError> {
    let ctx = start_default_test_kms_server().await;

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
pub(crate) async fn test_secrets_bad() -> Result<(), CliError> {
    let ctx = start_default_test_kms_server().await;

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
pub(crate) async fn test_conf_does_not_exist() -> Result<(), CliError> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/configs/kms_bad_group_id.bad");

    cmd.arg("ec").args(vec!["keys", "create"]);
    let output = recover_cmd_logs(&mut cmd);
    assert!(!output.status.success());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secrets_key_bad() -> Result<(), CliError> {
    let ctx = start_default_test_kms_server().await;

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
async fn test_multiple_databases() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    // since we are going to rewrite the conf, use a different port
    let ctx = start_test_server_with_options(9997, true, false, false).await?;

    // create a symmetric key in the default encrypted database
    let key_1 = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    // export the key 1
    // Export
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_1,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

    // create a new encrypted database
    let kms_client = ctx.owner_client_conf.initialize_kms_client(None, None)?;
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
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_2,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

    // go back to original conf
    write_json_object_to_file(&ctx.owner_client_conf, &ctx.owner_client_conf_path)
        .expect("Can't rewrite the original conf");
    // we should be able to export key_1 again
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_1,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

    // go to new conf
    write_json_object_to_file(&new_conf, &ctx.owner_client_conf_path)
        .expect("Can't rewrite the new conf");
    // we should be able to export key_2 again
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_2,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

    // stop that server
    ctx.stop_server().await?;
    Ok(())
}
