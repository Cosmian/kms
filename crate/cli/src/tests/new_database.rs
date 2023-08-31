use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

use crate::{
    actions::shared::utils::write_json_object_to_file,
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::SUB_COMMAND,
        shared::export,
        symmetric::create_key::create_symmetric_key,
        utils::{
            create_new_database, generate_invalid_conf, init_test_server, init_test_server_options,
            ONCE,
        },
        PROG_NAME,
    },
};

#[tokio::test]
pub async fn test_new_database() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.arg("new-database");
    cmd.assert().success().stdout(predicate::str::contains(
        "A new encrypted database is configured",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_secrets_bad() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    let bad_conf_path = generate_invalid_conf(&ctx.owner_cli_conf);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, bad_conf_path);

    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Database secret is wrong"));

    Ok(())
}

#[tokio::test]
pub async fn test_conf_does_not_exist() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/configs/kms_bad_group_id.bad");

    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    let output = cmd.output()?;
    assert!(!output.status.success());
    Ok(())
}

#[tokio::test]
pub async fn test_secrets_key_bad() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);
    cmd.assert().success();

    let invalid_conf_path = generate_invalid_conf(&ctx.owner_cli_conf);
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, invalid_conf_path);

    cmd.arg(SUB_COMMAND).args(vec![
        "keys",
        "create-master-key-pair",
        "--policy-binary",
        "test_data/policy.bin",
    ]);

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
    let ctx = init_test_server_options(9997, true, false, false, false, false).await;

    // create a symmetric key in the default encrypted database
    let key_1 = create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None, &[])?;
    // export the key 1
    // Export
    export(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_1,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )?;

    // create a new encrypted database
    let new_database_secret = create_new_database(&ctx.owner_cli_conf_path)?;

    // update the CLI conf
    let mut new_conf = ctx.owner_cli_conf.clone();
    new_conf.kms_database_secret = Some(new_database_secret);
    write_json_object_to_file(&new_conf, &ctx.owner_cli_conf_path)
        .expect("Can't write the new conf");

    // create a symmetric key in the default encrypted database
    let key_2 = create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None, &[])?;
    // export the key 1
    // Export
    export(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_2,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )?;

    // go back to original conf
    write_json_object_to_file(&ctx.owner_cli_conf, &ctx.owner_cli_conf_path)
        .expect("Can't rewrite the original conf");
    // we should be able to export key_1 again
    export(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_1,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )?;

    // go to new conf
    write_json_object_to_file(&new_conf, &ctx.owner_cli_conf_path)
        .expect("Can't rewrite the new conf");
    // we should be able to export key_2 again
    export(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_2,
        tmp_path.join("output.export").to_str().unwrap(),
        false,
        false,
        None,
        false,
    )?;

    // stop that server
    ctx.stop_server().await;
    Ok(())
}
