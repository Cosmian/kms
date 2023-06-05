use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        test_utils::{init_test_server, ONCE},
        CONF_PATH, PROG_NAME,
    },
};

const SUB_COMMAND: &str = "permission";

async fn gen_object() -> Result<String, CliError> {
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;
    Ok(master_private_key_id)
}

#[tokio::test]
pub async fn test_add() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;
    let object_id = gen_object().await?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "add",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The permission has been properly set",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["list", object_id.as_str()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("user@example.com\n\tGet"));

    Ok(())
}

#[tokio::test]
pub async fn test_add_error() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    // Bad operation
    let object_id = gen_object().await?;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "add",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "bad_ops",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Could not parse an operation"));

    // Bad object id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "add",
        "bad-object-id",
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Access denied: Object with uid `bad-object-id` is not owned by owner",
    ));

    // User_id = owner_id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "add",
        object_id.as_str(),
        "-u",
        "tech@cosmian.com",
        "-o",
        "get",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "You can\'t grant yourself, you have already all rights on your own objects",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_remove() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;
    let object_id = gen_object().await?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "add",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "remove",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The permission has been properly remove",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["list", object_id.as_str()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with("The permissions are:\n\n"));

    Ok(())
}

#[tokio::test]
pub async fn test_remove_error() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;
    let object_id = gen_object().await?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "add",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().success();

    // Bad operation
    let object_id = gen_object().await?;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "remove",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "bad_ops",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Could not parse an operation"));

    // Bad object id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "remove",
        "bad-object-id",
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Access denied: Object with uid `bad-object-id` is not owned by owner",
    ));

    // User_id = owner_id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "remove",
        object_id.as_str(),
        "-u",
        "tech@cosmian.com",
        "-o",
        "get",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Access denied: You can\'t revoke yourself, you should keep all rights on your own objects",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_list_error() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    // Bad object_id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["list", "bad_object_id"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Object with uid `bad_object_id` is not owned by owner `tech@cosmian.com`",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_owned() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    let object_id = gen_object().await?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(object_id));

    Ok(())
}

#[tokio::test]
pub async fn test_shared() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    // TODO: need a test with another user sharing his/her key with us

    Ok(())
}
