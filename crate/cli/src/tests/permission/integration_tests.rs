use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    tests::{
        test_utils::{init_test_server, ONCE},
        utils::abe::extract_private_key,
        PROG_NAME,
    },
};

const SUB_COMMAND: &str = "permission";

fn gen_object() -> String {
    let mut cmd = Command::cargo_bin(PROG_NAME).unwrap();
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg("abe").args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout).unwrap();

    String::from(extract_private_key(stdout).unwrap())
}

#[tokio::test]
pub async fn test_add() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;
    let object_id = gen_object();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["list", object_id.as_str()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("user@example.com\n\tGet"));

    Ok(())
}

#[tokio::test]
pub async fn test_add_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Bad operation
    let object_id = gen_object();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "add",
        object_id.as_str(),
        "-u",
        "laetitia.langlois@cosmian.com",
        "-o",
        "get",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "You can\'t grant yourself, you have already all rights on your own objects",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_remove() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;
    let object_id = gen_object();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["list", object_id.as_str()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with("The permissions are:\n\n"));

    Ok(())
}

#[tokio::test]
pub async fn test_remove_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;
    let object_id = gen_object();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    let object_id = gen_object();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
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
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "remove",
        object_id.as_str(),
        "-u",
        "laetitia.langlois@cosmian.com",
        "-o",
        "get",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Access denied: You can\'t revoke yourself, you shoud keep all rights on your own objects",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_list_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Bad object_id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["list", "bad_object_id"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Object with uid `bad_object_id` is not owned by owner `laetitia.langlois@cosmian.com`",
    ));
    Ok(())
}

#[tokio::test]
pub async fn test_owned() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let object_id = gen_object();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(object_id));

    Ok(())
}

#[tokio::test]
pub async fn test_shared() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // TODO: need a test with another user sharing his/her key with us

    Ok(())
}
