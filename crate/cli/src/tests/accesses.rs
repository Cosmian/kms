use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use super::{symmetric::create_key::create_symmetric_key, utils::TestsContext};
use crate::{
    actions::shared::utils::write_to_json_file,
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        shared::{destroy, export, revoke},
        symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
        utils::{init_test_server, init_test_server_options, log_init, ONCE},
        PROG_NAME,
    },
};

pub const SUB_COMMAND: &str = "access";

/// Generates a symmetric key
fn gen_key(cli_conf_path: &str) -> Result<String, CliError> {
    create_symmetric_key(cli_conf_path, None, None, None)
}

/// Grants access to a user
fn grant_access(
    cli_conf_path: &str,
    object_id: &str,
    user: &str,
    operation: &str,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(vec!["grant", user, object_id, operation]);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn switch_to_user(ctx: &TestsContext) -> Result<(), CliError> {
    let mut user_conf = ctx.cli_conf.clone();
    user_conf.ssl_client_pkcs12_path =
        Some("test_data/certificates/user.client.acme.com.p12".to_string());
    write_to_json_file(&user_conf, &ctx.cli_conf_path)?;
    Ok(())
}

fn switch_to_owner(ctx: &TestsContext) -> Result<(), CliError> {
    let mut user_conf = ctx.cli_conf.clone();
    user_conf.ssl_client_pkcs12_path =
        Some("test_data/certificates/owner.client.acme.com.p12".to_string());
    write_to_json_file(&user_conf, &ctx.cli_conf_path)?;
    Ok(())
}

#[tokio::test]
pub async fn test_ownership_and_grant() -> Result<(), CliError> {
    log_init("cosmian=info");
    // the client conf will use the owner cert
    let ctx = init_test_server_options(9996, false, true, true).await;
    let key_id = gen_key(&ctx.cli_conf_path)?;

    // the owner should have access
    export(
        &ctx.cli_conf_path,
        "sym",
        &key_id,
        "output.json",
        false,
        false,
        None,
        false,
    )?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(&ctx.cli_conf_path, &key_id)?;

    switch_to_user(&ctx)?;
    // the user should not be able to export
    assert!(
        export(
            &ctx.cli_conf_path,
            "sym",
            &key_id,
            "output.json",
            false,
            false,
            None,
            false,
        )
        .is_err()
    );
    // the user should not be able to encrypt or decrypt
    assert!(run_encrypt_decrypt_test(&ctx.cli_conf_path, &key_id).is_err());
    // the user should not be able to revoke the key
    assert!(revoke(&ctx.cli_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should not be able to destroy the key
    assert!(destroy(&ctx.cli_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    switch_to_owner(&ctx)?;
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "encrypt",
    )?;
    grant_access(
        &ctx.cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "decrypt",
    )?;

    // switch to user
    switch_to_user(&ctx)?;
    // the user should still not be able to export
    assert!(
        export(
            &ctx.cli_conf_path,
            "sym",
            &key_id,
            "output.json",
            false,
            false,
            None,
            false,
        )
        .is_err()
    );
    // the user should now be able to encrypt or decrypt
    run_encrypt_decrypt_test(&ctx.cli_conf_path, &key_id)?;

    // switch back to owner
    switch_to_owner(&ctx)?;
    // grant encrypt and decrypt access to user
    grant_access(&ctx.cli_conf_path, &key_id, "user.client@acme.com", "get")?;

    // switch to user
    switch_to_user(&ctx)?;
    // the user should now be able to export
    export(
        &ctx.cli_conf_path,
        "sym",
        &key_id,
        "output.json",
        false,
        false,
        None,
        false,
    )?;

    // switch back to owner
    switch_to_owner(&ctx)?;
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "revoke",
    )?;

    // switch to user
    switch_to_user(&ctx)?;
    // the user should now be able to revoke the key
    revoke(&ctx.cli_conf_path, "sym", &key_id, "user revoke")?;

    // switch back to owner
    switch_to_owner(&ctx)?;
    // destroy the key
    destroy(&ctx.cli_conf_path, "sym", &key_id)?;

    // stop the server
    ctx.stop_server().await;

    Ok(())
}

#[tokio::test]
pub async fn test_grant_error() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    // Bad operation
    let key_id = gen_key(&ctx.cli_conf_path)?;

    // bad operation
    assert!(
        grant_access(
            &ctx.cli_conf_path,
            &key_id,
            "user.client@acme.com",
            "BAD OP",
        )
        .is_err(),
    );

    // bad object ID
    assert!(grant_access(&ctx.cli_conf_path, "BAD ID", "user.client@acme.com", "get").is_err());

    // grant to my self
    assert!(grant_access(&ctx.cli_conf_path, &key_id, "alice@cosmian.com", "get").is_err());

    Ok(())
}

#[tokio::test]
pub async fn test_revoke() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let object_id = gen_key(&ctx.cli_conf_path)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "grant",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The permission has been properly revoke",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["list", object_id.as_str()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with("The permissions are:\n\n"));

    Ok(())
}

#[tokio::test]
pub async fn test_revoke_error() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let object_id = gen_key(&ctx.cli_conf_path)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "grant",
        object_id.as_str(),
        "-u",
        "user@example.com",
        "-o",
        "get",
    ]);
    cmd.assert().success();

    // Bad operation
    let object_id = gen_key(&ctx.cli_conf_path)?;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
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
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
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
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
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
    let ctx = ONCE.get_or_init(init_test_server).await;

    // Bad object_id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["list", "bad_object_id"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Object with uid `bad_object_id` is not owned by owner `tech@cosmian.com`",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_owned() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    let object_id = gen_key(&ctx.cli_conf_path)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.cli_conf_path);
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
