use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use super::symmetric::create_key::create_symmetric_key;
use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        shared::{destroy, export, revoke},
        symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
        utils::{init_test_server, ONCE},
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

/// Revoke access to a user
fn revoke_access(
    cli_conf_path: &str,
    object_id: &str,
    user: &str,
    operation: &str,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(vec!["revoke", user, object_id, operation]);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_ownership_and_grant() -> Result<(), CliError> {
    // the client conf will use the owner cert
    let ctx = ONCE.get_or_init(init_test_server).await;
    let key_id = gen_key(&ctx.owner_cli_conf_path)?;

    // the owner should have access
    export(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_id,
        "output.json",
        false,
        false,
        None,
        false,
    )?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(&ctx.owner_cli_conf_path, &key_id)?;

    // the user should not be able to export
    assert!(
        export(
            &ctx.user_cli_conf_path,
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
    assert!(run_encrypt_decrypt_test(&ctx.user_cli_conf_path, &key_id).is_err());
    // the user should not be able to revoke the key
    assert!(revoke(&ctx.user_cli_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should not be able to destroy the key
    assert!(destroy(&ctx.user_cli_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "encrypt",
    )?;
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "decrypt",
    )?;

    // switch to user
    // the user should still not be able to export
    assert!(
        export(
            &ctx.user_cli_conf_path,
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
    run_encrypt_decrypt_test(&ctx.user_cli_conf_path, &key_id)?;
    // the user should still not be able to revoke the key
    assert!(revoke(&ctx.user_cli_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&ctx.user_cli_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "get",
    )?;

    // switch to user
    // the user should now be able to export
    export(
        &ctx.user_cli_conf_path,
        "sym",
        &key_id,
        "output.json",
        false,
        false,
        None,
        false,
    )?;
    // the user should still not be able to revoke the key
    assert!(revoke(&ctx.user_cli_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&ctx.user_cli_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant revoke access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "revoke",
    )?;

    // switch to user
    // the user should now be able to revoke the key
    revoke(&ctx.user_cli_conf_path, "sym", &key_id, "user revoke")?;

    // switch back to owner
    // grant destroy access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "destroy",
    )?;

    // switch to user
    // destroy the key
    destroy(&ctx.user_cli_conf_path, "sym", &key_id)?;

    Ok(())
}

#[tokio::test]
pub async fn test_grant_error() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let key_id = gen_key(&ctx.owner_cli_conf_path)?;

    // bad operation
    assert!(
        grant_access(
            &ctx.owner_cli_conf_path,
            &key_id,
            "user.client@acme.com",
            "BAD OP",
        )
        .is_err(),
    );

    // bad object ID
    assert!(
        grant_access(
            &ctx.owner_cli_conf_path,
            "BAD ID",
            "user.client@acme.com",
            "get"
        )
        .is_err()
    );

    // grant to my self
    assert!(
        grant_access(
            &ctx.owner_cli_conf_path,
            &key_id,
            "owner.client@acme.com",
            "get"
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
pub async fn test_revoke_access() -> Result<(), CliError> {
    // the client conf will use the owner cert
    let ctx = ONCE.get_or_init(init_test_server).await;
    let key_id = gen_key(&ctx.owner_cli_conf_path)?;

    // the user should not be able to export
    assert!(
        export(
            &ctx.user_cli_conf_path,
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

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "get",
    )?;

    // switch to user
    // the user should now be able to export
    export(
        &ctx.user_cli_conf_path,
        "sym",
        &key_id,
        "output.json",
        false,
        false,
        None,
        false,
    )?;

    // switch back to owner
    // revoke access to user
    revoke_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "get",
    )?;

    // the user should not be able to export anymore
    assert!(
        export(
            &ctx.user_cli_conf_path,
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

    // revoke errors
    // switch back to owner
    assert!(
        revoke_access(
            &ctx.owner_cli_conf_path,
            &key_id,
            "user.client@acme.com",
            "BAD"
        )
        .is_err()
    );
    assert!(
        revoke_access(
            &ctx.owner_cli_conf_path,
            "BAD KEY",
            "user.client@acme.com",
            "get"
        )
        .is_err()
    );

    // this will not error
    revoke_access(&ctx.owner_cli_conf_path, &key_id, "BAD USER", "get")?;

    Ok(())
}

#[tokio::test]
pub async fn test_list_error() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    // Bad object_id
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["list", "bad_object_id"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Object with uid `bad_object_id` is not owned by owner `owner.client@acme.com`",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_owned() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    let object_id = gen_key(&ctx.owner_cli_conf_path)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_cli_conf_path);
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
