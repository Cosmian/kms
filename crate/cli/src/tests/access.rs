use std::process::Command;

use assert_cmd::prelude::*;

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

/// List accesses granted on an object
fn list_access(cli_conf_path: &str, object_id: &str) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["list", object_id]);
    let output = cmd.output()?;
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List objects owned by the user
fn list_owned_objects(cli_conf_path: &str) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    let output = cmd.output()?;
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List accesses granted
fn list_shared_accesses(cli_conf_path: &str) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["shared"]);
    let output = cmd.output()?;
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out)
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
pub async fn test_list_access_rights() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let key_id = gen_key(&ctx.owner_cli_conf_path)?;

    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "get",
    )?;

    // the owner can list access rights granted
    let owner_list = list_access(&ctx.owner_cli_conf_path, &key_id)?;
    assert!(owner_list.contains("user.client@acme.com: [Get]"));

    // The user is not the owner and thus should not be able to list accesses on ths object
    assert!(list_access(&ctx.user_cli_conf_path, &key_id).is_err());

    Ok(())
}

#[tokio::test]
pub async fn test_list_access_rights_error() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    assert!(list_access(&ctx.user_cli_conf_path, "BAD KEY").is_err());
    Ok(())
}

#[tokio::test]
pub async fn test_list_owned_objects() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let key_id = gen_key(&ctx.owner_cli_conf_path)?;

    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "get",
    )?;

    // the owner should have the object in the list
    let owner_list = list_owned_objects(&ctx.owner_cli_conf_path)?;
    assert!(owner_list.contains(&key_id));

    // The user is not the owner and thus should not have the object in the list
    let user_list = list_owned_objects(&ctx.user_cli_conf_path)?;
    assert!(!user_list.contains(&key_id));

    // create a key using the user
    let user_key_id = gen_key(&ctx.user_cli_conf_path)?;

    // the user should have the object in the list
    let user_list = list_owned_objects(&ctx.user_cli_conf_path)?;
    assert!(user_list.contains(&user_key_id));

    // The 'owner' is not the owner of this object and thus should not have the object in the list
    let owner_list = list_owned_objects(&ctx.owner_cli_conf_path)?;
    assert!(!owner_list.contains(&user_key_id));
    // ... but the list should still contain the other key
    assert!(owner_list.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub async fn test_list_shared_accesses() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let key_id = gen_key(&ctx.owner_cli_conf_path)?;

    let list = list_shared_accesses(&ctx.owner_cli_conf_path)?;
    assert!(!list.contains(&key_id));

    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_cli_conf_path,
        &key_id,
        "user.client@acme.com",
        "get",
    )?;

    let list = list_shared_accesses(&ctx.user_cli_conf_path)?;
    println!("user list {list}");

    let list = list_shared_accesses(&ctx.owner_cli_conf_path)?;
    println!("list {list}");
    assert!(list.contains(&key_id));

    // // the owner should have the object in the list
    // let owner_list = list_shared_accesses(&ctx.owner_cli_conf_path, &key_id)?;
    // assert!(owner_list.contains(&key_id));

    // // The user is not the owner and thus should not have the object in the list
    // let user_list = list_shared_accesses(&ctx.user_cli_conf_path)?;
    // assert!(!user_list.contains(&key_id));

    // // create a key using the user
    // let user_key_id = gen_key(&ctx.user_cli_conf_path)?;

    // // the user should have the object in the list
    // let user_list = list_shared_accesses(&ctx.user_cli_conf_path)?;
    // assert!(user_list.contains(&user_key_id));

    // // The 'owner' is not the owner of this object and thus should not have the object in the list
    // let owner_list = list_owned_objects(&ctx.owner_cli_conf_path)?;
    // assert!(!owner_list.contains(&user_key_id));
    // // ... but the list should still contain the other key
    // assert!(owner_list.contains(&key_id));

    Ok(())
}
