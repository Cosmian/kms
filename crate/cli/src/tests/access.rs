use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server_with_cert_auth;
use tracing::trace;

use super::{symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs};
use crate::{
    actions::symmetric::DataEncryptionAlgorithm,
    error::{result::CliResult, CliError},
    tests::{
        shared::{destroy, export_key, revoke, ExportKeyParams},
        symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
        PROG_NAME,
    },
};

pub(crate) const SUB_COMMAND: &str = "access-rights";

/// Generates a symmetric key
fn gen_key(cli_conf_path: &str) -> CliResult<String> {
    create_symmetric_key(cli_conf_path, None, None, None, &[])
}

/// Grants access to a user
pub(crate) fn grant_access(
    cli_conf_path: &str,
    object_id: &str,
    user: &str,
    operations: &[&str],
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["grant", user, object_id]);
    for operation in operations {
        cmd.arg(operation);
    }

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Revoke access to a user
pub(crate) fn revoke_access(
    cli_conf_path: &str,
    object_id: &str,
    user: &str,
    operations: &[&str],
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["revoke", user, object_id]);
    for operation in operations {
        cmd.arg(operation);
    }

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List accesses granted on an object
fn list_access(cli_conf_path: &str, object_id: &str) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["list", object_id]);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List objects owned by the user
fn list_owned_objects(cli_conf_path: &str) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["owned"]);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List accesses granted
fn list_accesses_rights_obtained(cli_conf_path: &str) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["obtained"]);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_ownership_and_grant() -> CliResult<()> {
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    // the owner should have access
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: "/tmp/output.json".to_owned(),
        ..Default::default()
    })?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;

    // the user should not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: "/tmp/output.json".to_owned(),
            ..Default::default()
        })
        .is_err()
    );
    // the user should not be able to encrypt or decrypt
    assert!(
        run_encrypt_decrypt_test(
            &ctx.user_client_conf_path,
            &key_id,
            DataEncryptionAlgorithm::AesGcm,
            None,
            0
        )
        .is_err()
    );
    // the user should not be able to revoke the key
    assert!(revoke(&ctx.user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should not be able to destroy the key
    assert!(destroy(&ctx.user_client_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["encrypt"],
    )?;
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["decrypt"],
    )?;

    // switch to user
    // the user should still not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: "/tmp/output.json".to_owned(),
            ..Default::default()
        })
        .is_err()
    );

    // the user should now be able to encrypt or decrypt
    run_encrypt_decrypt_test(
        &ctx.user_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;
    // the user should still not be able to revoke the key
    assert!(revoke(&ctx.user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&ctx.user_client_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get"],
    )?;

    // switch to user
    // the user should now be able to export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.user_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: "/tmp/output.json".to_owned(),
        ..Default::default()
    })?;
    // the user should still not be able to revoke the key
    assert!(revoke(&ctx.user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&ctx.user_client_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant revoke access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["revoke"],
    )?;

    // switch to user
    // the user should now be able to revoke the key
    revoke(&ctx.user_client_conf_path, "sym", &key_id, "user revoke")?;

    // switch back to owner
    // grant destroy access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["destroy"],
    )?;

    // switch to user
    // destroy the key
    destroy(&ctx.user_client_conf_path, "sym", &key_id)?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_grant_error() -> CliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    // bad operation
    assert!(
        grant_access(
            &ctx.owner_client_conf_path,
            &key_id,
            "user.client@acme.com",
            &["BAD_OP"],
        )
        .is_err(),
    );

    // bad object ID
    assert!(
        grant_access(
            &ctx.owner_client_conf_path,
            "BAD ID",
            "user.client@acme.com",
            &["get"]
        )
        .is_err()
    );

    // grant to my self
    assert!(
        grant_access(
            &ctx.owner_client_conf_path,
            &key_id,
            "owner.client@acme.com",
            &["get"]
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_revoke_access() -> CliResult<()> {
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    /*    // the user should not be able to export
    assert!(
        export(
            &ctx.user_client_conf_path,
            "sym",
            &key_id,
            "/tmp/output.json",
            None,
            false,
            None,
            false,
        )
        .is_err()
    );*/

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get"],
    )?;

    // switch to user
    // the user should now be able to export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.user_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: "/tmp/output.json".to_owned(),
        ..Default::default()
    })?;

    // switch back to owner
    // revoke access to user
    revoke_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get"],
    )?;

    // the user should not be able to export anymore
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: "/tmp/output.json".to_owned(),
            ..Default::default()
        })
        .is_err()
    );

    // revoke errors
    // switch back to owner
    assert!(
        revoke_access(
            &ctx.owner_client_conf_path,
            &key_id,
            "user.client@acme.com",
            &["BAD"]
        )
        .is_err()
    );
    assert!(
        revoke_access(
            &ctx.owner_client_conf_path,
            "BAD KEY",
            "user.client@acme.com",
            &["get"]
        )
        .is_err()
    );

    // this will not error
    revoke_access(&ctx.owner_client_conf_path, &key_id, "BAD USER", &["get"])?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_list_access_rights() -> CliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get"],
    )?;

    // the owner can list access rights granted
    let owner_list = list_access(&ctx.owner_client_conf_path, &key_id)?;
    trace!("owner list {owner_list}");
    assert!(owner_list.contains("user.client@acme.com: {get}"));

    // The user is not the owner and thus should not be able to list accesses on this object
    assert!(list_access(&ctx.user_client_conf_path, &key_id).is_err());

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_list_access_rights_error() -> CliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    assert!(list_access(&ctx.user_client_conf_path, "BAD KEY").is_err());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_list_owned_objects() -> CliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    // grant encrypt and decrypt access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get"],
    )?;

    // the owner should have the object in the list
    let owner_list = list_owned_objects(&ctx.owner_client_conf_path)?;
    assert!(owner_list.contains(&key_id));

    // The user is not the owner and thus should not have the object in the list
    let user_list = list_owned_objects(&ctx.user_client_conf_path)?;
    assert!(!user_list.contains(&key_id));

    // create a key using the user
    let user_key_id = gen_key(&ctx.user_client_conf_path)?;

    // the user should have the object in the list
    let user_list = list_owned_objects(&ctx.user_client_conf_path)?;
    assert!(user_list.contains(&user_key_id));

    // The 'owner' is not the owner of this object and thus should not have the object in the list
    let owner_list = list_owned_objects(&ctx.owner_client_conf_path)?;
    assert!(!owner_list.contains(&user_key_id));
    // ... but the list should still contain the other key
    assert!(owner_list.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_access_right_obtained() -> CliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    let list = list_accesses_rights_obtained(&ctx.owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // grant get access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get"],
    )?;

    // the user should have the "get" access granted
    let list = list_accesses_rights_obtained(&ctx.user_client_conf_path)?;
    trace!("user list {list}");
    assert!(list.contains(&key_id));
    assert!(list.contains("get"));

    // the owner has not been granted access rights on this object (it owns it)
    let list = list_accesses_rights_obtained(&ctx.owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // the owner should have the object in the list
    let owner_list = list_accesses_rights_obtained(&ctx.owner_client_conf_path)?;
    assert!(!owner_list.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_ownership_and_grant_wildcard_user() -> CliResult<()> {
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    // the owner should have access
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: "/tmp/output.json".to_owned(),
        ..Default::default()
    })?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;

    // the user should not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: "/tmp/output.json".to_owned(),
            ..Default::default()
        })
        .is_err()
    );
    // the user should not be able to encrypt or decrypt
    assert!(
        run_encrypt_decrypt_test(
            &ctx.user_client_conf_path,
            &key_id,
            DataEncryptionAlgorithm::AesGcm,
            None,
            0
        )
        .is_err()
    );
    // the user should not be able to revoke the key
    assert!(revoke(&ctx.user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should not be able to destroy the key
    assert!(destroy(&ctx.user_client_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(&ctx.owner_client_conf_path, &key_id, "*", &["encrypt"])?;
    grant_access(&ctx.owner_client_conf_path, &key_id, "*", &["decrypt"])?;

    // switch to user
    // the user should still not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: "/tmp/output.json".to_owned(),
            ..Default::default()
        })
        .is_err()
    );

    // the user should now be able to encrypt or decrypt
    run_encrypt_decrypt_test(
        &ctx.user_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;
    // the user should still not be able to revoke the key
    assert!(revoke(&ctx.user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&ctx.user_client_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(&ctx.owner_client_conf_path, &key_id, "*", &["get"])?;

    // switch to user
    // the user should now be able to export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.user_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: "/tmp/output.json".to_owned(),
        ..Default::default()
    })?;
    // the user should still not be able to revoke the key
    assert!(revoke(&ctx.user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&ctx.user_client_conf_path, "sym", &key_id).is_err());

    // switch back to owner
    // grant revoke access to user
    grant_access(&ctx.owner_client_conf_path, &key_id, "*", &["revoke"])?;

    // switch to user
    // the user should now be able to revoke the key
    revoke(&ctx.user_client_conf_path, "sym", &key_id, "user revoke")?;

    // switch back to owner
    // grant destroy access to user
    grant_access(&ctx.owner_client_conf_path, &key_id, "*", &["destroy"])?;

    // switch to user
    // destroy the key
    destroy(&ctx.user_client_conf_path, "sym", &key_id)?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_access_right_obtained_using_wildcard() -> CliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    // the owner should not have access rights (it owns it)
    let list = list_accesses_rights_obtained(&ctx.owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // grant get access to the wildcard user
    grant_access(&ctx.owner_client_conf_path, &key_id, "*", &["get"])?;

    // grant encrypt access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["encrypt"],
    )?;

    // the user should have the "get" access granted
    let list = list_accesses_rights_obtained(&ctx.user_client_conf_path)?;
    trace!("user list {list}");
    assert!(list.contains(&key_id));
    assert!(list.contains("get"));
    assert!(list.contains("encrypt"));

    // the owner has not been granted access rights on this object (it owns it)
    let list = list_accesses_rights_obtained(&ctx.owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // the owner should have the object in the list
    let owner_list = list_accesses_rights_obtained(&ctx.owner_client_conf_path)?;
    assert!(!owner_list.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_grant_multiple_operations() -> CliResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let key_id = gen_key(&ctx.owner_client_conf_path)?;

    // grant multiple access to user
    grant_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get", "revoke", "create", "create"], // double `create` will be dedup
    )?;

    // the owner can list access rights granted
    let owner_list = list_access(&ctx.owner_client_conf_path, &key_id)?;
    assert!(owner_list.contains("user.client@acme.com: {create, get, revoke}"));

    // revoke multiple access to user
    revoke_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get", "revoke", "get"], // double `get` will be dedup
    )?;

    let owner_list = list_access(&ctx.owner_client_conf_path, &key_id)?;
    assert!(owner_list.contains("user.client@acme.com: {create}"));

    // revoke same, nothing changed
    revoke_access(
        &ctx.owner_client_conf_path,
        &key_id,
        "user.client@acme.com",
        &["get", "revoke", "get"], // double `get` will be dedup
    )?;
    let owner_list = list_access(&ctx.owner_client_conf_path, &key_id)?;
    assert!(owner_list.contains("user.client@acme.com: {create}"));

    Ok(())
}
