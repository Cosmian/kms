use std::{
    env,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use assert_cmd::prelude::*;
use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::symmetric_utils::DataEncryptionAlgorithm,
};
use cosmian_logger::{log_init, trace};
use test_kms_server::start_default_test_kms_server_with_cert_auth;
#[cfg(feature = "non-fips")]
use test_kms_server::start_default_test_kms_server_with_privileged_users;

#[cfg(feature = "non-fips")]
use super::rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair};
use super::{KMS_SUBCOMMAND, symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs};
#[cfg(feature = "non-fips")]
use crate::tests::kms::shared::{ImportKeyParams, import_key};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            shared::{ExportKeyParams, destroy, export_key, revoke},
            symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
        },
        save_kms_cli_config,
    },
};

pub(crate) const SUB_COMMAND: &str = "access-rights";

/// Create a unique path inside the system temp directory
fn unique_temp_path(file_name: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    env::temp_dir()
        .join(format!("{file_name}.{now}"))
        .to_string_lossy()
        .into_owned()
}

/// Generates a symmetric key
fn gen_key(cli_conf_path: &str) -> CosmianResult<String> {
    create_symmetric_key(cli_conf_path, CreateKeyAction::default())
}

/// Export and import symmetric key
#[cfg(feature = "non-fips")]
fn export_import_sym_key(key_id: &str, cli_conf_path: &str) -> Result<String, CosmianError> {
    let export_path = unique_temp_path("output.export");
    export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_owned(),
        sub_command: "sym".to_owned(),
        key_id: key_id.to_owned(),
        key_file: export_path.clone(),
        ..Default::default()
    })?;
    let import_params = ImportKeyParams {
        cli_conf_path: cli_conf_path.to_owned(),
        sub_command: "sym".to_owned(),
        key_file: export_path,
        ..Default::default()
    };
    import_key(import_params)
}

/// Grants access to a user
pub(crate) fn grant_access(
    cli_conf_path: &str,
    object_id: Option<&str>,
    user: &str,
    operations: &[&str],
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND)
        .arg(SUB_COMMAND)
        .args(vec!["grant", user]);
    for operation in operations {
        cmd.arg(operation);
    }
    if let Some(uid) = object_id {
        cmd.args(vec!["--object-uid", uid]);
    }

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Revoke access to a user
pub(crate) fn revoke_access(
    cli_conf_path: &str,
    object_id: Option<&str>,
    user: &str,
    operations: &[&str],
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND)
        .arg(SUB_COMMAND)
        .args(vec!["revoke", user]);
    for operation in operations {
        cmd.arg(operation);
    }
    if let Some(uid) = object_id {
        cmd.args(vec!["--object-uid", uid]);
    }

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List accesses granted on an object
fn list_access(cli_conf_path: &str, object_id: &str) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND)
        .arg(SUB_COMMAND)
        .args(vec!["list", object_id]);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List objects owned by the user
fn list_owned_objects(cli_conf_path: &str) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(vec!["owned"]);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// List accesses granted
fn list_accesses_rights_obtained(cli_conf_path: &str) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND)
        .arg(SUB_COMMAND)
        .args(vec!["obtained"]);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let out = String::from_utf8(output.stdout)?;
        return Ok(out);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_ownership_and_grant() -> CosmianResult<()> {
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    // the owner should have access
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: unique_temp_path("output.json"),
        ..Default::default()
    })?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;

    // the user should not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: unique_temp_path("output.json"),
            ..Default::default()
        })
        .is_err()
    );
    // the user should not be able to encrypt or decrypt
    assert!(
        run_encrypt_decrypt_test(
            &user_client_conf_path,
            &key_id,
            DataEncryptionAlgorithm::AesGcm,
            None,
            0
        )
        .is_err()
    );
    // the user should not be able to revoke the key
    assert!(revoke(&user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should not be able to destroy the key
    assert!(destroy(&user_client_conf_path, "sym", &key_id, false).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["decrypt", "encrypt"],
    )?;

    // switch to user
    // the user should still not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: unique_temp_path("output.json"),
            ..Default::default()
        })
        .is_err()
    );

    // the user should now be able to encrypt or decrypt
    run_encrypt_decrypt_test(
        &user_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;
    // the user should still not be able to revoke the key
    assert!(revoke(&user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&user_client_conf_path, "sym", &key_id, false).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get"],
    )?;

    // switch to user
    // the user should now be able to export
    export_key(ExportKeyParams {
        cli_conf_path: user_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: unique_temp_path("output.json"),
        ..Default::default()
    })?;
    // the user should still not be able to revoke the key
    assert!(revoke(&user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&user_client_conf_path, "sym", &key_id, false).is_err());

    // switch back to owner
    // grant revoke access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["revoke"],
    )?;

    // switch to user
    // the user should now be able to revoke the key
    revoke(&user_client_conf_path, "sym", &key_id, "user revoke")?;

    // switch back to owner
    // grant destroy access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["destroy"],
    )?;

    // switch to user
    // destroy the key
    destroy(&user_client_conf_path, "sym", &key_id, false)?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_grant_error() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    // bad operation
    assert!(
        grant_access(
            &owner_client_conf_path,
            Some(&key_id),
            "user.client@acme.com",
            &["BAD_OP"],
        )
        .is_err(),
    );

    // bad object ID
    assert!(
        grant_access(
            &owner_client_conf_path,
            Some("BAD ID"),
            "user.client@acme.com",
            &["get"]
        )
        .is_err()
    );

    // grant to my self
    assert!(
        grant_access(
            &owner_client_conf_path,
            Some(&key_id),
            "owner.client@acme.com",
            &["get"]
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_revoke_access() -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    //    // the user should not be able to export
    // assert!(
    // export(
    // &user_client_conf_path,
    // "sym",
    // &key_id,
    // "/tmp/output.json",
    // None,
    // false,
    // None,
    // false,
    // )
    // .is_err()
    // );

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get"],
    )?;

    // switch to user
    // the user should now be able to export
    export_key(ExportKeyParams {
        cli_conf_path: user_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: unique_temp_path("output.json"),
        ..Default::default()
    })?;

    // switch back to owner
    // revoke access to user
    revoke_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get"],
    )?;

    // the user should not be able to export anymore
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: user_client_conf_path,
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: unique_temp_path("output.json"),
            ..Default::default()
        })
        .is_err()
    );

    // revoke errors
    // switch back to owner
    assert!(
        revoke_access(
            &owner_client_conf_path,
            Some(&key_id),
            "user.client@acme.com",
            &["BAD"]
        )
        .is_err()
    );
    assert!(
        revoke_access(
            &owner_client_conf_path,
            Some("BAD KEY"),
            "user.client@acme.com",
            &["get"]
        )
        .is_err()
    );

    // this will not error
    revoke_access(&owner_client_conf_path, Some(&key_id), "BAD USER", &["get"])?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_list_access_rights() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    // grant encrypt and decrypt access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get"],
    )?;

    // the owner can list access rights granted
    let owner_list = list_access(&owner_client_conf_path, &key_id)?;
    trace!("owner list {owner_list}");
    assert!(owner_list.contains("user.client@acme.com: {get}"));

    // The user is not the owner and thus should not be able to list accesses on this object
    assert!(list_access(&user_client_conf_path, &key_id).is_err());

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_list_access_rights_error() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (_, user_client_conf_path) = save_kms_cli_config(ctx);

    assert!(list_access(&user_client_conf_path, "BAD KEY").is_err());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_list_owned_objects() -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);
    let key_id = gen_key(&owner_client_conf_path)?;

    // grant encrypt and decrypt access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get"],
    )?;

    // The user is not the owner and thus should not have the object in the list
    let user_list = list_owned_objects(&user_client_conf_path)?;
    assert!(!user_list.contains(&key_id));

    // the owner should have the object in the list
    let owner_list = list_owned_objects(&owner_client_conf_path)?;
    assert!(owner_list.contains(&key_id));

    // create a key using the user
    let user_key_id = gen_key(&user_client_conf_path)?;

    // the user should have the object in the list
    let user_list = list_owned_objects(&user_client_conf_path)?;
    assert!(user_list.contains(&user_key_id));

    // The 'owner' is not the owner of this object and thus should not have the object in the list
    let owner_list = list_owned_objects(&owner_client_conf_path)?;
    assert!(!owner_list.contains(&user_key_id));
    // ... but the list should still contain the other key
    assert!(owner_list.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_access_right_obtained() -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    let list = list_accesses_rights_obtained(&owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // grant get access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get"],
    )?;

    // the user should have the "get" access granted
    let list = list_accesses_rights_obtained(&user_client_conf_path)?;
    trace!("user list {list}");
    assert!(list.contains(&key_id));
    assert!(list.contains("get"));

    // the owner has not been granted access rights on this object (it owns it)
    let list = list_accesses_rights_obtained(&owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // the owner should have the object in the list
    let owner_list = list_accesses_rights_obtained(&owner_client_conf_path)?;
    assert!(!owner_list.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_ownership_and_grant_wildcard_user() -> CosmianResult<()> {
    // the client conf will use the owner cert
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    // the owner should have access
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: unique_temp_path("output.json"),
        ..Default::default()
    })?;

    // the owner can encrypt and decrypt
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;

    // the user should not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: unique_temp_path("output.json"),
            ..Default::default()
        })
        .is_err()
    );
    // the user should not be able to encrypt or decrypt
    assert!(
        run_encrypt_decrypt_test(
            &user_client_conf_path,
            &key_id,
            DataEncryptionAlgorithm::AesGcm,
            None,
            0
        )
        .is_err()
    );
    // the user should not be able to revoke the key
    assert!(revoke(&user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should not be able to destroy the key
    assert!(destroy(&user_client_conf_path, "sym", &key_id, false).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(&owner_client_conf_path, Some(&key_id), "*", &["encrypt"])?;
    grant_access(&owner_client_conf_path, Some(&key_id), "*", &["decrypt"])?;

    // switch to user
    // the user should still not be able to export
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: user_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id: key_id.clone(),
            key_file: unique_temp_path("output.json"),
            ..Default::default()
        })
        .is_err()
    );

    // the user should now be able to encrypt or decrypt
    run_encrypt_decrypt_test(
        &user_client_conf_path,
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        0,
    )?;
    // the user should still not be able to revoke the key
    assert!(revoke(&user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&user_client_conf_path, "sym", &key_id, false).is_err());

    // switch back to owner
    // grant encrypt and decrypt access to user
    grant_access(&owner_client_conf_path, Some(&key_id), "*", &["get"])?;

    // switch to user
    // the user should now be able to export
    export_key(ExportKeyParams {
        cli_conf_path: user_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: unique_temp_path("output.json"),
        ..Default::default()
    })?;
    // the user should still not be able to revoke the key
    assert!(revoke(&user_client_conf_path, "sym", &key_id, "failed revoke").is_err());
    // the user should still not be able to destroy the key
    assert!(destroy(&user_client_conf_path, "sym", &key_id, false).is_err());

    // switch back to owner
    // grant revoke access to user
    grant_access(&owner_client_conf_path, Some(&key_id), "*", &["revoke"])?;

    // switch to user
    // the user should now be able to revoke the key
    revoke(&user_client_conf_path, "sym", &key_id, "user revoke")?;

    // switch back to owner
    // grant destroy access to user
    grant_access(&owner_client_conf_path, Some(&key_id), "*", &["destroy"])?;

    // switch to user
    // destroy the key
    destroy(&user_client_conf_path, "sym", &key_id, false)?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_access_right_obtained_using_wildcard() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    // the owner should not have access rights (it owns it)
    let list = list_accesses_rights_obtained(&owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // grant get access to the wildcard user
    grant_access(&owner_client_conf_path, Some(&key_id), "*", &["get"])?;

    // grant encrypt access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["encrypt"],
    )?;

    // the user should have the "get" access granted
    let list = list_accesses_rights_obtained(&user_client_conf_path)?;
    trace!("user list {list}");
    assert!(list.contains(&key_id));
    assert!(list.contains("get"));
    assert!(list.contains("encrypt"));

    // the owner has not been granted access rights on this object (it owns it)
    let list = list_accesses_rights_obtained(&owner_client_conf_path)?;
    assert!(!list.contains(&key_id));

    // the owner should have the object in the list
    let owner_list = list_accesses_rights_obtained(&owner_client_conf_path)?;
    assert!(!owner_list.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_grant_multiple_operations() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let key_id = gen_key(&owner_client_conf_path)?;

    // grant multiple access to user
    grant_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get", "revoke", "encrypt", "encrypt"], // double `encrypt` will be dedup
    )?;

    // the owner can list access rights granted
    let owner_list = list_access(&owner_client_conf_path, &key_id)?;
    assert!(owner_list.contains("user.client@acme.com: {encrypt, get, revoke}"));

    // revoke multiple access to user
    revoke_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get", "revoke", "get"], // double `get` will be dedup
    )?;

    let owner_list = list_access(&owner_client_conf_path, &key_id)?;
    assert!(owner_list.contains("user.client@acme.com: {encrypt}"));

    // revoke same, nothing changed
    revoke_access(
        &owner_client_conf_path,
        Some(&key_id),
        "user.client@acme.com",
        &["get", "revoke", "get"], // double `get` will be dedup
    )?;
    let owner_list = list_access(&owner_client_conf_path, &key_id)?;
    assert!(owner_list.contains("user.client@acme.com: {encrypt}"));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_grant_with_without_object_uid() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // grant create access to user - without object id
    let result_grant_create = grant_access(
        &owner_client_conf_path,
        None,
        "user.client@acme.com",
        &["create"],
    );

    assert!(result_grant_create.is_ok());

    // object_id is required for other operations
    let result_grant_other = grant_access(
        &owner_client_conf_path,
        None,
        "user.client@acme.com",
        &["create", "get"],
    );

    assert!(result_grant_other.is_err());

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_privileged_users() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server_with_privileged_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.privileged@acme.com".to_owned(),
    ])
    .await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    // by default privileged users can create or import objects
    let key_id = gen_key(&owner_client_conf_path);
    assert!(key_id.is_ok());
    let binding = key_id.unwrap();
    let initial_key_id = binding.as_str();
    grant_access(
        &owner_client_conf_path,
        Some(initial_key_id),
        "user.client@acme.com",
        &["export", "get"],
    )?;
    let keypair_id = create_rsa_key_pair(&owner_client_conf_path, &RsaKeyPairOptions::default());
    assert!(keypair_id.is_ok());
    let imported_key_id = export_import_sym_key(initial_key_id, &owner_client_conf_path);
    assert!(imported_key_id.is_ok());

    // by default non-privileged users can't create or import objects
    let key_id_user = gen_key(&user_client_conf_path);
    assert!(key_id_user.is_err());
    let keypair_id_user = gen_key(&user_client_conf_path);
    assert!(keypair_id_user.is_err());
    let imported_key_id = export_import_sym_key(initial_key_id, &user_client_conf_path);
    assert!(imported_key_id.is_err());

    // privileged user can grant create access
    let result_grant_create = grant_access(
        &owner_client_conf_path,
        None,
        "user.client@acme.com",
        &["create"],
    );
    assert!(result_grant_create.is_ok());

    // then user can create objects
    let key_id_user = gen_key(&user_client_conf_path);
    assert!(key_id_user.is_ok());
    let keypair_id_user = gen_key(&user_client_conf_path);
    assert!(keypair_id_user.is_ok());
    let imported_key_id = export_import_sym_key(initial_key_id, &user_client_conf_path);
    assert!(imported_key_id.is_ok());

    // simple user can't grant create access
    let result_grant_create = grant_access(
        &user_client_conf_path,
        None,
        "user2.client@acme.com",
        &["create"],
    );
    assert!(result_grant_create.is_err());

    // privileged user can't grant create access to other privileged user
    let result_grant_create = grant_access(
        &owner_client_conf_path,
        None,
        "user.privileged@acme.com",
        &["create"],
    );
    assert!(result_grant_create.is_err());

    // privileged user can revoke user create access right
    let result_revoke_create = revoke_access(
        &owner_client_conf_path,
        None,
        "user.client@acme.com",
        &["create"],
    );
    assert!(result_revoke_create.is_ok());

    // then user can't create object anymore
    let key_id_user = gen_key(&user_client_conf_path);
    assert!(key_id_user.is_err());
    let keypair_id_user = gen_key(&user_client_conf_path);
    assert!(keypair_id_user.is_err());
    let imported_key_id = export_import_sym_key(initial_key_id, &user_client_conf_path);
    assert!(imported_key_id.is_err());

    // privileged user can't revoke create access to other privileged user
    let result_revoke_create = revoke_access(
        &owner_client_conf_path,
        None,
        "user.privileged@acme.com",
        &["create"],
    );
    assert!(result_revoke_create.is_err());

    Ok(())
}
