use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;
use predicates::prelude::*;
use tempfile::TempDir;

use crate::{
    error::{result::CliResult, CliError},
    tests::{
        cover_crypt::{
            encrypt_decrypt::{decrypt, encrypt},
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key,
            SUB_COMMAND,
        },
        utils::recover_cmd_logs,
        PROG_NAME,
    },
};

#[tokio::test]
async fn test_view_policy() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "test_data/ttlv_public_key.json",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Security Level::<"))
        .stdout(predicate::str::contains("Top Secret::+"))
        .stdout(predicate::str::contains("R&D"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "test_data/ttlv_public_key.json",
        "--detailed",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"Security Level\""))
        .stdout(predicate::str::contains("\"Top Secret\""))
        .stdout(predicate::str::contains("\"last_attribute_value\": 7"));

    Ok(())
}

#[tokio::test]
async fn test_create_policy() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "create",
        "-s",
        "test_data/policy_specifications.json",
        "-p",
        "/tmp/policy.bin",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success().stdout(predicate::str::contains(
        "The binary policy file was generated in \"/tmp/policy.bin\".",
    ));

    Ok(())
}

pub(crate) async fn rename(
    cli_conf_path: &str,
    master_private_key_id: &str,
    attribute: &str,
    new_name: &str,
) -> CliResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let args = vec![
        "policy",
        "rename-attribute",
        "--key-id",
        master_private_key_id,
        attribute,
        new_name,
    ];
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) async fn add(
    cli_conf_path: &str,
    master_private_key_id: &str,
    new_attribute: &str,
) -> CliResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let args = vec![
        "policy",
        "add-attribute",
        "--key-id",
        master_private_key_id,
        new_attribute,
    ];
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) async fn disable(
    cli_conf_path: &str,
    master_private_key_id: &str,
    attribute: &str,
) -> CliResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let args = vec![
        "policy",
        "disable-attribute",
        "--key-id",
        master_private_key_id,
        attribute,
    ];
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) async fn remove(
    cli_conf_path: &str,
    master_private_key_id: &str,
    attribute: &str,
) -> CliResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let args = vec![
        "policy",
        "remove-attribute",
        "--key-id",
        master_private_key_id,
        attribute,
    ];
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_edit_policy() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let cipher_file = tmp_path.join("cipher.enc");
    let new_cipher_file = tmp_path.join("cipher.new.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
        false,
    )?;
    let user_decryption_key = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    )?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(cipher_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        &[cipher_file.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // Rename MKG to Marketing
    rename(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::MKG",
        "Marketing",
    )
    .await?;

    // the user key should still be able to decrypt marketing file
    decrypt(
        &ctx.owner_client_conf_path,
        &[cipher_file.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // Adding new attribute "Department::Sales"
    add(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::Sales",
    )
    .await?;

    // Encrypt message for the new attribute
    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::Sales && Security Level::Confidential",
        Some(new_cipher_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // Create a new user key with access to both the new and the renamed attribute
    let sales_mkg_user_decryption_key = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::Sales || Department::Marketing) && Security Level::Confidential",
        &[],
        false,
    )?;

    // finance and marketing user can not decrypt the sales file
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            &[new_cipher_file.to_str().unwrap()],
            &user_decryption_key,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    // sales and marketing user can decrypt the sales file
    decrypt(
        &ctx.owner_client_conf_path,
        &[new_cipher_file.to_str().unwrap()],
        &sales_mkg_user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // disable attribute Sales
    disable(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::Sales",
    )
    .await?;

    // can no longer encrypt for this attribute
    assert!(
        encrypt(
            &ctx.owner_client_conf_path,
            &[input_file.to_str().unwrap()],
            &master_public_key_id,
            "Department::Sales && Security Level::Confidential",
            None,
            None,
        )
        .is_err()
    );

    // can still decrypt existing sales files
    decrypt(
        &ctx.owner_client_conf_path,
        &[new_cipher_file.to_str().unwrap()],
        &sales_mkg_user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // remove attribute Sales
    remove(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::Sales",
    )
    .await?;

    // can no longer decrypt message for this attribute
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            &[new_cipher_file.to_str().unwrap()],
            &sales_mkg_user_decryption_key,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    Ok(())
}
