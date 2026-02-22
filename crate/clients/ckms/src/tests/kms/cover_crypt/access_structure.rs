use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            cover_crypt::{
                SUB_COMMAND,
                encrypt_decrypt::{decrypt, encrypt},
                master_key_pair::create_cc_master_key_pair,
                user_decryption_keys::create_user_decryption_key,
            },
            shared::{ExportKeyParams, export_key},
            utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

#[tokio::test]
async fn test_view_access_structure() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new master key pair
    let (_master_secret_key_id, master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let public_key_path = tmp_path.join("public_key.json");

    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "cc".to_owned(),
        key_id: master_public_key_id,
        key_file: format!("{}", public_key_path.display()),
        ..Default::default()
    })?;

    // read the bytes from the exported file
    // let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, &owner_client_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(vec![
        "access-structure",
        "view",
        "-f",
        &format!("{}", public_key_path.display()),
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Security Level"))
        .stdout(predicate::str::contains("Top Secret"))
        .stdout(predicate::str::contains("RnD"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, &owner_client_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(vec![
        "access-structure",
        "view",
        "-f",
        &format!("{}", public_key_path.display()),
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"Security Level\""))
        .stdout(predicate::str::contains("\"Top Secret\""))
        .stdout(predicate::str::contains(
            "Attribute { id: 6, security_mode: Classic, encryption_status: EncryptDecrypt }",
        ));

    Ok(())
}

pub(crate) async fn rename(
    cli_conf_path: &str,
    master_secret_key_id: &str,
    attribute: &str,
    new_name: &str,
) -> CosmianResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec![
        "access-structure",
        "rename-attribute",
        "--key-id",
        master_secret_key_id,
        attribute,
        new_name,
    ];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) async fn add(
    cli_conf_path: &str,
    master_secret_key_id: &str,
    new_attribute: &str,
) -> CosmianResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec![
        "access-structure",
        "add-attribute",
        "--key-id",
        master_secret_key_id,
        new_attribute,
    ];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) async fn disable(
    cli_conf_path: &str,
    master_secret_key_id: &str,
    attribute: &str,
) -> CosmianResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec![
        "access-structure",
        "disable-attribute",
        "--key-id",
        master_secret_key_id,
        attribute,
    ];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) async fn remove(
    cli_conf_path: &str,
    master_secret_key_id: &str,
    attribute: &str,
) -> CosmianResult<()> {
    start_default_test_kms_server().await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec![
        "access-structure",
        "remove-attribute",
        "--key-id",
        master_secret_key_id,
        attribute,
    ];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("successfully") {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_edit_access_structure() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let cipher_file = tmp_path.join("cipher.enc");
    let new_cipher_file = tmp_path.join("cipher.new.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_secret_key_id, master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    let user_decryption_key = create_user_decryption_key(
        &owner_client_conf_path,
        &master_secret_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    )?;

    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(cipher_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        &[cipher_file.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // Rename MKG to Marketing
    rename(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::MKG",
        "Marketing",
    )
    .await?;

    // the user key should still be able to decrypt marketing file
    decrypt(
        &owner_client_conf_path,
        &[cipher_file.to_str().unwrap()],
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // Adding new attribute "Department::Sales"
    add(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::Sales",
    )
    .await?;

    // Encrypt message for the new attribute
    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::Sales && Security Level::Confidential",
        Some(new_cipher_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // Create a new user key with access to both the new and the renamed attribute
    let sales_mkg_user_decryption_key = create_user_decryption_key(
        &owner_client_conf_path,
        &master_secret_key_id,
        "(Department::Sales || Department::Marketing) && Security Level::Confidential",
        &[],
        false,
    )?;

    // finance and marketing user can not decrypt the sales file
    assert!(
        decrypt(
            &owner_client_conf_path,
            &[new_cipher_file.to_str().unwrap()],
            &user_decryption_key,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    // sales and marketing user can decrypt the sales file
    decrypt(
        &owner_client_conf_path,
        &[new_cipher_file.to_str().unwrap()],
        &sales_mkg_user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // disable attribute Sales
    disable(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::Sales",
    )
    .await?;

    // can no longer encrypt for this attribute
    assert!(
        encrypt(
            &owner_client_conf_path,
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
        &owner_client_conf_path,
        &[new_cipher_file.to_str().unwrap()],
        &sales_mkg_user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // remove attribute Sales
    remove(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::Sales",
    )
    .await?;

    // can no longer decrypt message for this attribute
    assert!(
        decrypt(
            &owner_client_conf_path,
            &[new_cipher_file.to_str().unwrap()],
            &sales_mkg_user_decryption_key,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    Ok(())
}
