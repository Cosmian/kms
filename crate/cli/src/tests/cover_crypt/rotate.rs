use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use tempfile::TempDir;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::{
            encrypt_decrypt::{decrypt, encrypt},
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key,
            SUB_COMMAND,
        },
        shared::{export::export, import::import},
        symmetric::create_key::create_symmetric_key,
        test_utils::{init_test_server, ONCE},
        CONF_PATH, PROG_NAME,
    },
};

pub async fn rotate(master_private_key_id: &str, attributes: &[&str]) -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    let mut args = vec!["rotate", master_private_key_id];
    args.extend_from_slice(attributes);
    cmd.arg(SUB_COMMAND).args(args);
    let output = cmd.output()?;
    if output.status.success()
        && std::str::from_utf8(&output.stdout)?.contains("were rotated for attributes")
    {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_rotate() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;
    let _user_decryption_key = create_user_decryption_key(
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
    );

    rotate(
        &master_private_key_id,
        &["Department::MKG", "Department::FIN"],
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_rotate_error() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;
    let _user_decryption_key = create_user_decryption_key(
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
    );

    // bad attributes
    assert!(
        rotate(&master_private_key_id, &["bad_attribute"])
            .await
            .is_err()
    );

    // bad keys
    assert!(
        rotate("bad_key", &["Department::MKG", "Department::FIN"])
            .await
            .is_err()
    );

    // Import a wrapped key

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // create a symmetric key
    let symmetric_key_id = create_symmetric_key(None, None, None).await?;
    // export a wrapped key
    let exported_wrapped_key_file = tmp_path.join("exported_wrapped_master_private.key");
    export(
        SUB_COMMAND,
        &master_private_key_id,
        exported_wrapped_key_file.to_str().unwrap(),
        false,
        false,
        Some(symmetric_key_id),
        false,
    )
    .await?;
    // import it wrapped
    let wrapped_key_id = import(
        SUB_COMMAND,
        &exported_wrapped_key_file.to_string_lossy(),
        None,
        false,
        true,
    )
    .await?;
    // Rotate is not allowed for wrapped keys
    assert!(
        rotate(&wrapped_key_id, &["Department::MKG", "Department::FIN"])
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn test_decrypt_rotate_decrypt() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file_before = tmp_path.join("plain.before.enc");
    let output_file_after = tmp_path.join("plain.after.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )
    .await?;
    let user_decryption_key = create_user_decryption_key(
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
    )
    .await?;

    encrypt(
        input_file.to_str().unwrap(),
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file_before.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        output_file_before.to_str().unwrap(),
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // export the user_decryption_key
    let exported_user_decryption_key_file = tmp_path.join("exported_user_decryption.key");
    export(
        SUB_COMMAND,
        &user_decryption_key,
        exported_user_decryption_key_file.to_str().unwrap(),
        false,
        false,
        None,
        false,
    )
    .await?;

    //rotate the attributes
    rotate(
        &master_private_key_id,
        &["Department::MKG", "Department::FIN"],
    )
    .await?;

    // encrypt again after the rotation
    encrypt(
        input_file.to_str().unwrap(),
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file_after.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the new file
    decrypt(
        output_file_after.to_str().unwrap(),
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    // ... and the old file
    decrypt(
        output_file_before.to_str().unwrap(),
        &user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // import the non rotated user_decryption_key
    let old_user_decryption_key = import(
        SUB_COMMAND,
        &exported_user_decryption_key_file.to_string_lossy(),
        None,
        false,
        false,
    )
    .await?;
    // the imported user key should not be able to decrypt the new file
    assert!(
        decrypt(
            output_file_after.to_str().unwrap(),
            &old_user_decryption_key,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );
    // ... but should decrypt the old file
    decrypt(
        output_file_before.to_str().unwrap(),
        &old_user_decryption_key,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    Ok(())
}
