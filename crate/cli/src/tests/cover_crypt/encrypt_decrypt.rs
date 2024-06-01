use std::{fs, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{read_bytes_from_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;

use crate::{
    error::{result::CliResult, CliError},
    tests::{
        cover_crypt::{
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key, SUB_COMMAND,
        },
        utils::recover_cmd_logs,
        PROG_NAME,
    },
};

/// Encrypts a file using the given public key and access policy.
pub(crate) fn encrypt(
    cli_conf_path: &str,
    input_files: &[&str],
    public_key_id: &str,
    access_policy: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["encrypt", "--key-id", public_key_id];
    args.append(&mut input_files.to_vec());
    args.push(access_policy);

    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Decrypt a file using the given private key
pub(crate) fn decrypt(
    cli_conf_path: &str,
    input_files: &[&str],
    private_key_id: &str,
    output_file: Option<&str>,
    authentication_data: Option<&str>,
) -> CliResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["decrypt", "--key-id", private_key_id];
    args.append(&mut input_files.to_vec());

    if let Some(output_file) = output_file {
        args.push("-o");
        args.push(output_file);
    }
    if let Some(authentication_data) = authentication_data {
        args.push("-a");
        args.push(authentication_data);
    }
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_encrypt_decrypt_using_object_ids() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
        false,
    )?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // create a user decryption key
    let user_ok_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file.to_str().unwrap()],
        &user_ok_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    // this user key should not be able to decrypt the file
    let user_ko_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::FIN && Security Level::Top Secret",
        &[],
        false,
    )?;
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            &[output_file.to_str().unwrap()],
            &user_ko_key_id,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_bulk_using_object_ids() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file1 = PathBuf::from("test_data/plain.txt");
    let input_file2 = PathBuf::from("test_data/plain2.txt");
    let input_file3 = PathBuf::from("test_data/plain3.txt");

    let output_file1 = tmp_path.join("plain.enc");
    let output_file2 = tmp_path.join("plain2.enc");
    let output_file3 = tmp_path.join("plain3.enc");

    let recovered_file1 = tmp_path.join("plain.plain");
    let recovered_file2 = tmp_path.join("plain2.plain");
    let recovered_file3 = tmp_path.join("plain3.plain");

    fs::remove_file(&output_file1).ok();
    assert!(!output_file1.exists());

    fs::remove_file(&output_file2).ok();
    assert!(!output_file2.exists());

    fs::remove_file(&output_file3).ok();
    assert!(!output_file3.exists());

    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
        false,
    )?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[
            input_file1.to_str().unwrap(),
            input_file2.to_str().unwrap(),
            input_file3.to_str().unwrap(),
        ],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        tmp_path.to_str(),
        Some("myid"),
    )?;

    assert!(output_file1.exists());
    assert!(output_file2.exists());
    assert!(output_file3.exists());

    // create a user decryption key
    let user_ok_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        &[
            output_file1.to_str().unwrap(),
            output_file2.to_str().unwrap(),
            output_file3.to_str().unwrap(),
        ],
        &user_ok_key_id,
        // output file names will be based on input file name with '.rec' extension
        None,
        Some("myid"),
    )?;

    assert!(recovered_file1.exists());
    assert!(recovered_file2.exists());
    assert!(recovered_file3.exists());

    let original_content = read_bytes_from_file(&input_file1)?;
    let recovered_content = read_bytes_from_file(&recovered_file1)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file3)?;
    let recovered_content = read_bytes_from_file(&recovered_file3)?;
    assert_eq!(original_content, recovered_content);

    // this user key should not be able to decrypt the file
    let user_ko_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "Department::FIN && Security Level::Top Secret",
        &[],
        false,
    )?;
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            &[output_file1.to_str().unwrap()],
            &user_ko_key_id,
            Some(recovered_file1.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    // Test encrypted files have their own encrypted header
    // along the data and can be decrypted alone
    fs::remove_file(&recovered_file2).ok();
    assert!(!recovered_file2.exists());

    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file2.to_str().unwrap()],
        &user_ok_key_id,
        // output file names will be based on input file name with '.rec' extension
        None,
        Some("myid"),
    )?;

    assert!(recovered_file2.exists());

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_using_tags() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (_master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &["tag"],
        false,
    )?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        "[\"tag\"]",
        "Department::MKG && Security Level::Confidential",
        Some(output_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // create a user decryption key
    let user_ok_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        "[\"tag\"]",
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &["tag"],
        false,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file.to_str().unwrap()],
        "[\"tag\"]",
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    //TODO Left here but this has become undefined behavior in the new version:
    //TODO if the first key found is the correct one, decryption will work, else it will fail

    // // decrypt fails because two keys with same tag exist
    // let _user_ko_key_id = create_user_decryption_key(
    //     &ctx.owner_client_conf_path,
    //     "[\"tag\"]",
    //     "Department::FIN && Security Level::Top Secret",
    //     &["tag"], false
    // )?;
    // assert!(
    //     decrypt(
    //         &ctx.owner_client_conf_path,
    //         &[output_file.to_str().unwrap()],
    //         "[\"tag\"]",
    //         Some(recovered_file.to_str().unwrap()),
    //         Some("myid"),
    //     )
    //     .is_err()
    // );

    // this user key should not be able to decrypt the file
    let _user_ko_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        "[\"tag\"]",
        "Department::FIN && Security Level::Top Secret",
        &["tag_ko"],
        false,
    )?;
    assert!(
        decrypt(
            &ctx.owner_client_conf_path,
            &[output_file.to_str().unwrap()],
            "[\"tag_ko\"]",
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    fs::remove_file(&recovered_file).ok();
    assert!(!recovered_file.exists());
    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file.to_str().unwrap()],
        &user_ok_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    assert!(recovered_file.exists());

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_bulk_using_tags() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file1 = PathBuf::from("test_data/plain.txt");
    let input_file2 = PathBuf::from("test_data/plain2.txt");
    let input_file3 = PathBuf::from("test_data/plain3.txt");

    let output_file1 = tmp_path.join("plain.enc");
    let output_file2 = tmp_path.join("plain2.enc");
    let output_file3 = tmp_path.join("plain3.enc");

    let recovered_file1 = tmp_path.join("plain.plain");
    let recovered_file2 = tmp_path.join("plain2.plain");
    let recovered_file3 = tmp_path.join("plain3.plain");

    fs::remove_file(&output_file1).ok();
    assert!(!output_file1.exists());

    fs::remove_file(&output_file2).ok();
    assert!(!output_file2.exists());

    fs::remove_file(&output_file3).ok();
    assert!(!output_file3.exists());

    let (_master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &["tag_bulk"],
        false,
    )?;

    encrypt(
        &ctx.owner_client_conf_path,
        &[
            input_file1.to_str().unwrap(),
            input_file2.to_str().unwrap(),
            input_file3.to_str().unwrap(),
        ],
        "[\"tag_bulk\"]",
        "Department::MKG && Security Level::Confidential",
        tmp_path.to_str(),
        Some("myid"),
    )?;

    assert!(output_file1.exists());
    assert!(output_file2.exists());
    assert!(output_file3.exists());

    // create a user decryption key
    let user_ok_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        "[\"tag_bulk\"]",
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &["tag_bulk"],
        false,
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &ctx.owner_client_conf_path,
        &[
            output_file1.to_str().unwrap(),
            output_file2.to_str().unwrap(),
            output_file3.to_str().unwrap(),
        ],
        "[\"tag_bulk\"]",
        // output file names will be based on input file name with '.rec' extension
        None,
        Some("myid"),
    )?;

    assert!(recovered_file1.exists());
    assert!(recovered_file2.exists());
    assert!(recovered_file3.exists());

    let original_content = read_bytes_from_file(&input_file1)?;
    let recovered_content = read_bytes_from_file(&recovered_file1)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
    assert_eq!(original_content, recovered_content);

    let original_content = read_bytes_from_file(&input_file3)?;
    let recovered_content = read_bytes_from_file(&recovered_file3)?;
    assert_eq!(original_content, recovered_content);

    //TODO Left here but this has become undefined behavior in the new version:
    //TODO if the first key found is the correct one, decryption will work, else it will fail

    // // decrypt fails because two keys with same tag exist
    // let _user_ko_key_id = create_user_decryption_key(
    //     &ctx.owner_client_conf_path,
    //     "[\"tag_bulk\"]",
    //     "Department::FIN && Security Level::Top Secret",
    //     &["tag_bulk"],
    // )?;
    // assert!(
    //     decrypt(
    //         &ctx.owner_client_conf_path,
    //         &[output_file1.to_str().unwrap()],
    //         "[\"tag_bulk\"]",
    //         Some(recovered_file1.to_str().unwrap()),
    //         Some("myid"),
    //     )
    //     .is_err()
    // );

    // Test encrypted files have their own encrypted header
    // along the data and can be decrypted alone
    fs::remove_file(&recovered_file2).ok();
    assert!(!recovered_file2.exists());

    decrypt(
        &ctx.owner_client_conf_path,
        &[output_file2.to_str().unwrap()],
        &user_ok_key_id,
        // output file names will be based on input file name with '.rec' extension
        None,
        Some("myid"),
    )?;

    assert!(recovered_file2.exists());

    let original_content = read_bytes_from_file(&input_file2)?;
    let recovered_content = read_bytes_from_file(&recovered_file2)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}
