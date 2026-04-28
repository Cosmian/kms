use std::{fs, process::Command};

use assert_cmd::prelude::*;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use super::{SUB_COMMAND, create_key::create_fpe_key};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, save_kms_cli_config, utils::recover_cmd_logs},
};

fn fpe_encrypt(
    cli_conf_path: &str,
    input_file: &str,
    key_id: &str,
    data_type: &str,
    alphabet: Option<&str>,
    tweak: Option<&str>,
    output_file: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "encrypt".to_owned(),
        "--key-id".to_owned(),
        key_id.to_owned(),
        "--type".to_owned(),
        data_type.to_owned(),
        "-o".to_owned(),
        output_file.to_owned(),
    ];
    if let Some(a) = alphabet {
        args.push("--alphabet".to_owned());
        args.push(a.to_owned());
    }
    if let Some(t) = tweak {
        args.push("--tweak".to_owned());
        args.push(t.to_owned());
    }
    // FILE is a positional argument — pass it last
    args.push(input_file.to_owned());

    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn fpe_decrypt(
    cli_conf_path: &str,
    input_file: &str,
    key_id: &str,
    data_type: &str,
    alphabet: Option<&str>,
    tweak: Option<&str>,
    output_file: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "decrypt".to_owned(),
        "--key-id".to_owned(),
        key_id.to_owned(),
        "--type".to_owned(),
        data_type.to_owned(),
        "-o".to_owned(),
        output_file.to_owned(),
    ];
    if let Some(a) = alphabet {
        args.push("--alphabet".to_owned());
        args.push(a.to_owned());
    }
    if let Some(t) = tweak {
        args.push("--tweak".to_owned());
        args.push(t.to_owned());
    }
    // FILE is a positional argument — pass it last
    args.push(input_file.to_owned());

    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn fpe_encrypt_by_tag(
    cli_conf_path: &str,
    input_file: &str,
    tag: &str,
    data_type: &str,
    alphabet: Option<&str>,
    tweak: Option<&str>,
    output_file: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "encrypt".to_owned(),
        "--tag".to_owned(),
        tag.to_owned(),
        "--type".to_owned(),
        data_type.to_owned(),
        "-o".to_owned(),
        output_file.to_owned(),
    ];
    if let Some(a) = alphabet {
        args.push("--alphabet".to_owned());
        args.push(a.to_owned());
    }
    if let Some(t) = tweak {
        args.push("--tweak".to_owned());
        args.push(t.to_owned());
    }
    // FILE is a positional argument — pass it last
    args.push(input_file.to_owned());

    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn fpe_decrypt_by_tag(
    cli_conf_path: &str,
    input_file: &str,
    tag: &str,
    data_type: &str,
    alphabet: Option<&str>,
    tweak: Option<&str>,
    output_file: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![
        "decrypt".to_owned(),
        "--tag".to_owned(),
        tag.to_owned(),
        "--type".to_owned(),
        data_type.to_owned(),
        "-o".to_owned(),
        output_file.to_owned(),
    ];
    if let Some(a) = alphabet {
        args.push("--alphabet".to_owned());
        args.push(a.to_owned());
    }
    if let Some(t) = tweak {
        args.push("--tweak".to_owned());
        args.push(t.to_owned());
    }
    // FILE is a positional argument — pass it last
    args.push(input_file.to_owned());

    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_fpe_text_roundtrip() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);
    let key_id = create_fpe_key(&owner_client_conf_path, &[])?;

    let tmp = TempDir::new()?;
    let input = tmp.path().join("card.txt");
    let encrypted = tmp.path().join("card.enc");
    let decrypted = tmp.path().join("card.plain");
    let plaintext = "1234-5678-9012-3456";
    fs::write(&input, plaintext)?;

    fpe_encrypt(
        &owner_client_conf_path,
        input.to_str().unwrap(),
        &key_id,
        "text",
        Some("numeric"),
        Some("aabbccdd"),
        encrypted.to_str().unwrap(),
    )?;

    let ciphertext = fs::read_to_string(&encrypted)?;
    assert_ne!(
        ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );
    assert_eq!(
        ciphertext.matches('-').count(),
        plaintext.matches('-').count(),
        "FPE must preserve separator positions"
    );

    fpe_decrypt(
        &owner_client_conf_path,
        encrypted.to_str().unwrap(),
        &key_id,
        "text",
        Some("numeric"),
        Some("aabbccdd"),
        decrypted.to_str().unwrap(),
    )?;

    assert_eq!(fs::read_to_string(&decrypted)?, plaintext);
    Ok(())
}

#[tokio::test]
async fn test_fpe_integer_roundtrip() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);
    let key_id = create_fpe_key(&owner_client_conf_path, &[])?;

    let tmp = TempDir::new()?;
    let input = tmp.path().join("number.txt");
    let encrypted = tmp.path().join("number.enc");
    let decrypted = tmp.path().join("number.plain");
    let plaintext = "123456789012";
    fs::write(&input, plaintext)?;

    fpe_encrypt(
        &owner_client_conf_path,
        input.to_str().unwrap(),
        &key_id,
        "integer",
        Some("numeric"),
        Some("01020304"),
        encrypted.to_str().unwrap(),
    )?;

    let ciphertext = fs::read_to_string(&encrypted)?;
    assert_ne!(
        ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "FPE must preserve integer length"
    );

    fpe_decrypt(
        &owner_client_conf_path,
        encrypted.to_str().unwrap(),
        &key_id,
        "integer",
        Some("numeric"),
        Some("01020304"),
        decrypted.to_str().unwrap(),
    )?;

    assert_eq!(fs::read_to_string(&decrypted)?, plaintext);
    Ok(())
}

#[tokio::test]
async fn test_fpe_float_roundtrip() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);
    let key_id = create_fpe_key(&owner_client_conf_path, &[])?;

    let tmp = TempDir::new()?;
    let input = tmp.path().join("float.txt");
    let encrypted = tmp.path().join("float.enc");
    let decrypted = tmp.path().join("float.plain");
    let plaintext = "123456.789";
    fs::write(&input, plaintext)?;

    fpe_encrypt(
        &owner_client_conf_path,
        input.to_str().unwrap(),
        &key_id,
        "float",
        None,
        Some("cafebabe"),
        encrypted.to_str().unwrap(),
    )?;

    let ciphertext = fs::read_to_string(&encrypted)?;
    assert_ne!(
        ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );

    fpe_decrypt(
        &owner_client_conf_path,
        encrypted.to_str().unwrap(),
        &key_id,
        "float",
        None,
        Some("cafebabe"),
        decrypted.to_str().unwrap(),
    )?;

    assert_eq!(fs::read_to_string(&decrypted)?, plaintext);
    Ok(())
}

#[tokio::test]
async fn test_fpe_by_tag() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);
    let tag = "my-fpe-tag";
    create_fpe_key(&owner_client_conf_path, &[tag])?;

    let tmp = TempDir::new()?;
    let input = tmp.path().join("card.txt");
    let encrypted = tmp.path().join("card.enc");
    let decrypted = tmp.path().join("card.plain");
    let plaintext = "9876-5432-1098-7654";
    fs::write(&input, plaintext)?;

    fpe_encrypt_by_tag(
        &owner_client_conf_path,
        input.to_str().unwrap(),
        tag,
        "text",
        Some("numeric"),
        Some("deadbeef"),
        encrypted.to_str().unwrap(),
    )?;

    let ciphertext = fs::read_to_string(&encrypted)?;
    assert_ne!(ciphertext, plaintext);

    fpe_decrypt_by_tag(
        &owner_client_conf_path,
        encrypted.to_str().unwrap(),
        tag,
        "text",
        Some("numeric"),
        Some("deadbeef"),
        decrypted.to_str().unwrap(),
    )?;

    assert_eq!(fs::read_to_string(&decrypted)?, plaintext);
    Ok(())
}
