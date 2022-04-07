use std::{fs, path::Path, process::Command};

use assert_cmd::prelude::*;
use file_diff::diff;
use predicates::prelude::*;
use regex::{Regex, RegexBuilder};

use crate::{
    config::KMS_CLI_CONF_ENV,
    tests::{
        test_utils::{init, ONCE},
        PROG_NAME,
    },
};

const SUB_COMMAND: &str = "abe";

/// Extract the key_uid (prefixed by a pattern) from a text
fn extract_uid<'a>(text: &'a str, pattern: &'a str) -> Option<&'a str> {
    let formatted = format!(r"^  {}: (?P<uid>[a-z0-9-]+)$", pattern);
    let uid_regex: Regex = RegexBuilder::new(formatted.as_str())
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

/// Extract the private key from a text.
fn extract_private_key(text: &str) -> Option<&str> {
    extract_uid(text, "Private key unique identifier")
}

/// Extract the public key from a text.
fn extract_public_key(text: &str) -> Option<&str> {
    extract_uid(text, "Public key unique identifier")
}

/// Extract the decryption user key from a text.
fn extract_user_key(text: &str) -> Option<&str> {
    extract_uid(text, "Decryption user key unique identifier")
}

#[tokio::test]
pub async fn test_init() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Private key unique identifier:"))
        .stdout(predicate::str::contains("Public key unique identifier:"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");

    cmd.arg(SUB_COMMAND)
        .args(vec!["init", "--policy", "test_data/policy.json"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Private key unique identifier:"))
        .stdout(predicate::str::contains("Public key unique identifier:"));

    Ok(())
}

#[tokio::test]
pub async fn test_init_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");

    cmd.arg(SUB_COMMAND)
        .args(vec!["init", "--policy", "test_data/notfound.json"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read the policy json file",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");

    cmd.arg(SUB_COMMAND)
        .args(vec!["init", "--policy", "test_data/policy.bad"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error: Policy JSON malformed"));

    Ok(())
}

#[test]
pub fn test_bad_conf() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env_clear();
    cmd.arg(SUB_COMMAND).args(vec!["--help"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't find KMS_CLI_CONF env variable",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "notfound.json");

    cmd.arg(SUB_COMMAND).args(vec!["--help"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read notfound.json set in the KMS_CLI_CONF env variable",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.bad");

    cmd.arg(SUB_COMMAND).args(vec!["--help"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Config JSON malformed in test_data/kms.bad",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_new() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "(department::marketing || department::finance) && level::secret",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "Decryption user key unique identifier:",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_new_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // bad attributes
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "department::marketing || level::secret2",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("secret2 is missing in axis level"));

    // bad keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "department::marketing || level::secret",
        "--secret-key-id",
        "bad_key",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Object with uid: bad_key not found",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_revoke() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "(department::marketing || department::finance) && level::secret",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
        "--revocation-reason",
        "for test",
        "-u",
        extract_user_key(stdout).unwrap(),
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Revokation is not supported yet"));

    //TODO: Uncomment that when revokation will be supported
    // cmd.assert().success();

    Ok(())
}

#[tokio::test]
pub async fn test_revoke_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    // not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
        "--revocation-reason",
        "for test",
        "-u",
        "none",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Revokation is not supported yet"));

    Ok(())
}

#[tokio::test]
pub async fn test_destroy() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "(department::marketing || department::finance) && level::secret",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND)
        .args(vec!["destroy", "-u", extract_user_key(stdout).unwrap()]);
    cmd.assert().success();

    Ok(())
}

#[tokio::test]
pub async fn test_destroy_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    // not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["destroy", "-u", "none"]);
    cmd.assert().success(); // for now this command does not fail

    Ok(())
}

#[tokio::test]
pub async fn test_rotate() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "rotate",
        "-a",
        "department::marketing",
        "-a",
        "department::finance",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The master key pair has been properly rotated.",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_rotate_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // bad attributes
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "rotate",
        "-a",
        "level::secret2",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "attribute not found: level::secret2",
    ));

    // bad keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "rotate",
        "-a",
        "department::marketing",
        "--secret-key-id",
        "bad_key",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Object with uid: bad_key not found",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    fs::remove_file("/tmp/plain.enc").ok();
    fs::remove_file("/tmp/plain.plain").ok();

    assert!(!Path::new("/tmp/plain.enc").exists());
    assert!(!Path::new("/tmp/plain.plain").exists());

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing",
        "-a",
        "level::confidential",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "test_data/plain.txt",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The encrypted file can be found at /tmp/plain.enc",
    ));

    assert!(Path::new("/tmp/plain.enc").exists());

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "(department::marketing || department::finance) && level::secret",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "--resource-uid",
        "myid",
        "-o",
        "/tmp",
        "-u",
        extract_user_key(stdout).unwrap(),
        "/tmp/plain.enc",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The decrypted file can be found at /tmp/plain.plain",
    ));

    assert!(Path::new("/tmp/plain.plain").exists());
    assert!(diff("/tmp/plain.plain", "test_data/plain.txt"));

    fs::remove_file("/tmp/plain.enc").unwrap();
    fs::remove_file("/tmp/plain.plain").unwrap();

    Ok(())
}

#[tokio::test]
pub async fn test_encrypt_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // plain text not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing",
        "-a",
        "level::confidential",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "notexist",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Can't read the file to encrypt"));

    // attributes are malformed
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "departmentmarketing",
        "-a",
        "level::confidential",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "notexist",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid attribute: separator "));

    // attributes are wellformed but not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing2",
        "-a",
        "level::confidential",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "test_data/plain.txt",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "attribute not found: department::marketing2",
    ));

    // the key is wrong
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing2",
        "-a",
        "level::confidential",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-p",
        "trash",
        "test_data/plain.txt",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Object with uid: trash not found"));

    // the output target is wrong (no right)
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing",
        "-a",
        "level::confidential",
        "-o",
        "/noexist",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "test_data/plain.txt",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Fail to write the encrypted file"));

    Ok(())
}

#[tokio::test]
pub async fn test_decrypt_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "(department::marketing || department::finance) && level::secret",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // encrypted text not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-u",
        extract_user_key(stdout).unwrap(),
        "notexist",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Can't read the file to decrypt"));

    // the key is wrong
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-u",
        "trash",
        "test_data/plain.txt",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Object with uid: trash not found"));

    // the encrpyted file is wrong
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.json");
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "-o",
        "/tmp",
        "--resource-uid",
        "myid",
        "-u",
        extract_user_key(stdout).unwrap(),
        "test_data/plain.txt",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Bad or corrupted encrypted files"));

    Ok(())
}
