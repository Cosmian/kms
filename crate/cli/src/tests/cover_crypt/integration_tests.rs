use std::{fs, path::Path, process::Command};

use assert_cmd::prelude::*;
use file_diff::diff;
use predicates::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    tests::{
        test_utils::{init_test_server, ONCE},
        utils::extract_uids::{extract_private_key, extract_public_key, extract_user_key},
        CONF_PATH, PROG_NAME,
    },
};

const SUB_COMMAND: &str = "cc";

#[tokio::test]
pub async fn test_init() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Private key unique identifier:"))
        .stdout(predicate::str::contains("Public key unique identifier:"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);

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
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);

    cmd.arg(SUB_COMMAND)
        .args(vec!["init", "--policy", "test_data/notfound.json"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read the policy json file",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);

    cmd.arg(SUB_COMMAND)
        .args(vec!["init", "--policy", "test_data/policy.bad"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error: Policy JSON malformed"));

    Ok(())
}

#[tokio::test]
pub async fn test_bad_conf() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "notfound.json");

    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error: Can't read notfound.json"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.arg(SUB_COMMAND).args(vec!["--help"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, "test_data/kms.bad");

    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Config JSON malformed in test_data/kms.bad",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_new() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
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
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // bad attributes
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "department::marketing || level::secret2",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "attribute not found: level::secret2",
    ));

    // bad keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "department::marketing || level::secret",
        "--secret-key-id",
        "bad_key",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Object with uid: bad_key not found",
    ));

    // Import then generate a new user key
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "department::marketing || level::secret",
        "--secret-key-id",
        secret_key_id,
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "The server can't create a decryption key: the master private key is wrapped",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_revoke() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
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
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
        "--revocation-reason",
        "for test",
        "-u",
        extract_user_key(stdout).unwrap(),
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Revocation is not supported yet"));

    //TODO: Uncomment that when revocation will be supported
    // cmd.assert().success();

    // Import a wrapped key
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    // Revocation is allowed for wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
        "--revocation-reason",
        "for test",
        "-u",
        secret_key_id,
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Revocation is not supported yet"));

    Ok(())
}

#[tokio::test]
pub async fn test_revoke_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "revoke",
        "--revocation-reason",
        "for test",
        "-u",
        "none",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Revocation is not supported yet"));

    Ok(())
}

#[tokio::test]
pub async fn test_destroy() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
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
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["destroy", "-u", extract_user_key(stdout).unwrap()]);
    cmd.assert().success();

    // Import a wrapped key
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    // Destroy is allowed for wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["destroy", "-u", secret_key_id]);
    cmd.assert().success();

    Ok(())
}

#[tokio::test]
pub async fn test_destroy_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["destroy", "-u", "none"]);
    cmd.assert().success(); // for now this command does not fail

    Ok(())
}

// TODO: remove ignore when sqlcipher will supports json and operator `->`
#[tokio::test]
#[cfg_attr(feature = "sqlcipher", ignore)]
pub async fn test_rotate() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
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
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // bad attributes
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
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
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
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

    // Import a wrapped key
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    // Rotate is not allowed for wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "rotate",
        "-a",
        "department::marketing",
        "--secret-key-id",
        secret_key_id,
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "The server can't rekey: the key is wrapped",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    fs::remove_file("/tmp/plain-2.enc").ok();
    fs::remove_file("/tmp/plain-2.plain").ok();

    assert!(!Path::new("/tmp/plain-2.enc").exists());
    assert!(!Path::new("/tmp/plain-2.plain").exists());

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing",
        "-a",
        "level::confidential",
        "-o",
        "/tmp/plain-2.enc",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "test_data/plain-2.txt",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The encrypted file can be found at \"/tmp/plain-2.enc\"",
    ));

    assert!(Path::new("/tmp/plain-2.enc").exists());

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
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
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "--resource-uid",
        "myid",
        "-o",
        "/tmp/plain-2.dec",
        "-u",
        extract_user_key(stdout).unwrap(),
        "/tmp/plain-2.enc",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "The decrypted file can be found at \"/tmp/plain-2.dec\"",
    ));

    assert!(Path::new("/tmp/plain-2.dec").exists());
    assert!(diff("/tmp/plain-2.dec", "test_data/plain-2.txt"));

    fs::remove_file("/tmp/plain-2.enc").unwrap();
    fs::remove_file("/tmp/plain-2.dec").unwrap();

    Ok(())
}

#[tokio::test]
pub async fn test_encrypt_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // plain text does not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing",
        "-a",
        "level::confidential",
        "-o",
        "/tmp/output.enc",
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
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "departmentmarketing",
        "-a",
        "level::confidential",
        "-o",
        "/tmp/output.enc",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "test_data/plain-2.txt",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "at least one separator '::' expected in departmentmarketing",
    ));

    // attributes are wellformed but do not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing2",
        "-a",
        "level::confidential",
        "-o",
        "/tmp/output.enc",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "test_data/plain-2.txt",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "attribute not found: department::marketing2",
    ));

    // the key is wrong
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing2",
        "-a",
        "level::confidential",
        "-o",
        "/tmp/output.enc",
        "--resource-uid",
        "myid",
        "-p",
        "trash",
        "test_data/plain-2.txt",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Object with uid: trash not found"));

    // the output target is wrong (no right)
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing",
        "-a",
        "level::confidential",
        "-o",
        "/noexist/output.enc",
        "--resource-uid",
        "myid",
        "-p",
        extract_public_key(stdout).unwrap(),
        "test_data/plain-2.txt",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Fail to write the encrypted file"));

    // Import a wrapped key
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    // Encrypt is not allowed for wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "encrypt",
        "-a",
        "department::marketing",
        "-a",
        "level::confidential",
        "-o",
        "/tmp/output.enc",
        "--resource-uid",
        "myid",
        "-p",
        secret_key_id,
        "test_data/plain-2.txt",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "The server can't encrypt: the key is wrapped",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_decrypt_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "new",
        "(department::marketing || department::finance) && level::secret",
        "--secret-key-id",
        extract_private_key(stdout).unwrap(),
    ]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    // encrypted text does not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "-o",
        "/tmp/output.dec",
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
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "-o",
        "/tmp/output.dec",
        "--resource-uid",
        "myid",
        "-u",
        "trash",
        "test_data/plain-2.txt",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Object with uid: trash not found"));

    // the encrypted file is wrong
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "-o",
        "/tmp/output.dec",
        "--resource-uid",
        "myid",
        "-u",
        extract_user_key(stdout).unwrap(),
        "test_data/plain-2.txt",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Bad or corrupted encrypted data"));

    // Import a wrapped key
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--user-key-file",
        "test_data/wrapped_key",
        "--access-policy",
        "department::marketing || level::secret",
        "--secret-key-id",
        "random-id",
        "-w",
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let user_key_id = extract_user_key(stdout).unwrap();

    // Decrypt is not allowed for wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "decrypt",
        "-o",
        "/tmp/output.dec",
        "--resource-uid",
        "myid",
        "--user-key-id",
        user_key_id,
        "test_data/plain-2.txt",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "The server can't decrypt: the key is wrapped",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_import() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Init
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let private_key_id = extract_private_key(stdout).unwrap();

    // Export
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export",
        "-i",
        private_key_id,
        "-o",
        "/tmp/output.export",
    ]);
    cmd.assert().success();

    // Import
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["import", "-f", "/tmp/output.export"]);
    cmd.assert().success();

    Ok(())
}

#[tokio::test]
pub async fn test_import_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Secret key file not found
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["import", "--object-file", "test_data/notfound"]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read the object file: \"test_data/notfound\"",
    ));

    // Secret key file is not a TTLV one
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["import", "--object-file", "test_data/policy.bad"]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Failed reading the object file: \"test_data/policy.bad\"",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_import_keys() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Already wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Private key unique identifier:"))
        .stdout(predicate::str::contains("Public key unique identifier:"));

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    // Already wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--user-key-file",
        "test_data/wrapped_key",
        "--access-policy",
        "department::marketing || level::secret",
        "--secret-key-id",
        secret_key_id,
        "-w",
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "Decryption user key unique identifier:",
    ));

    // To wrap keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-W",
        "0123456789abcdefgijklmnopqrstuvw", // 32-bytes password
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Private key unique identifier:"))
        .stdout(predicate::str::contains("Public key unique identifier:"));

    // To wrap keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--user-key-file",
        "test_data/wrapped_key",
        "--access-policy",
        "department::marketing || level::secret",
        "--secret-key-id",
        secret_key_id,
        "-W",
        "0123456789abcdefgijklmnopqrstuvw", // 32-bytes password
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "Decryption user key unique identifier:",
    ));

    // Not wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Private key unique identifier:"))
        .stdout(predicate::str::contains("Public key unique identifier:"));

    // Not wrapped keys
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--user-key-file",
        "test_data/wrapped_key",
        "--access-policy",
        "department::marketing || level::secret",
        "--secret-key-id",
        secret_key_id,
    ]);
    cmd.assert().success().stdout(predicate::str::contains(
        "Decryption user key unique identifier:",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_import_keys_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Policy file not found
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/notfound.json",
        "-w",
    ]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read the policy json file",
    ));

    // Secret key file not found
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/notfound",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read the private key file",
    ));

    // Public key file not found
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/notfound",
        "--policy",
        "test_data/policy.json",
        "-w",
    ]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read the public key file",
    ));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let private_key_id = extract_private_key(stdout).unwrap();

    // User key file not found
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--user-key-file",
        "test_data/notfound",
        "--access-policy",
        "department::marketing || level::secret",
        "--secret-key-id",
        private_key_id,
        "-w",
    ]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: Can't read the user key file",
    ));

    // Bad attributes
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--user-key-file",
        "test_data/wrapped_key",
        "--access-policy",
        "department::marketing || level::secret2",
        "--secret-key-id",
        private_key_id,
        "-w",
    ]);

    // TODO: For now, it's a success. We do not check the attributes set in the object we import.
    cmd.assert().success().stdout(predicate::str::contains(
        "Decryption user key unique identifier:",
    ));

    // Bad key
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--user-key-file",
        "test_data/wrapped_key",
        "--access-policy",
        "department::marketing || level::secret2",
        "--secret-key-id",
        "bad_key",
        "-w",
    ]);

    // TODO: For now, we do not check if the secret_key_id exist
    cmd.assert().success().stdout(predicate::str::contains(
        "Decryption user key unique identifier:",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_export_keys() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Get from init
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export-keys",
        "-k",
        extract_private_key(stdout).unwrap(),
        "/tmp/output.get",
    ]);

    cmd.assert().success().stdout(predicate::str::contains(
        "The key file can be found at /tmp/output.get",
    ));

    // Get from import
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-W",
        "0123456789abcdefgijklmnopqrstuvw", // 32-bytes password
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["export-keys", "-k", secret_key_id, "/tmp/output.get"]);

    cmd.assert().success().stdout(predicate::str::contains(
        "The key file can be found at /tmp/output.get",
    ));

    // We forgot to unwrap
    assert!(!diff("test_data/wrapped_key", "/tmp/output.get"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export-keys",
        "-k",
        secret_key_id,
        "-W",
        "0123456789abcdefgijklmnopqrstuvw", // 32-bytes password
        "/tmp/output.get",
    ]);

    cmd.assert().success().stdout(predicate::str::contains(
        "The key file can be found at /tmp/output.get",
    ));

    // We unwrapped
    assert!(diff("test_data/wrapped_key", "/tmp/output.get"));

    Ok(())
}

#[tokio::test]
pub async fn test_export_keys_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Get from init
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    // Bad output
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export-keys",
        "-k",
        secret_key_id,
        "/notexist/notexist",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Fail to write the key file"));

    // Id not exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND)
        .args(vec!["export-keys", "-k", "not_exist", "/tmp/output.get"]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Item not found: Object with uid: not_exist not found",
    ));

    // Unwrap not wrapped
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export-keys",
        "-k",
        secret_key_id,
        "-W",
        "0123456789abcdefgijklmnopqrstuvw", // 32-bytes password
        "/tmp/output.get",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid_Data_Type: Invalid size"));

    // Get from import
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "import-keys",
        "--secret-key-file",
        "test_data/wrapped_key",
        "--public-key-file",
        "test_data/wrapped_key",
        "--policy",
        "test_data/policy.json",
        "-W",
        "0123456789abcdefgijklmnopqrstuvw", // 32-bytes password
    ]);

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let secret_key_id = extract_private_key(stdout).unwrap();

    // Unwrapped with bad password
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export-keys",
        "-k",
        secret_key_id,
        "-W",
        "0000000000abcdefgijklmnopqrstuvw", // wrong 32-bytes password
        "/tmp/output.get",
    ]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "The ciphertext is invalid. Decrypted IV is not appropriate",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_export() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Init
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let private_key_id = extract_private_key(stdout).unwrap();

    // Export
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export",
        "-i",
        private_key_id,
        "-o",
        "/tmp/output.export",
    ]);
    cmd.assert().success();

    // Export but don't exist
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export",
        "-i",
        "dont_exist",
        "-o",
        "/tmp/output2.export",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: failed retrieving the object dont_exist",
    ));

    Ok(())
}

#[tokio::test]
pub async fn test_export_error() -> Result<(), Box<dyn std::error::Error>> {
    ONCE.get_or_init(init_test_server).await;

    // Init
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["init"]);
    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout)?;
    let private_key_id = extract_private_key(stdout).unwrap();

    // Export
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec![
        "export",
        "-i",
        private_key_id,
        "-o",
        "/notexist/notexist",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Fail to write exported file"));

    Ok(())
}
