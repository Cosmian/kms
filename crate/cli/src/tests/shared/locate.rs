use std::process::Command;

use assert_cmd::prelude::*;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        access::{grant_access, revoke_access},
        cover_crypt::{
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key,
        },
        elliptic_curve::create_key_pair::create_ec_key_pair,
        symmetric::create_key::create_symmetric_key,
        utils::{recover_cmd_logs, start_default_test_kms_server, ONCE},
        PROG_NAME,
    },
};

pub fn locate(
    cli_conf_path: &str,
    tags: Option<&[&str]>,
    algorithm: Option<&str>,
    cryptographic_length: Option<usize>,
    key_format_type: Option<&str>,
) -> Result<Vec<String>, CliError> {
    let mut args: Vec<String> = vec![];
    if let Some(tags) = tags {
        for tag in tags {
            args.push("--tag".to_owned());
            args.push((*tag).to_string());
        }
    }
    if let Some(algorithm) = algorithm {
        args.push("--algorithm".to_owned());
        args.push(algorithm.to_owned());
    }
    if let Some(cryptographic_length) = cryptographic_length {
        args.push("--cryptographic-length".to_owned());
        args.push(cryptographic_length.to_string());
    }
    if let Some(key_format_type) = key_format_type {
        args.push("--key-format-type".to_owned());
        args.push(key_format_type.to_string());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("locate").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(std::str::from_utf8(&output.stdout)?
            .lines()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<String>>())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_locate_cover_crypt() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &["test_cc"],
    )?;

    // Locate with Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc"]),
        Some("coVerCRypt"),
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // locate using the key format type
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        Some("CoverCRyptPUBLIcKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    //locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc"]),
        Some("CoverCrypt"),
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));

    // generate a user key
    let user_key_id = create_user_decryption_key(
        &ctx.owner_cli_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &["test_cc", "another_tag"],
    )?;
    // Locate with Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));
    assert!(ids.contains(&user_key_id));
    //locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc"]),
        Some("CoverCrypt"),
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&user_key_id));
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc", "another_tag"]),
        Some("CoverCrypt"),
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));

    // test using system Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc", "_uk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc", "_sk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_cc", "_pk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    Ok(())
}

#[tokio::test]
pub async fn test_locate_elliptic_curve() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // generate a new key pair
    let (private_key_id, public_key_id) =
        create_ec_key_pair(&ctx.owner_cli_conf_path, &["test_ec"])?;

    // Locate with Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_ec"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&private_key_id));
    assert!(ids.contains(&public_key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_ec"]),
        Some("EcDH"),
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&private_key_id));
    assert!(ids.contains(&public_key_id));

    // locate using the key format type
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_ec"]),
        None,
        None,
        Some("TransparentECPrivateKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_ec"]),
        None,
        None,
        Some("TransparentECPublicKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&public_key_id));

    //locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_ec"]),
        Some("ECDH"),
        None,
        Some("TransparentECPrivateKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));

    // test using system Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_ec", "_sk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_ec", "_pk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&public_key_id));

    Ok(())
}

#[tokio::test]
pub async fn test_locate_symmetric_key() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // generate a new key
    let key_id = create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None, &["test_sym"])?;

    // Locate with Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_sym"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_sym"]),
        Some("Aes"),
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // locate using the key format type
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_sym"]),
        None,
        None,
        Some("TransparentSymmetricKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    //locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_sym"]),
        Some("AES"),
        None,
        Some("TransparentSymmetricKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // test using system Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_sym", "_kk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub async fn test_locate_grant() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &["test_grant"],
    )?;

    // Locate with Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_grant"]),
        Some("coVerCRypt"),
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // generate a user key
    let user_key_id = create_user_decryption_key(
        &ctx.owner_cli_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &["test_grant", "another_tag"],
    )?;
    // Locate with Tags
    let ids = locate(
        &ctx.owner_cli_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));
    assert!(ids.contains(&user_key_id));

    // the user should not be able to locate anything
    let ids = locate(
        &ctx.user_cli_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 0);

    // Grant access to the user decryption key
    grant_access(
        &ctx.owner_cli_conf_path,
        &user_key_id,
        "user.client@acme.com",
        "encrypt",
    )?;

    // The user should be able to locate the user key and only that one
    let ids = locate(
        &ctx.user_cli_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));

    //revoke the access
    revoke_access(
        &ctx.owner_cli_conf_path,
        &user_key_id,
        "user.client@acme.com",
        "encrypt",
    )?;

    // the user should no more be able to locate the key
    let ids = locate(
        &ctx.user_cli_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 0);

    Ok(())
}
