use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli::actions::kms::symmetric::keys::create_key::CreateKeyAction;
#[cfg(feature = "non-fips")]
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server_with_cert_auth;

#[cfg(feature = "non-fips")]
use crate::tests::kms::elliptic_curve::create_key_pair::create_ec_key_pair;
#[cfg(feature = "non-fips")]
use crate::tests::kms::{
    access::{grant_access, revoke_access},
    cover_crypt::{
        master_key_pair::create_cc_master_key_pair,
        user_decryption_keys::create_user_decryption_key,
    },
};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            symmetric::create_key::create_symmetric_key,
            utils::{extract_uids::extract_locate_uids, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

pub(crate) fn locate(
    cli_conf_path: &str,
    tags: Option<&[&str]>,
    algorithm: Option<&str>,
    cryptographic_length: Option<usize>,
    key_format_type: Option<&str>,
) -> CosmianResult<Vec<String>> {
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
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg("locate").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let uids = extract_locate_uids(std::str::from_utf8(&output.stdout)?);
        return Ok(uids.unwrap_or_default());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_locate_cover_crypt() -> CosmianResult<()> {
    use crate::tests::save_kms_cli_config;

    log_init(option_env!("RUST_LOG"));

    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &["test_cc"],
        false,
    )?;

    // Locate with Tags
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // Locate with cryptographic algorithm (CLI expects lowercase names)
    let ids = locate(
        &owner_client_conf_path,
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
        &owner_client_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        Some("CoverCRyptPUBLIcKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc"]),
        Some("CoverCrypt"),
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));

    // generate a user key
    let user_key_id = create_user_decryption_key(
        &owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &["test_cc", "another_tag"],
        false,
    )?;
    // Locate with Tags
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));
    assert!(ids.contains(&user_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc"]),
        Some("CoverCrypt"),
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&user_key_id));
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc", "another_tag"]),
        Some("CoverCrypt"),
        None,
        Some("CoverCryptSecretKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));

    // test using system Tags
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc", "_uk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc", "_sk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_cc", "_pk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_locate_elliptic_curve() -> CosmianResult<()> {
    use crate::tests::save_kms_cli_config;

    log_init(option_env!("RUST_LOG"));
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new key pair
    let (private_key_id, public_key_id) =
        create_ec_key_pair(&owner_client_conf_path, "nist-p256", &["test_ec"], false)?;

    // Locate with Tags
    let ids = locate(
        &owner_client_conf_path,
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
        &owner_client_conf_path,
        Some(&["test_ec"]),
        Some("ECDH"),
        None,
        None,
    )?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&private_key_id));
    assert!(ids.contains(&public_key_id));

    // locate using the key format type
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_ec"]),
        None,
        None,
        Some("TransparentECPrivateKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_ec"]),
        None,
        None,
        Some("TransparentECPublicKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&public_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_ec"]),
        Some("eCdH"),
        None,
        Some("TransparentECPrivateKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));

    // test using system Tags
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_ec", "_sk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = locate(
        &owner_client_conf_path,
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
pub(crate) async fn test_locate_symmetric_key() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new key
    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            tags: vec!["test_sym".to_string()],
            ..Default::default()
        },
    )?;

    // Locate with Tags
    let ids = locate(
        &owner_client_conf_path,
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
        &owner_client_conf_path,
        Some(&["test_sym"]),
        Some("aes"),
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // locate using the key format type
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_sym"]),
        None,
        None,
        Some("TransparentSymmetricKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_sym"]),
        Some("aes"),
        None,
        Some("TransparentSymmetricKey"),
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // test using system Tags
    let ids = locate(
        &owner_client_conf_path,
        Some(&["test_sym", "_kk"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_locate_grant() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let (owner_client_conf_path, user_client_conf_path) = save_kms_cli_config(ctx);

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &["test_grant"],
        false,
    )?;

    // Locate with Tags
    let ids = locate(
        &owner_client_conf_path,
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
        &owner_client_conf_path,
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
        &owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &["test_grant", "another_tag"],
        false,
    )?;
    // Locate with Tags
    let ids = locate(
        &owner_client_conf_path,
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
        &user_client_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 0);

    // Grant access to the user decryption key
    grant_access(
        &owner_client_conf_path,
        Some(&user_key_id),
        "user.client@acme.com",
        &["encrypt"],
    )?;

    // The user should be able to locate the user key and only that one
    let ids = locate(
        &user_client_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));

    // revoke the access
    revoke_access(
        &owner_client_conf_path,
        Some(&user_key_id),
        "user.client@acme.com",
        &["encrypt"],
    )?;

    // the user should no more be able to locate the key
    let ids = locate(
        &user_client_conf_path,
        Some(&["test_grant"]),
        None,
        None,
        None,
    )?;
    assert_eq!(ids.len(), 0);

    Ok(())
}
