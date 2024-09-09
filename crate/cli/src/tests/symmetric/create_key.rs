use std::process::Command;

use assert_cmd::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kms_client::{kmip::extra::tagging::EMPTY_TAGS, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    error::{result::CliResult, CliError},
    tests::{
        utils::{extract_uids::extract_uid, recover_cmd_logs},
        PROG_NAME,
    },
};

/// Create a symmetric key via the CLI
pub(crate) fn create_symmetric_key(
    cli_conf_path: &str,
    number_of_bits: Option<usize>,
    wrap_key_b64: Option<&str>,
    algorithm: Option<&str>,
    tags: &[&str],
) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys", "create"];
    let num_s;
    if let Some(number_of_bits) = number_of_bits {
        num_s = number_of_bits.to_string();
        args.extend(vec!["--number-of-bits", &num_s]);
    }
    if let Some(wrap_key_b64) = wrap_key_b64 {
        args.extend(vec!["--bytes-b64", wrap_key_b64]);
    }
    if let Some(algorithm) = algorithm {
        args.extend(vec!["--algorithm", algorithm]);
    }
    // add tags
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    cmd.arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Unique identifier").ok_or_else(|| {
            CliError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_create_symmetric_key() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let mut rng = CsRng::from_entropy();
    let mut key = vec![0u8; 32];

    // AES
    {
        // AES 256 bit key
        create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
        // AES 128 bit key
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            Some(128),
            None,
            None,
            &EMPTY_TAGS,
        )?;
        //  AES 256 bit key from a base64 encoded key
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            None,
            Some(&key_b64),
            None,
            &EMPTY_TAGS,
        )?;
    }

    #[cfg(not(feature = "fips"))]
    {
        // ChaCha20 256 bit key
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            None,
            None,
            Some("chacha20"),
            &EMPTY_TAGS,
        )?;
        // ChaCha20 128 bit key
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            Some(128),
            None,
            Some("chacha20"),
            &EMPTY_TAGS,
        )?;
        //  ChaCha20 256 bit key from a base64 encoded key
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            None,
            Some(&key_b64),
            Some("chacha20"),
            &EMPTY_TAGS,
        )?;
    }

    // Sha3
    {
        // ChaCha20 256 bit salt
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            None,
            None,
            Some("sha3"),
            &EMPTY_TAGS,
        )?;
        // ChaCha20 salts
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            Some(224),
            None,
            Some("sha3"),
            &EMPTY_TAGS,
        )?;
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            Some(256),
            None,
            Some("sha3"),
            &EMPTY_TAGS,
        )?;
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            Some(384),
            None,
            Some("sha3"),
            &EMPTY_TAGS,
        )?;
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            Some(512),
            None,
            Some("sha3"),
            &EMPTY_TAGS,
        )?;
        //  ChaCha20 256 bit salt from a base64 encoded salt
        let mut rng = CsRng::from_entropy();
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);
        let key_b64 = general_purpose::STANDARD.encode(&salt);
        create_symmetric_key(
            &ctx.owner_client_conf_path,
            None,
            Some(&key_b64),
            Some("sha3"),
            &EMPTY_TAGS,
        )?;
    }
    Ok(())
}
