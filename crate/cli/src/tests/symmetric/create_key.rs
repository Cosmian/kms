use std::process::Command;

use assert_cmd::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};

use super::SUB_COMMAND;
use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        utils::{extract_uids::extract_uid, init_test_server, ONCE},
        PROG_NAME,
    },
};

pub fn create_symmetric_key(
    cli_conf_path: &str,
    number_of_bits: Option<usize>,
    wrap_key_b64: Option<&str>,
    algorithm: Option<&str>,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND).args(vec!["keys", "create"]);
    if let Some(number_of_bits) = number_of_bits {
        cmd.args(vec!["--number-of-bits", &number_of_bits.to_string()]);
    }
    if let Some(wrap_key_b64) = wrap_key_b64 {
        cmd.args(vec!["--bytes-b64", wrap_key_b64]);
    }
    if let Some(algorithm) = algorithm {
        cmd.args(vec!["--algorithm", algorithm]);
    }
    let output = cmd.output()?;
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;

        let unique_identifier = extract_uid(output, "The symmetric key was created with id")
            .ok_or_else(|| {
                CliError::Default("failed extracting the unique identifier".to_owned())
            })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_create_symmetric_key() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;
    let mut rng = CsRng::from_entropy();
    let mut key = vec![0u8; 32];

    // AES
    {
        // AES 256 bit key
        create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None)?;
        // AES 128 bit key
        create_symmetric_key(&ctx.owner_cli_conf_path, Some(128), None, None)?;
        //  AES 256 bit key from a base64 encoded key
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(&ctx.owner_cli_conf_path, None, Some(&key_b64), None)?;
    }

    // AChaCha20
    {
        // ChaCha20 256 bit key
        create_symmetric_key(&ctx.owner_cli_conf_path, None, None, Some("chacha20"))?;
        // ChaCha20 128 bit key
        create_symmetric_key(&ctx.owner_cli_conf_path, Some(128), None, Some("chacha20"))?;
        //  ChaCha20 256 bit key from a base64 encoded key
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(
            &ctx.owner_cli_conf_path,
            None,
            Some(&key_b64),
            Some("chacha20"),
        )?;
    }

    // Sha3
    {
        // ChaCha20 256 bit salt
        create_symmetric_key(&ctx.owner_cli_conf_path, None, None, Some("sha3"))?;
        // ChaCha20 salts
        create_symmetric_key(&ctx.owner_cli_conf_path, Some(224), None, Some("sha3"))?;
        create_symmetric_key(&ctx.owner_cli_conf_path, Some(256), None, Some("sha3"))?;
        create_symmetric_key(&ctx.owner_cli_conf_path, Some(384), None, Some("sha3"))?;
        create_symmetric_key(&ctx.owner_cli_conf_path, Some(512), None, Some("sha3"))?;
        //  ChaCha20 256 bit salt from a base64 encoded salt
        let mut rng = CsRng::from_entropy();
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);
        let key_b64 = general_purpose::STANDARD.encode(&salt);
        create_symmetric_key(&ctx.owner_cli_conf_path, None, Some(&key_b64), Some("sha3"))?;
    }
    Ok(())
}
