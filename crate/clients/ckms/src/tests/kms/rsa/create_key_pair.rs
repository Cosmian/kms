use std::{collections::HashSet, process::Command};

use assert_cmd::prelude::*;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            utils::{
                extract_uids::{extract_private_key, extract_public_key},
                recover_cmd_logs,
            },
        },
        save_kms_cli_config,
    },
};

#[derive(Default)]
pub(crate) struct RsaKeyPairOptions {
    pub(crate) number_of_bits: Option<usize>,
    pub(crate) tags: HashSet<String>,
    pub(crate) sensitive: bool,
    pub(crate) key_id: Option<String>,
}

pub(crate) fn create_rsa_key_pair(
    cli_conf_path: &str,
    options: &RsaKeyPairOptions,
) -> CosmianResult<(String, String)> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec!["keys", "create"];

    let num_s;
    if let Some(size_in_bits) = options.number_of_bits {
        args.push("--size_in_bits");
        num_s = size_in_bits.to_string();
        args.push(&num_s);
    }
    // add tags
    for tag in &options.tags {
        args.push("--tag");
        args.push(tag);
    }
    if options.sensitive {
        args.push("--sensitive");
    }
    if let Some(key_id) = options.key_id.as_ref() {
        args.push(key_id);
    }
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let rsa_output = std::str::from_utf8(&output.stdout)?;
        assert!(rsa_output.contains("Private key unique identifier:"));
        assert!(rsa_output.contains("Public key unique identifier:"));
        let private_key_id = extract_private_key(rsa_output)
            .ok_or_else(|| CosmianError::Default("failed extracting the private key".to_owned()))?
            .to_owned();
        let public_key_id = extract_public_key(rsa_output)
            .ok_or_else(|| CosmianError::Default("failed extracting the public key".to_owned()))?
            .to_owned();
        return Ok((private_key_id, public_key_id));
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_rsa_create_key_pair() -> CosmianResult<()> {
    // from specs
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);
    create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            tags: HashSet::from_iter(vec!["tag1".to_owned(), "tag2".to_owned()]),
            ..Default::default()
        },
    )?;
    Ok(())
}
