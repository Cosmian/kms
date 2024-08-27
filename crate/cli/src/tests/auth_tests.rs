use std::process::Command;

use assert_cmd::prelude::*;
use base64::Engine;
use cosmian_kms_client::{read_object_from_json_ttlv_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_test_server_with_options;
use tempfile::TempDir;
use tracing::trace;

use super::utils::recover_cmd_logs;
use crate::{
    error::result::CliResult,
    tests::{
        access::SUB_COMMAND, shared::export_key, symmetric::create_key::create_symmetric_key,
        PROG_NAME,
    },
};

fn run_cli_command(owner_client_conf_path: &str) {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(KMS_CLI_CONF_ENV, owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

// let us not make other test cases fail
const PORT: u16 = 9999;

#[tokio::test]
pub(crate) async fn test_all_authentications() -> CliResult<()> {
    // plaintext no auth
    let ctx =
        start_test_server_with_options("sqlite", PORT, false, false, false, None, None).await?;
    run_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // plaintext JWT token auth
    let ctx =
        start_test_server_with_options("sqlite", PORT, true, false, false, None, None).await?;
    run_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // tls token auth
    let ctx = start_test_server_with_options("sqlite", PORT, true, true, false, None, None).await?;
    run_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // tls client cert auth
    let ctx = start_test_server_with_options("sqlite", PORT, false, true, true, None, None).await?;
    run_cli_command(&ctx.owner_client_conf_path);

    // Create and export an API token
    let api_token_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    trace!("New API token ID: {:?}", api_token_id);

    // Export as default (JsonTTLV with Raw Key Format Type)
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &api_token_id,
        tmp_path.join("api_token").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;
    let api_token = base64::engine::general_purpose::STANDARD.encode(
        read_object_from_json_ttlv_file(&tmp_path.join("api_token"))?
            .key_block()?
            .key_bytes()?,
    );
    trace!("New API token: {api_token}");
    ctx.stop_server().await?;

    // // API token auth
    // let ctx = start_test_server_with_options(
    //     "sqlite",
    //     PORT,
    //     false,
    //     false,
    //     false,
    //     Some(api_token_id),
    //     Some(api_token),
    // )
    // .await?;
    // run_cli_command(&ctx.owner_client_conf_path);
    // ctx.stop_server().await?;

    Ok(())
}
