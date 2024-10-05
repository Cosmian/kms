#![allow(unused)]
use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use base64::Engine;
use cosmian_kms_client::{read_object_from_json_ttlv_file, KMS_CLI_CONF_ENV};
use cosmian_logger::log_utils::log_init;
use kms_test_server::{
    start_test_server_with_options, AuthenticationOptions, DBConfig, TestsContext,
};
use tempfile::TempDir;
use tracing::{info, trace};

use super::utils::recover_cmd_logs;
use crate::{
    error::result::CliResult,
    tests::{
        access::SUB_COMMAND,
        shared::{export_key, ExportKeyParams},
        symmetric::create_key::create_symmetric_key,
        PROG_NAME,
    },
};

fn run_owned_cli_command(owner_client_conf_path: &str) {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(KMS_CLI_CONF_ENV, owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

fn create_api_token(ctx: &TestsContext) -> CliResult<(String, String)> {
    // Create and export an API token
    let api_token_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    trace!("Symmetric key created of unique identifier: {api_token_id:?}");

    // Export as default (JsonTTLV with Raw Key Format Type)
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: api_token_id.clone(),
        key_file: tmp_path.join("api_token").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    let api_token = base64::engine::general_purpose::STANDARD.encode(
        read_object_from_json_ttlv_file(&tmp_path.join("api_token"))?
            .key_block()?
            .key_bytes()?,
    );
    trace!("API token created: {api_token}");
    Ok((api_token_id, api_token))
}

// let us not make other test cases fail
const PORT: u16 = 9999;

#[tokio::test]
pub(crate) async fn test_all_authentications() -> CliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // plaintext no auth
    info!("Testing server with no auth");
    let ctx = start_test_server_with_options(
        DBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
            clear_database: true,
            ..DBConfig::default()
        },
        PORT,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: false,
            use_client_cert: false,
            api_token_id: None,
            api_token: None,
        },
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    // Create an API auth token with admin rights for later
    let (api_token_id, api_token) = create_api_token(&ctx)?;
    ctx.stop_server().await?;

    let default_db_config = DBConfig {
        database_type: Some("sqlite".to_owned()),
        sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
        clear_database: false,
        ..DBConfig::default()
    };

    // plaintext JWT token auth
    info!("Testing server with JWT token auth");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: false,
            use_client_cert: false,
            api_token_id: None,
            api_token: None,
        },
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // tls token auth
    info!("Testing server with TLS token auth");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            use_client_cert: false,
            api_token_id: None,
            api_token: None,
        },
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token auth but JWT auth used at first
    info!("Testing server with bad API token auth but JWT auth used at first");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            use_client_cert: false,
            api_token_id: Some("my_bad_token_id".to_owned()),
            api_token: Some("my_bad_token".to_owned()),
        },
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // API token auth
    info!("Testing server with API token auth");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: false,
            use_client_cert: false,
            api_token_id: Some(api_token_id),
            api_token: Some(api_token),
        },
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // On recent versions of macOS, the root Certificate for the client is searched on the keychain
    // and not found, since it is a local self-signed certificate.
    // This is likely a bug in reqwest
    #[cfg(not(target_os = "macos"))]
    {
        // tls client cert auth
        info!("Testing server with TLS client cert auth");
        let ctx = start_test_server_with_options(
            default_db_config.clone(),
            PORT,
            AuthenticationOptions {
                use_jwt_token: false,
                use_https: true,
                use_client_cert: true,
                api_token_id: None,
                api_token: None,
            },
        )
        .await?;
        run_owned_cli_command(&ctx.owner_client_conf_path);
        ctx.stop_server().await?;

        // Bad API token auth but cert auth used at first
        info!("Testing server with bad API token auth but cert auth used at first");
        let ctx = start_test_server_with_options(
            default_db_config.clone(),
            PORT,
            AuthenticationOptions {
                use_jwt_token: false,
                use_https: true,
                use_client_cert: true,
                api_token_id: Some("my_bad_token_id".to_string()),
                api_token: Some("my_bad_token".to_string()),
            },
        )
        .await?;
        run_owned_cli_command(&ctx.owner_client_conf_path);
        ctx.stop_server().await?;

        // Bad API token and good JWT token auth but still cert auth used at first
        info!(
            "Testing server with bad API token and good JWT token auth but still cert auth used \
             at first"
        );
        let ctx = start_test_server_with_options(
            default_db_config,
            PORT,
            AuthenticationOptions {
                use_jwt_token: true,
                use_https: true,
                use_client_cert: true,
                api_token_id: Some("my_bad_token_id".to_string()),
                api_token: Some("my_bad_token".to_string()),
            },
        )
        .await?;
        run_owned_cli_command(&ctx.owner_client_conf_path);
        ctx.stop_server().await?;
    }

    Ok(())
}
