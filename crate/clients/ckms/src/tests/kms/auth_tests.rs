use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use base64::Engine;
use cosmian_config_utils::ConfigUtils;
use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kms_client::read_object_from_json_ttlv_file,
};
use cosmian_logger::{debug, info, log_init, trace};
use tempfile::TempDir;
use test_kms_server::{
    load_client_config, load_server_config, start_temp_test_kms_server, with_server_port,
};
use tokio::fs;

use super::utils::recover_cmd_logs;
use crate::{
    config::{CKMS_CONF_ENV, ClientConfig},
    error::result::CosmianResult,
    tests::{
        PROG_NAME, force_save_kms_cli_config,
        kms::{
            access::SUB_COMMAND,
            shared::{ExportKeyParams, export_key},
            symmetric::create_key::create_symmetric_key,
        },
    },
};

fn run_owned_cli_command(owner_client_conf_path: &str) {
    // Debug: ensure token/cert presence in saved config
    if let Ok(conf) = ClientConfig::from_toml(owner_client_conf_path) {
        let http = &conf.kms_config.http_config;
        debug!(
            "[auth_tests] Using conf {} => url: {}, token: {}, cert: {}",
            owner_client_conf_path,
            http.server_url,
            if http.access_token.is_some() {
                "set"
            } else {
                "none"
            },
            if http.ssl_client_pkcs12_path.is_some() {
                "set"
            } else {
                "none"
            }
        );
    }
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(CKMS_CONF_ENV, owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

/// This function runs the CLI command with the provided configuration path and expects it to fail.
fn run_owned_cli_command_expect_failure(owner_client_conf_path: &str) {
    // Debug: ensure token/cert presence in saved config
    if let Ok(conf) = ClientConfig::from_toml(owner_client_conf_path) {
        let http = &conf.kms_config.http_config;
        debug!(
            "[auth_tests] Using conf (expected fail) {} => url: {}, token: {}, cert: {}",
            owner_client_conf_path,
            http.server_url,
            if http.access_token.is_some() {
                "set"
            } else {
                "none"
            },
            if http.ssl_client_pkcs12_path.is_some() {
                "set"
            } else {
                "none"
            }
        );
    }
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(CKMS_CONF_ENV, owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();
}

fn create_api_token(owner_client_conf_path: &str) -> CosmianResult<(String, String)> {
    // Create and export an API token
    let api_token_id = create_symmetric_key(owner_client_conf_path, CreateKeyAction::default())?;
    trace!("Symmetric key created of unique identifier: {api_token_id:?}");

    // Export as default (JsonTTLV with Raw Key Format Type)
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.to_string(),
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

#[allow(clippy::large_stack_frames)]
#[tokio::test]
pub(crate) async fn test_kms_all_authentications() -> CosmianResult<()> {
    log_init(None);

    // All auth-test servers share one SQLite database so that API-token keys
    // created by the first (no-auth) server are visible to all subsequent ones.
    // Using the process ID avoids conflicts when multiple test binaries run in parallel.
    let shared_sqlite = PathBuf::from(format!("/tmp/kms_auth_test_sqlite_{}", std::process::id()));
    let _unused = fs::remove_dir_all(&shared_sqlite).await;
    let with_db =
        |mut config: test_kms_server::reexport::cosmian_kms_server::config::ClapConfig| {
            config.db.sqlite_path = shared_sqlite.clone();
            config
        };

    let https_jwt_config = "test_auth_https_jwt";
    let https_client_ca_config = "test_auth_https_client_ca";
    let https_config = "test_auth_https";

    // plaintext no auth — first server starts with a fresh DB
    info!("==> Testing server with no auth");
    let mut config = with_db(load_server_config("test_auth_plain")?);
    config.db.clear_database = true;
    let ctx =
        start_temp_test_kms_server(config, load_client_config("test_auth_plain_owner")?).await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);

    run_owned_cli_command(&owner_client_conf_path);
    // Create an API auth token with admin rights for later
    let (api_token_id, api_token) = create_api_token(&owner_client_conf_path)?;
    ctx.stop_server().await?;

    // plaintext JWT token auth
    info!("==> Testing server with JWT token over HTTP");
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config("test_auth_plain_jwt")?),
        load_client_config("test_auth_plain_jwt_owner")?,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // tls token auth
    info!("==> Testing server with JWT token auth over HTTPS");
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config(https_jwt_config)?),
        load_client_config("test_auth_https_jwt_cert_owner")?,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Client Certificate authentication
    info!("==> Testing server with Client Certificate auth");
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config(https_client_ca_config)?),
        load_client_config("test_auth_https_client_ca_owner")?,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 1: Both Client Certificates and JWT authentication enabled, user presents JWT token only
    info!(
        "==> Testing server with both Client Certificates and JWT auth - User sends JWT token only"
    );
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config(https_jwt_config)?),
        load_client_config("test_auth_https_jwt_owner")?,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 2: Both Client Certificates and API token authentication enabled, user presents API token only
    info!(
        "==> Testing server with both Client Certificates and API token auth - User sends API \
         token only"
    );
    let mut config = with_db(load_server_config(https_client_ca_config)?);
    config.http.api_token_id = Some(api_token_id.clone());
    let mut client_s2 = load_client_config("test_auth_https_client_ca_owner")?;
    client_s2.http_config.access_token = Some(api_token.clone());
    let ctx = start_temp_test_kms_server(config, client_s2).await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 3: Both JWT and API token authentication enabled, user presents API token only
    info!("==> Testing server with both JWT and API token auth - User sends the API token only");
    let mut config = with_db(load_server_config(https_jwt_config)?);
    config.http.api_token_id = Some(api_token_id.clone());
    let mut client_s3 = load_client_config("test_auth_https_owner")?;
    client_s3.http_config.access_token = Some(api_token.clone());
    let ctx = start_temp_test_kms_server(config, client_s3).await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 4: JWT authentication enabled, no token provided (failure case)
    info!("==> Testing server with JWT auth - User does not send the token (should fail)");
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config("test_auth_plain_jwt")?),
        with_server_port(load_client_config("test_auth_plain_owner")?, 12002),
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command_expect_failure(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 5: Client Certificate authentication enabled, no certificate provided (failure case)
    info!("==> Testing server with Client Certificate auth - missing certificate (should fail)");
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config(https_client_ca_config)?),
        with_server_port(load_client_config("test_auth_https_owner")?, 12004),
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command_expect_failure(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 6: API token authentication enabled, no token provided (failure case)
    info!("==> Testing server with API token auth - missing token (should fail)");
    let mut config = with_db(load_server_config(https_config)?);
    config.http.api_token_id = Some(api_token_id.clone());
    let ctx =
        start_temp_test_kms_server(config, load_client_config("test_auth_https_owner")?).await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command_expect_failure(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token auth but JWT auth used at first
    info!("==> Testing server with bad API token auth but JWT auth used at first");
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config("test_auth_plain_jwt")?),
        load_client_config("test_auth_plain_jwt_owner")?,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token auth, but cert auth used at first
    info!("==> Testing server with bad API token auth but cert auth used at first");
    let mut config = with_db(load_server_config(https_client_ca_config)?);
    config.http.api_token_id = Some("my_bad_token_id".to_owned());
    let ctx = start_temp_test_kms_server(
        config,
        load_client_config("test_auth_https_client_ca_owner")?,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token and good JWT token auth but still cert auth used at first
    info!(
        "==> Testing server with bad API token and good JWT token auth but still cert auth used \
         at first"
    );
    let mut config = with_db(load_server_config(https_jwt_config)?);
    config.http.api_token_id = Some("my_bad_token_id".to_owned());
    let ctx = start_temp_test_kms_server(
        config,
        load_client_config("test_auth_https_jwt_cert_owner")?,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // delete the temp db dir
    let _e = fs::remove_dir_all(&shared_sqlite).await;

    Ok(())
}
