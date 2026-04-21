use std::{net::TcpListener, path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use base64::Engine;
use cosmian_config_utils::ConfigUtils;
use cosmian_kms_cli_actions::{
    actions::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kms_client::{
        read_object_from_json_ttlv_file, reexport::cosmian_http_client::HttpClientConfig,
    },
};
use cosmian_kms_logger::{debug, info, log_init, trace};
use tempfile::TempDir;
use test_kms_server::{
    AuthenticationOptions, ClientAuthOptions, MainDBConfig, ServerJwtAuth as JwtAuth,
    ServerTlsMode as TlsMode, build_server_params, start_default_test_kms_server_with_jwt_auth,
    start_test_server_with_options,
};
use tokio::fs;

use super::utils::recover_cmd_logs;
use crate::{
    config::{CKMS_CONF_ENV, ClientConfig},
    error::result::CosmianResult,
    tests::{
        PROG_NAME,
        access::SUB_COMMAND,
        force_save_kms_cli_config,
        shared::{ExportKeyParams, export_key},
        symmetric::create_key::create_symmetric_key,
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
            if http.tls_client_pkcs12_path.is_some() {
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
            if http.tls_client_pkcs12_path.is_some() {
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

// Pick a free local port to avoid collisions with other tests
fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to an ephemeral port")
        .local_addr()
        .expect("Failed to read local_addr")
        .port()
}

#[allow(clippy::large_stack_frames)]
#[tokio::test]
pub(crate) async fn test_kms_all_authentications() -> CosmianResult<()> {
    log_init(None);

    // Determine a base port and clean up its associated workspace directory
    let base_port = pick_free_port();
    let _e = fs::remove_dir_all(PathBuf::from(format!(
        "/tmp/kms_test_workspace_{base_port}"
    )))
    .await;

    // plaintext no auth
    info!("==> Testing server with no auth");
    let port = base_port;
    let ctx = start_test_server_with_options(
        MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
            clear_database: true,
            ..MainDBConfig::default()
        },
        port,
        AuthenticationOptions {
            client: ClientAuthOptions::default(),
            server_params: Some(build_server_params(
                MainDBConfig {
                    database_type: Some("sqlite".to_owned()),
                    sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
                    clear_database: false,
                    ..MainDBConfig::default()
                },
                port,
                TlsMode::PlainHttp,
                JwtAuth::Disabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);

    run_owned_cli_command(&owner_client_conf_path);
    // Create an API auth token with admin rights for later
    let (api_token_id, api_token) = create_api_token(&owner_client_conf_path)?;
    ctx.stop_server().await?;

    let default_db_config = MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
        clear_database: false,
        ..MainDBConfig::default()
    };

    // plaintext JWT token auth
    info!("==> Testing server with JWT token over HTTP");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                jwt: test_kms_server::JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::PlainHttp,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // tls token auth
    info!("==> Testing server with JWT token auth over HTTPS");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                jwt: test_kms_server::JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Client Certificate authentication (PKCS#12)
    info!("==> Testing server with Client Certificate auth (PKCS#12)");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions::default(),
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Client Certificate authentication (PEM cert + key — FIPS-compatible format)
    info!("==> Testing server with Client Certificate auth (PEM)");
    let port = pick_free_port();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pem_cert = manifest_dir
        .join("../../../test_data/certificates/client_server/owner/owner.client.acme.com.crt")
        .canonicalize()
        .expect("owner PEM cert must exist in test_data");
    let pem_key = manifest_dir
        .join("../../../test_data/certificates/client_server/owner/owner.client.acme.com.key")
        .canonicalize()
        .expect("owner PEM key must exist in test_data");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig {
                    tls_client_pem_cert_path: Some(pem_cert.to_string_lossy().into_owned()),
                    tls_client_pem_key_path: Some(pem_key.to_string_lossy().into_owned()),
                    ..Default::default()
                },
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 1: Both Client Certificates and JWT authentication enabled, user presents JWT token only
    info!(
        "==> Testing server with both Client Certificates and JWT auth - User sends JWT token only"
    );
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                // Suppress client certificate to ensure JWT-only auth path
                client_cert: test_kms_server::ClientCertPolicy::Suppress,
                jwt: test_kms_server::JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 2: Both Client Certificates and API token authentication enabled, user presents API token only
    info!(
        "==> Testing server with both Client Certificates and API token auth -User sends API \
         token only"
    );
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig {
                    access_token: Some(api_token.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                Some(api_token_id.clone()),
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 3: Both JWT and API token authentication enabled, user presents API token only
    info!("==> Testing server with both JWT and API token auth - User sends the API token only");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                // Suppress JWT to ensure API token only
                jwt: test_kms_server::JwtPolicy::Suppress,
                http: HttpClientConfig {
                    access_token: Some(api_token.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Enabled,
                None,
                Some(api_token_id.clone()),
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 4: JWT authentication enabled, no token provided (failure case)
    info!("==> Testing server with JWT auth - User does not send the token (should fail)");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                jwt: test_kms_server::JwtPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::PlainHttp,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command_expect_failure(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 5: Client Certificate authentication enabled, no certificate provided (failure case)
    info!("==> Testing server with Client Certificate auth - missing certificate (should fail)");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                client_cert: test_kms_server::ClientCertPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command_expect_failure(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 6: API token authentication enabled, no token provided (failure case)
    info!("==> Testing server with API token auth - missing token (should fail)");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig {
                    access_token: None, // missing token -> should fail
                    ..Default::default()
                },
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsNoClientCa,
                JwtAuth::Disabled,
                None,
                Some(api_token_id.clone()),
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command_expect_failure(&owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 7: JWT authentication enabled, but no JWT token presented (failure case)
    info!("===> Testing server with JWT auth - but no JWT token sent (should fail)");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                jwt: test_kms_server::JwtPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::PlainHttp,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command_expect_failure(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token auth but JWT auth used at first
    info!("==> Testing server with bad API token auth but JWT auth used at first");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                jwt: test_kms_server::JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::PlainHttp,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token auth, but cert auth used at first
    info!("==> Testing server with bad API token auth but cert auth used at first");
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions::default(),
            server_params: Some(build_server_params(
                default_db_config.clone(),
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                Some("my_bad_token_id".to_owned()),
            )?),
        },
        None,
        None,
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
    let port = pick_free_port();
    let ctx = start_test_server_with_options(
        default_db_config,
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                jwt: test_kms_server::JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(build_server_params(
                MainDBConfig {
                    database_type: Some("sqlite".to_owned()),
                    sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
                    clear_database: false,
                    ..MainDBConfig::default()
                },
                port,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Enabled,
                None,
                Some("my_bad_token_id".to_owned()),
            )?),
        },
        None,
        None,
    )
    .await?;
    let (owner_client_conf_path, _) = force_save_kms_cli_config(&ctx);
    run_owned_cli_command(&owner_client_conf_path);
    ctx.stop_server().await?;

    // delete the temp db dir
    let _e = fs::remove_dir_all(PathBuf::from(format!(
        "/tmp/kms_test_workspace_{base_port}"
    )))
    .await;

    Ok(())
}

/// Regression test: ensure JWT authentication succeeds end-to-end.
///
/// This test guards against the panic introduced in `jsonwebtoken` 10.x when
/// neither the `rust_crypto` nor the `aws_lc_rs` feature is enabled for that
/// crate. Previously the server worker would panic on the first JWT-authenticated
/// request with:
///
/// > "Could not automatically determine the process-level CryptoProvider …"
///
/// The test also catches the `jsonwebtoken` 10.x audience-validation regression:
/// tokens carrying an `aud` claim were rejected with `InvalidAudience` when the
/// server had no expected audience configured (`validate_aud` defaulted to `true`
/// but the expected audience set was empty).
#[allow(clippy::large_stack_frames)]
#[tokio::test]
pub(crate) async fn test_jwt_authentication_no_panic() -> CosmianResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server_with_jwt_auth().await;
    let (owner_conf_path, _) = force_save_kms_cli_config(ctx);

    // A simple `access owned` command is enough to exercise the full
    // JWT-authenticated request path without touching any cryptographic keys.
    run_owned_cli_command(&owner_conf_path);

    Ok(())
}
