use base64::Engine;
use cosmian_kms_client::{KmsClientConfig, read_object_from_json_ttlv_file};
use cosmian_logger::{error, info, trace};
use std::path::PathBuf;
use tempfile::TempDir;
use test_kms_server::{
    TestsContext, init_test_logging, load_client_config, load_server_config,
    start_temp_test_kms_server, with_server_port,
};
use tokio::fs;

use crate::{
    actions::kms::{
        access::ListOwnedObjects, shared::ExportSecretDataOrKeyAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum ScenarioOutcome {
    ShouldSucceed,
    ShouldFail,
}

async fn run_auth_scenario(
    description: &str,
    config: test_kms_server::reexport::cosmian_kms_server::config::ClapConfig,
    owner_client_config: KmsClientConfig,
    expect: ScenarioOutcome,
) -> KmsCliResult<()> {
    info!("==> {description}");
    let ctx = start_temp_test_kms_server(config, owner_client_config).await?;
    let list_result = ListOwnedObjects.run(ctx.get_owner_client()).await;
    match expect {
        ScenarioOutcome::ShouldSucceed => {
            drop(list_result?);
        }
        ScenarioOutcome::ShouldFail => {
            if list_result.is_ok() {
                error!("It should fail for test: {}", description.to_string());
            }
            list_result.unwrap_err();
        }
    }
    ctx.stop_server().await?;
    Ok(())
}

async fn create_api_token(ctx: &TestsContext) -> KmsCliResult<(String, String)> {
    let api_token_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    trace!("Symmetric key created of unique identifier: {api_token_id}");

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    ExportSecretDataOrKeyAction {
        key_file: tmp_path.join("api_token"),
        key_id: Some(api_token_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let api_token = base64::engine::general_purpose::STANDARD.encode(
        read_object_from_json_ttlv_file(&tmp_path.join("api_token"))?
            .key_block()?
            .key_bytes()?,
    );
    trace!("API token created: {api_token}");
    Ok((api_token_id.to_string(), api_token))
}

#[tokio::test]
pub(super) async fn test_kms_all_authentications() -> KmsCliResult<()> {
    init_test_logging();

    let _e = fs::remove_dir_all(PathBuf::from("./cosmian-kms")).await;

    // All auth-test servers share one SQLite database so that API-token keys
    // created by the first (no-auth) server are visible to all subsequent ones.
    // Using the process ID avoids conflicts when multiple test binaries run in parallel.
    let shared_sqlite = PathBuf::from(format!("/tmp/kms_auth_test_sqlite_{}", std::process::id()));
    let _unused = fs::remove_dir_all(&shared_sqlite).await;
    // Closure: override sqlite_path on any server config to use the shared DB.
    let with_db =
        |mut config: test_kms_server::reexport::cosmian_kms_server::config::ClapConfig| {
            config.db.sqlite_path = shared_sqlite.clone();
            config
        };

    let https_jwt_config = "test/auth_https_jwt";
    let https_client_ca_config = "test/auth_https_client_ca";
    let https_config = "test/auth_https";

    // plaintext no auth — first server starts with a fresh DB
    info!("==> Testing server with no auth");
    let mut config = with_db(load_server_config("test/auth_plain")?);
    config.db.clear_database = true;
    let ctx =
        start_temp_test_kms_server(config, load_client_config("test/auth_plain_owner")?).await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    let (api_token_id, api_token) = create_api_token(&ctx).await?;
    ctx.stop_server().await?;

    // plaintext JWT token auth
    run_auth_scenario(
        "Testing server with JWT token over HTTP",
        with_db(load_server_config("test/auth_plain_jwt")?),
        load_client_config("test/auth_plain_jwt_owner")?,
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // tls JWT token auth
    run_auth_scenario(
        "Testing server with JWT token auth over HTTPS",
        with_db(load_server_config(https_jwt_config)?),
        load_client_config("test/auth_https_jwt_cert_owner")?,
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // Client Certificate authentication
    info!("==> Testing server with Client Certificate auth");
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config(https_client_ca_config)?),
        load_client_config("test/auth_https_client_ca_owner")?,
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // SCENARIO 1: Both Client Certificates and JWT — user presents JWT token only
    run_auth_scenario(
        "Testing server with both Client Certificates and JWT auth - User sends JWT token only",
        with_db(load_server_config(https_jwt_config)?),
        load_client_config("test/auth_https_jwt_owner")?,
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // SCENARIO 2: Both Client Certificates and API token — user presents API token only
    let mut config = with_db(load_server_config(https_client_ca_config)?);
    config.http.api_token_id = Some(api_token_id.clone());
    let mut client_s2 = load_client_config("test/auth_https_client_ca_owner")?;
    client_s2.http_config.access_token = Some(api_token.clone());
    run_auth_scenario(
        "Testing server with both Client Certificates and API token auth - API token only",
        config,
        client_s2,
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // SCENARIO 3: Both JWT and API token — user presents API token only
    let mut config = with_db(load_server_config(https_config)?);
    config.http.api_token_id = Some(api_token_id.clone());
    let mut client_s3 = load_client_config("test/auth_https_owner")?;
    client_s3.http_config.access_token = Some(api_token.clone());
    run_auth_scenario(
        "Testing server with both JWT and API token auth - User sends the API token only",
        config,
        client_s3,
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // SCENARIO 4: JWT authentication enabled, no token provided (failure case)
    // Plain owner client (no JWT) connects to the JWT server — should be rejected.
    run_auth_scenario(
        "Testing server with JWT auth - User does not send the token (should fail)",
        with_db(load_server_config("test/auth_plain_jwt")?),
        with_server_port(load_client_config("test/auth_plain_owner")?, 12002),
        ScenarioOutcome::ShouldFail,
    )
    .await?;

    // SCENARIO 5: Client Certificate authentication enabled, no certificate provided (failure case)
    // HTTPS client without cert connects to the cert-required server — should be rejected.
    run_auth_scenario(
        "Testing server with Client Certificate auth - missing certificate (should fail)",
        with_db(load_server_config(https_client_ca_config)?),
        with_server_port(load_client_config("test/auth_https_owner")?, 12004),
        ScenarioOutcome::ShouldFail,
    )
    .await?;

    // SCENARIO 6: API token authentication enabled, no token provided (failure case)
    let mut config = with_db(load_server_config(https_config)?);
    config.http.api_token_id = Some(api_token_id.clone());
    run_auth_scenario(
        "Testing server with API token auth - missing token (should fail)",
        config,
        load_client_config("test/auth_https_owner")?,
        ScenarioOutcome::ShouldFail,
    )
    .await?;

    // Bad API token auth but JWT auth used at first (should succeed)
    let ctx = start_temp_test_kms_server(
        with_db(load_server_config("test/auth_plain_jwt")?),
        load_client_config("test/auth_plain_jwt_owner")?,
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // Bad API token auth, but cert auth used at first (should succeed)
    let mut config = with_db(load_server_config(https_client_ca_config)?);
    config.http.api_token_id = Some("my_bad_token_id".to_owned());
    let ctx = start_temp_test_kms_server(
        config,
        load_client_config("test/auth_https_client_ca_owner")?,
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // Bad API token and good JWT token auth but cert auth still used (should succeed)
    let mut config = with_db(load_server_config(https_jwt_config)?);
    config.http.api_token_id = Some("my_bad_token_id".to_owned());
    let ctx = start_temp_test_kms_server(
        config,
        load_client_config("test/auth_https_jwt_cert_owner")?,
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    let _e = fs::remove_dir_all(PathBuf::from("./cosmian-kms")).await;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_tls_options() -> KmsCliResult<()> {
    init_test_logging();

    let _e = fs::remove_dir_all(PathBuf::from("./sqlite-data-auth-tests")).await;

    // TLS configuration tests
    //
    // Platform note:
    // - The KMS server side in tests always terminates TLS via OpenSSL
    //   (FIPS in default builds, legacy in non-fips), with provider/runtime
    //   settings injected by `test_kms_server`.
    // - The HTTP client stack varies by platform/feature (native-tls on macOS,
    //   rustls on non-fips builds). Some expectations differ on macOS:
    //   gated with cfg!(target_os = "macos") below.

    let https_config_name = "test/auth_https";
    let https_client_ca_config_name = "test/auth_https_client_ca";

    // (description, config_name, server_cipher, client_cipher, should_succeed)
    #[allow(clippy::type_complexity)]
    let test_cases: Vec<(&str, &str, Option<&str>, Option<&str>, bool)> = vec![
        (
            "Testing server and client with no option for TLS",
            https_config_name,
            None,
            None,
            true,
        ),
        (
            "Testing server and client with same cipher suite - old TLS 1.2 cipher",
            https_config_name,
            Some("ECDHE-RSA-AES256-GCM-SHA384"),
            Some("ECDHE-RSA-AES256-GCM-SHA384"),
            true,
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2",
            https_config_name,
            Some("TLS_AES_256_GCM_SHA384"),
            None,
            cfg!(not(target_os = "macos")),
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2 - manually set for client",
            https_config_name,
            Some("TLS_AES_256_GCM_SHA384"),
            Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            cfg!(not(target_os = "macos")),
        ),
        (
            "Testing server with invalid cipher suite",
            https_config_name,
            Some("INVALID_CIPHER_SUITE"),
            None,
            false,
        ),
        (
            "Testing server and client with TLS 1.3 - same cipher suite",
            https_config_name,
            Some("TLS_AES_256_GCM_SHA384"),
            Some("TLS_AES_256_GCM_SHA384"),
            cfg!(not(target_os = "macos")),
        ),
        (
            "Testing server with tls 1.3 client - tls 1.2/1.3 server",
            https_config_name,
            None,
            Some("TLS_AES_256_GCM_SHA384"),
            true,
        ),
        (
            "Testing with client that owns a valid certificate issued from a known CA",
            https_client_ca_config_name,
            None,
            None,
            true,
        ),
    ];

    for (index, (description, config_name, server_cipher, client_cipher, should_succeed)) in
        test_cases.into_iter().enumerate()
    {
        // Each test case gets a unique port (13000..+N) to avoid conflicts when
        // a failed-case server hasn't fully released the socket yet.
        const TLS_TEST_BASE_PORT: u16 = 13000;
        info!("==> {description}");
        info!(
            "[test_tls_options] case index={} expect_success={}",
            index, should_succeed
        );

        let tls_port = TLS_TEST_BASE_PORT + u16::try_from(index)?;
        let mut config = load_server_config(config_name)?;
        config.http.port = tls_port;
        config.tls.tls_cipher_suites = server_cipher.map(str::to_owned);
        let mut client_config = if config_name == https_client_ca_config_name {
            with_server_port(
                load_client_config("test/auth_https_client_ca_owner")?,
                tls_port,
            )
        } else {
            with_server_port(load_client_config("test/auth_https_owner")?, tls_port)
        };
        client_config.http_config.cipher_suites = client_cipher.map(str::to_owned);

        let result = start_temp_test_kms_server(config, client_config).await;
        if should_succeed {
            let ctx = result?;
            ListOwnedObjects.run(ctx.get_owner_client()).await?;
            ctx.stop_server().await?;
        } else {
            if result.is_ok() {
                error!("It should fail for test: {}", description.to_string());
            }
            result.unwrap_err();
        }
    }

    Ok(())
}
