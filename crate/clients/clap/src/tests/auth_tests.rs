use base64::Engine;
use cosmian_kms_client::{
    read_object_from_json_ttlv_file, reexport::cosmian_http_client::HttpClientConfig,
};
#[cfg(not(target_os = "windows"))]
use cosmian_logger::error;
use cosmian_logger::{info, trace};
use tempfile::TempDir;
use test_kms_server::{
    TestClientOptions, TestsContext, init_test_logging, start_test_server,
    start_test_server_with_patch, test_config_path,
};

use crate::{
    actions::{
        access::ListOwnedObjects, shared::ExportSecretDataOrKeyAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

async fn create_api_token(ctx: &TestsContext) -> KmsCliResult<(String, String)> {
    // Create and export an API token
    let api_token_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    trace!("Symmetric key created of unique identifier: {api_token_id}");

    // Export as default (JsonTTLV with Raw Key Format Type)
    // create a temp dir
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

    // Create a shared temp dir for scenarios that need API token persistence
    // across server restarts (the token is created once and reused).
    let shared_db_dir = TempDir::new()?;
    let shared_db_path = shared_db_dir.path().join("sqlite-data");

    // ── Plain HTTP, no auth ────────────────────────────────────────────────
    info!("==> Testing server with no auth");
    let db_path = shared_db_path.clone();
    let ctx = start_test_server_with_patch(
        &test_config_path("auth_plain.toml"),
        move |config| {
            config.db.sqlite_path = db_path;
        },
        TestClientOptions::default(),
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    // Create an API auth token with admin rights for later scenarios
    let (api_token_id, api_token) = create_api_token(&ctx).await?;
    ctx.stop_server().await?;

    // ── Plain HTTP, JWT auth ─────────────────────────────────────────────
    info!("==> Testing server with JWT token over HTTP");
    let ctx = start_test_server(
        &test_config_path("auth_plain_jwt.toml"),
        TestClientOptions {
            send_jwt: true,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── HTTPS + Client CA + JWT ──────────────────────────────────────────
    info!("==> Testing server with JWT token auth over HTTPS");
    let ctx = start_test_server(
        &test_config_path("auth_https_jwt.toml"),
        TestClientOptions {
            send_jwt: true,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── Client Certificate auth ──────────────────────────────────────────
    info!("==> Testing server with Client Certificate auth");
    let ctx = start_test_server(
        &test_config_path("auth_https_client_ca.toml"),
        TestClientOptions::default(),
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── SCENARIO 1: Cert+JWT enabled, client sends JWT only ──────────────
    info!(
        "==> Testing server with both Client Certificates and JWT auth - User sends JWT token only"
    );
    let ctx = start_test_server(
        &test_config_path("auth_https_jwt.toml"),
        TestClientOptions {
            send_client_cert: false,
            send_jwt: true,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── SCENARIO 2: Cert+API token enabled, client sends API token only ──
    info!(
        "==> Testing server with both Client Certificates and API token auth - User sends API \
         token only"
    );
    let api_token_clone = api_token.clone();
    let api_token_id_clone = api_token_id.clone();
    let db_path = shared_db_path.clone();
    let ctx = start_test_server_with_patch(
        &test_config_path("auth_https_client_ca.toml"),
        move |config| {
            config.http.api_token_id = Some(api_token_id_clone);
            config.db.sqlite_path = db_path;
            config.db.clear_database = false;
        },
        TestClientOptions {
            http: HttpClientConfig {
                access_token: Some(api_token_clone),
                ..Default::default()
            },
            send_jwt: false,
            send_api_token: true,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── SCENARIO 3: JWT+API token enabled, client sends API token only ───
    info!("==> Testing server with both JWT and API token auth - User sends the API token only");
    let api_token_clone = api_token.clone();
    let api_token_id_clone = api_token_id.clone();
    let db_path = shared_db_path.clone();
    let ctx = start_test_server_with_patch(
        &test_config_path("auth_https_no_client_ca_jwt.toml"),
        move |config| {
            config.http.api_token_id = Some(api_token_id_clone);
            config.db.sqlite_path = db_path;
            config.db.clear_database = false;
        },
        TestClientOptions {
            http: HttpClientConfig {
                access_token: Some(api_token_clone),
                ..Default::default()
            },
            send_jwt: false,
            send_api_token: true,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── SCENARIO 4: JWT required, no token (failure) ─────────────────────
    info!("==> Testing server with JWT auth - User does not send the token (should fail)");
    let ctx = start_test_server(
        &test_config_path("auth_plain_jwt.toml"),
        TestClientOptions {
            send_jwt: false,
            send_api_token: false,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;

    // ── SCENARIO 5: Client Cert required, no cert (failure) ──────────────
    info!("==> Testing server with Client Certificate auth - missing certificate (should fail)");
    let ctx = start_test_server(
        &test_config_path("auth_https_client_ca.toml"),
        TestClientOptions {
            send_client_cert: false,
            send_jwt: false,
            send_api_token: false,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;

    // ── SCENARIO 6: API token required, no token (failure) ───────────────
    info!("==> Testing server with API token auth - missing token (should fail)");
    let api_token_id_clone = api_token_id.clone();
    let ctx = start_test_server_with_patch(
        &test_config_path("auth_https.toml"),
        move |config| {
            config.http.api_token_id = Some(api_token_id_clone);
        },
        TestClientOptions {
            send_jwt: false,
            send_api_token: false,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;

    // ── SCENARIO 7: JWT required, no JWT sent (failure) ──────────────────
    info!("===> Testing server with JWT auth - but no JWT token sent (should fail)");
    let ctx = start_test_server(
        &test_config_path("auth_plain_jwt.toml"),
        TestClientOptions {
            send_jwt: false,
            send_api_token: false,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;

    // ── Bad API token but JWT auth succeeds ──────────────────────────────
    info!("==> Testing server with bad API token auth but JWT auth used at first");
    let ctx = start_test_server(
        &test_config_path("auth_plain_jwt.toml"),
        TestClientOptions {
            send_jwt: true,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── Bad API token but cert auth succeeds ─────────────────────────────
    info!("==> Testing server with bad API token auth but cert auth used at first");
    let ctx = start_test_server_with_patch(
        &test_config_path("auth_https_client_ca.toml"),
        |config| {
            config.http.api_token_id = Some("my_bad_token_id".to_owned());
        },
        TestClientOptions::default(),
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // ── Bad API token + good JWT + cert auth ─────────────────────────────
    info!(
        "==> Testing server with bad API token and good JWT token auth but still cert auth used \
         at first"
    );
    let ctx = start_test_server_with_patch(
        &test_config_path("auth_https_jwt.toml"),
        |config| {
            config.http.api_token_id = Some("my_bad_token_id".to_owned());
        },
        TestClientOptions {
            send_jwt: true,
            ..Default::default()
        },
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_tls_options() -> KmsCliResult<()> {
    init_test_logging();

    // TLS configuration tests
    //
    // Platform note:
    // - The KMS server side in tests always terminates TLS via OpenSSL
    //   (FIPS in default builds, legacy in non-fips), with provider/runtime
    //   settings injected by `test_kms_server` at test time (OPENSSL_CONF,
    //   OPENSSL_MODULES).
    // - The HTTP client stack used by the CLI tests varies by features and
    //   platform (native-tls bridging to the system's Security.framework on
    //   macOS, or rustls on non-fips builds). TLS 1.3 cipher selection and
    //   mixed-version negotiation semantics differ across these backends.
    //
    // As a result, some TLS expectations legitimately differ on macOS versus
    // Linux: we gate those with `#[cfg(target_os = "macos")]` below. These
    // differences stem from the client TLS backend behavior rather than the
    // server using an incorrect OpenSSL flavor.

    // Test cases: (description, server_cipher, client_cipher, use_client_ca, should_succeed)
    #[cfg(feature = "non-fips")]
    #[allow(clippy::type_complexity)]
    let test_cases: Vec<(&str, Option<&str>, Option<&str>, bool, bool)> = vec![
        (
            "Testing server and client with no option for TLS",
            None,
            None,
            false,
            true,
        ),
        (
            "Testing server and client with same cipher suite - old TLS 1.2 cipher that client \
             (rustls) doesn't recognize, so client falls back to safe defaults which succeed",
            Some("ECDHE-RSA-AES256-GCM-SHA384"),
            Some("ECDHE-RSA-AES256-GCM-SHA384"),
            false,
            true,
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2",
            Some("TLS_AES_256_GCM_SHA384"),
            None,
            false,
            {
                #[cfg(target_os = "macos")]
                {
                    false
                }
                #[cfg(not(target_os = "macos"))]
                {
                    true
                }
            },
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2 - manually set for client",
            Some("TLS_AES_256_GCM_SHA384"),
            Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            false,
            {
                #[cfg(target_os = "macos")]
                {
                    false
                }
                #[cfg(not(target_os = "macos"))]
                {
                    true
                }
            },
        ),
        (
            "Testing server with invalid cipher suite",
            Some("INVALID_CIPHER_SUITE"),
            None,
            false,
            false,
        ),
        (
            "Testing server and client with TLS 1.3 - same cipher suite",
            Some("TLS_AES_256_GCM_SHA384"),
            Some("TLS_AES_256_GCM_SHA384"),
            false,
            {
                #[cfg(target_os = "macos")]
                {
                    false
                }
                #[cfg(not(target_os = "macos"))]
                {
                    true
                }
            },
        ),
        (
            "Testing server with tls 1.3 client - tls 1.2/1.3 server",
            None,
            Some("TLS_AES_256_GCM_SHA384"),
            false,
            true,
        ),
        (
            "Testing with client that owns a valid certificate issued from a known CA",
            None,
            None,
            true,
            true,
        ),
    ];

    #[cfg(not(feature = "non-fips"))]
    #[allow(clippy::type_complexity)]
    let test_cases: Vec<(&str, Option<&str>, Option<&str>, bool, bool)> = vec![
        (
            "Testing server and client with no option for TLS",
            None,
            None,
            false,
            true,
        ),
        (
            "Testing server and client with same cipher suite - old TLS 1.2 cipher that client \
             (native-tls) uses, should succeed",
            Some("ECDHE-RSA-AES256-GCM-SHA384"),
            Some("ECDHE-RSA-AES256-GCM-SHA384"),
            false,
            true,
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2",
            Some("TLS_AES_256_GCM_SHA384"),
            None,
            false,
            {
                #[cfg(target_os = "macos")]
                {
                    false
                }
                #[cfg(not(target_os = "macos"))]
                {
                    true
                }
            },
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2 - manually set for client",
            Some("TLS_AES_256_GCM_SHA384"),
            Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            false,
            {
                #[cfg(target_os = "macos")]
                {
                    false
                }
                #[cfg(not(target_os = "macos"))]
                {
                    true
                }
            },
        ),
        (
            "Testing server with invalid cipher suite",
            Some("INVALID_CIPHER_SUITE"),
            None,
            false,
            false,
        ),
        (
            "Testing server and client with TLS 1.3 - same cipher suite",
            Some("TLS_AES_256_GCM_SHA384"),
            Some("TLS_AES_256_GCM_SHA384"),
            false,
            {
                #[cfg(target_os = "macos")]
                {
                    false
                }
                #[cfg(not(target_os = "macos"))]
                {
                    true
                }
            },
        ),
        (
            "Testing server with tls 1.3 client - tls 1.2/1.3 server",
            None,
            Some("TLS_AES_256_GCM_SHA384"),
            false,
            true,
        ),
        (
            "Testing with client that owns a valid certificate issued from a known CA",
            None,
            None,
            true,
            true,
        ),
    ];

    for (description, server_cipher, client_cipher, use_client_ca, should_succeed) in test_cases {
        info!("==> {description}");
        info!(
            "[test_tls_options] server_cipher={server_cipher:?} client_cipher={client_cipher:?} \
             expect_success={should_succeed}"
        );

        let config_path = if use_client_ca {
            test_config_path("auth_https_client_ca.toml")
        } else {
            test_config_path("auth_https.toml")
        };

        let server_cipher_owned = server_cipher.map(str::to_owned);
        let client_opts = TestClientOptions {
            http: HttpClientConfig {
                cipher_suites: client_cipher.map(str::to_owned),
                ..Default::default()
            },
            ..Default::default()
        };

        let result = start_test_server_with_patch(
            &config_path,
            move |config| {
                config.tls.tls_cipher_suites = server_cipher_owned;
            },
            client_opts,
        )
        .await;

        if should_succeed {
            let ctx = result?;
            ListOwnedObjects.run(ctx.get_owner_client()).await?;
            ctx.stop_server().await?;
        } else {
            if result.is_ok() {
                error!("It should fail for test: {description}");
            }
            result.unwrap_err();
        }
    }

    Ok(())
}
