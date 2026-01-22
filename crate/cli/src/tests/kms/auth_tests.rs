use std::path::PathBuf;

use base64::Engine;
use cosmian_kms_client::{
    read_object_from_json_ttlv_file, reexport::cosmian_http_client::HttpClientConfig,
};
use cosmian_logger::{error, info, trace};
use tempfile::TempDir;
#[cfg(not(target_os = "windows"))]
use test_kms_server::build_server_params;
use test_kms_server::{
    ApiTokenPolicy, AuthenticationOptions, ClientAuthOptions, ClientCertPolicy, JwtPolicy,
    MainDBConfig, ServerJwtAuth as JwtAuth, ServerTlsMode as TlsMode, TestsContext,
    build_server_params_full, init_test_logging,
    reexport::cosmian_kms_server::config::ServerParams, start_test_server_with_options,
};
use tokio::fs;

use crate::{
    actions::kms::{
        access::ListOwnedObjects, shared::ExportSecretDataOrKeyAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

// let us not make other test cases fail
const DEFAULT_KMS_SERVER_PORT: u16 = 9998;
// Base port for this test's HTTP scenarios; use a high, disjoint range
// to avoid collisions with other test suites and ONCE servers.
const PORT: u16 = 12000;
// Use a far, disjoint range for TLS tests to avoid port collisions when tests run in parallel
const TLS_PORT: u16 = 13000;

// Use a fixed workspace directory so all scenarios share the same DB
fn shared_workspace_dir() -> PathBuf {
    PathBuf::from("./cosmian-kms")
}

fn make_server_params(
    db_config: MainDBConfig,
    port: u16,
    tls: TlsMode,
    jwt: JwtAuth,
    server_tls_cipher_suites: Option<String>,
    api_token_id: Option<String>,
) -> KmsCliResult<ServerParams> {
    Ok(build_server_params_full(
        test_kms_server::BuildServerParamsOptions {
            workspace_dir: Some(shared_workspace_dir()),
            db_config,
            port,
            tls,
            jwt,
            server_tls_cipher_suites,
            api_token_id,
            ..Default::default()
        },
    )?)
}

fn client_http_with_cert() -> HttpClientConfig {
    #[cfg(feature = "non-fips")]
    {
        HttpClientConfig {
            ssl_client_pkcs12_path: Some(
                "../../test_data/certificates/client_server/owner/owner.client.acme.com.p12"
                    .to_string(),
            ),
            ssl_client_pkcs12_password: Some("password".to_string()),
            ..Default::default()
        }
    }
    #[cfg(not(feature = "non-fips"))]
    {
        HttpClientConfig {
            ssl_client_pem_cert_path: Some(
                "../../test_data/certificates/client_server/owner/owner.client.acme.com.crt"
                    .to_string(),
            ),
            ssl_client_pem_key_path: Some(
                "../../test_data/certificates/client_server/owner/owner.client.acme.com.key"
                    .to_string(),
            ),
            ..Default::default()
        }
    }
}

fn client_http_with_token(token: Option<String>) -> HttpClientConfig {
    HttpClientConfig {
        access_token: token,
        ..Default::default()
    }
}

fn client_http_with_cert_and_token(token: String) -> HttpClientConfig {
    #[cfg(feature = "non-fips")]
    {
        HttpClientConfig {
            ssl_client_pkcs12_path: Some(
                "../../test_data/certificates/client_server/owner/owner.client.acme.com.p12"
                    .to_string(),
            ),
            ssl_client_pkcs12_password: Some("password".to_string()),
            access_token: Some(token),
            ..Default::default()
        }
    }
    #[cfg(not(feature = "non-fips"))]
    {
        HttpClientConfig {
            ssl_client_pem_cert_path: Some(
                "../../test_data/certificates/client_server/owner/owner.client.acme.com.crt"
                    .to_string(),
            ),
            ssl_client_pem_key_path: Some(
                "../../test_data/certificates/client_server/owner/owner.client.acme.com.key"
                    .to_string(),
            ),
            access_token: Some(token),
            ..Default::default()
        }
    }
}

#[inline]
fn auth_opts(http: HttpClientConfig, sp: ServerParams) -> AuthenticationOptions {
    AuthenticationOptions {
        client: ClientAuthOptions {
            http,
            // Use defaults for policies
            ..Default::default()
        },
        server_params: Some(sp),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ScenarioOutcome {
    ShouldSucceed,
    ShouldFail,
}

async fn run_auth_scenario(
    description: &str,
    db_config: &MainDBConfig,
    port: u16,
    auth: AuthenticationOptions,
    expect: ScenarioOutcome,
) -> KmsCliResult<()> {
    info!("==> {description}");
    let ctx = start_test_server_with_options(db_config.clone(), port, auth, None, None).await?;
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
    // Ensure logging is initialized once across the whole test process
    init_test_logging();

    // delete the temp db dir holding `sqlite-data-auth-tests/kms.db`
    let _e = fs::remove_dir_all(PathBuf::from("./cosmian-kms")).await;

    // Use a fresh TCP port for each server start to avoid TIME_WAIT port reuse
    // and potential races when starting/stopping servers rapidly.
    let mut port_counter = PORT;
    let mut next_port = || {
        port_counter += 1;
        port_counter
    };

    // plaintext no auth
    info!("==> Testing server with no auth");
    let p0 = next_port();
    let ctx = start_test_server_with_options(
        MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
            clear_database: true,
            ..MainDBConfig::default()
        },
        p0,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                MainDBConfig {
                    database_type: Some("sqlite".to_owned()),
                    sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
                    clear_database: false,
                    ..MainDBConfig::default()
                },
                p0,
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

    ListOwnedObjects.run(ctx.get_owner_client()).await?;

    // Create an API auth token with admin rights for later
    let (api_token_id, api_token) = create_api_token(&ctx).await?;
    ctx.stop_server().await?;

    let default_db_config = MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
        clear_database: false,
        ..MainDBConfig::default()
    };

    // plaintext JWT token auth
    let p1 = next_port();
    run_auth_scenario(
        "Testing server with JWT token over HTTP",
        &default_db_config,
        p1,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p1,
                TlsMode::PlainHttp,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // tls token auth
    let p2 = next_port();
    run_auth_scenario(
        "Testing server with JWT token auth over HTTPS",
        &default_db_config,
        p2,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p2,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // Client Certificate authentication
    info!("==> Testing server with Client Certificate auth");
    let p3 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        p3,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: client_http_with_cert(),
                // client cert auto-injection now happens unless policy suppresses it
                client_cert: ClientCertPolicy::Send,
                jwt: JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: {
                let sp1 = make_server_params(
                    default_db_config.clone(),
                    p3,
                    TlsMode::HttpsWithClientCa,
                    JwtAuth::Disabled,
                    None,
                    None,
                )?;
                Some(sp1)
            },
        },
        None,
        None,
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // SCENARIO 1: Both Client Certificates and JWT authentication enabled, user presents JWT token only
    info!(
        "==> Testing server with both Client Certificates and JWT auth - User sends JWT token only"
    );
    let p4 = next_port();
    run_auth_scenario(
        "Testing server with both Client Certificates and JWT auth - User sends JWT token only",
        &default_db_config,
        p4,
        auth_opts(
            HttpClientConfig::default(),
            make_server_params(
                default_db_config.clone(),
                p4,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Enabled,
                None,
                None,
            )?,
        ),
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // SCENARIO 2: Both Client Certificates and API token authentication enabled, user presents API token only
    info!(
        "==> Testing server with both Client Certificates and API token auth -User sends API \
         token only"
    );
    let p5 = next_port();
    run_auth_scenario(
        "Testing server with both Client Certificates and API token auth -User sends API token \
         only",
        &default_db_config,
        p5,
        auth_opts(
            client_http_with_token(Some(api_token.clone())),
            make_server_params(
                default_db_config.clone(),
                p5,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                Some(api_token_id.clone()),
            )?,
        ),
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // SCENARIO 3: Both JWT and API token authentication enabled, user presents API token only
    info!("==> Testing server with both JWT and API token auth - User sends the API token only");
    let p6 = next_port();
    run_auth_scenario(
        "Testing server with both JWT and API token auth - User sends the API token only",
        &default_db_config,
        p6,
        auth_opts(
            client_http_with_token(Some(api_token.clone())),
            make_server_params(
                default_db_config.clone(),
                p6,
                TlsMode::HttpsNoClientCa,
                JwtAuth::Enabled,
                None,
                Some(api_token_id.clone()),
            )?,
        ),
        ScenarioOutcome::ShouldSucceed,
    )
    .await?;

    // SCENARIO 4: JWT authentication enabled, no token provided (failure case)
    info!("==> Testing server with JWT auth - User does not send the token (should fail)");
    let p7 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        p7,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p7,
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
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;
    let p8 = next_port();
    run_auth_scenario(
        "Testing server with JWT auth - User does not send the token (should fail)",
        &default_db_config,
        p8,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p8,
                TlsMode::PlainHttp,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        ScenarioOutcome::ShouldFail,
    )
    .await?;

    // SCENARIO 5: Client Certificate authentication enabled, no certificate provided (failure case)
    info!("==> Testing server with Client Certificate auth - missing certificate (should fail)");
    let p9 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        p9,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                client_cert: ClientCertPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p9,
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
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;
    let p10 = next_port();
    run_auth_scenario(
        "Testing server with Client Certificate auth - missing certificate (should fail)",
        &default_db_config,
        p10,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                client_cert: ClientCertPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p10,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                None,
            )?),
        },
        ScenarioOutcome::ShouldFail,
    )
    .await?;

    // SCENARIO 6: API token authentication enabled, no token provided (failure case)
    info!("==> Testing server with API token auth - missing token (should fail)");
    let p11 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        p11,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                api_token: ApiTokenPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p11,
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
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;
    let p12 = next_port();
    run_auth_scenario(
        "Testing server with API token auth - missing token (should fail)",
        &default_db_config,
        p12,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                api_token: ApiTokenPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p12,
                TlsMode::HttpsNoClientCa,
                JwtAuth::Disabled,
                None,
                Some(api_token_id.clone()),
            )?),
        },
        ScenarioOutcome::ShouldFail,
    )
    .await?;

    // SCENARIO 7: JWT authentication enabled, but no JWT token presented (failure case)
    info!("===> Testing server with JWT auth - but no JWT token sent (should fail)");
    let p13 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        p13,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p13,
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
    ListOwnedObjects
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();
    ctx.stop_server().await?;
    let p14 = next_port();
    run_auth_scenario(
        "Testing server with JWT auth - but no JWT token sent (should fail)",
        &default_db_config,
        p14,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::Suppress,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p14,
                TlsMode::PlainHttp,
                JwtAuth::Enabled,
                None,
                None,
            )?),
        },
        ScenarioOutcome::ShouldFail,
    )
    .await?;

    // Bad API token auth but JWT auth used at first
    info!("==> Testing server with bad API token auth but JWT auth used at first");
    let p15 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        p15,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(make_server_params(
                default_db_config.clone(),
                p15,
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
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // Bad API token auth, but cert auth used at first
    info!("==> Testing server with bad API token auth but cert auth used at first");
    let p16 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        p16,
        auth_opts(
            client_http_with_cert_and_token("my_bad_token".to_owned()),
            make_server_params(
                default_db_config.clone(),
                p16,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Disabled,
                None,
                Some("my_bad_token_id".to_owned()),
            )?,
        ),
        None,
        None,
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // Bad API token and good JWT token auth but still cert auth used at first
    info!(
        "==> Testing server with bad API token and good JWT token auth but still cert auth used \
         at first"
    );
    let p17 = next_port();
    let ctx = start_test_server_with_options(
        default_db_config,
        p17,
        auth_opts(
            client_http_with_cert_and_token("my_bad_token".to_owned()),
            make_server_params(
                MainDBConfig {
                    database_type: Some("sqlite".to_owned()),
                    sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
                    clear_database: false,
                    ..MainDBConfig::default()
                },
                p17,
                TlsMode::HttpsWithClientCa,
                JwtAuth::Enabled,
                None,
                Some("my_bad_token_id".to_owned()),
            )?,
        ),
        None,
        None,
    )
    .await?;
    ListOwnedObjects.run(ctx.get_owner_client()).await?;
    ctx.stop_server().await?;

    // delete the temp db dir
    let _e = fs::remove_dir_all(PathBuf::from("./cosmian-kms")).await;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_tls_options() -> KmsCliResult<()> {
    init_test_logging();

    let default_db_config = MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
        clear_database: true,
        ..MainDBConfig::default()
    };

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
    #[cfg(feature = "non-fips")]
    let test_cases = vec![
        (
            "Testing server and client with no option for TLS",
            auth_opts(
                HttpClientConfig::default(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT,
                    TlsMode::HttpsNoClientCa,
                    JwtAuth::Disabled,
                    None,
                    None,
                )?,
            ),
            true, // should succeed
        ),
        (
            "Testing server and client with same cipher suite - old TLS 1.2 cipher that client \
             (rustls) doesn't recognize, so client falls back to safe defaults which succeed",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 1,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()),
                        None,
                    )?,
                )
            },
            true, // should succeed due to fallback to defaults
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2",
            auth_opts(
                HttpClientConfig::default(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT + 2,
                    TlsMode::HttpsNoClientCa,
                    JwtAuth::Disabled,
                    Some("TLS_AES_256_GCM_SHA384".to_string()),
                    None,
                )?,
            ),
            #[cfg(target_os = "macos")]
            false, // macOS native-tls may refuse TLS1.2->TLS1.3 negotiation
            #[cfg(not(target_os = "macos"))]
            true, // Other platforms typically negotiate successfully
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2 - manually set for client",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 3,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        Some("TLS_AES_256_GCM_SHA384".to_string()),
                        None,
                    )?,
                )
            },
            // On macOS, native-tls can still enforce TLS 1.2 and fail
            #[cfg(target_os = "macos")]
            false,
            #[cfg(not(target_os = "macos"))]
            true,
        ),
        (
            "Testing server with invalid cipher suite",
            auth_opts(
                HttpClientConfig::default(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT + 4,
                    TlsMode::HttpsNoClientCa,
                    JwtAuth::Disabled,
                    Some("INVALID_CIPHER_SUITE".to_string()),
                    None,
                )?,
            ),
            false, // should fail
        ),
        (
            "Testing server and client with TLS 1.3 - same cipher suite",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 5,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        Some("TLS_AES_256_GCM_SHA384".to_string()),
                        None,
                    )?,
                )
            },
            #[cfg(target_os = "macos")]
            false, // macOS/OpenSSL may reject TLS1.3 ciphers via SSL_CTX_set_cipher_list
            #[cfg(not(target_os = "macos"))]
            true, // should succeed elsewhere
        ),
        (
            "Testing server with tls 1.3 client - tls 1.2/1.3 server",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 6,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        None,
                        None,
                    )?,
                )
            },
            true, // should succeed
        ),
        (
            "Testing with client that owns a valid certificate issued from a known CA",
            auth_opts(
                client_http_with_cert(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT + 7,
                    TlsMode::HttpsWithClientCa,
                    JwtAuth::Disabled,
                    None,
                    None,
                )?,
            ),
            true, // should succeed
        ),
    ];

    // In FIPS mode, skip tests that rely on certificates from different CA chains
    // that aren't part of the FIPS test certificate setup (another_p12, gmail_cse with HttpsWithClientCa)
    #[cfg(not(feature = "non-fips"))]
    let test_cases = vec![
        (
            "Testing server and client with no option for TLS",
            auth_opts(
                HttpClientConfig::default(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT,
                    TlsMode::HttpsNoClientCa,
                    JwtAuth::Disabled,
                    None,
                    None,
                )?,
            ),
            true, // should succeed
        ),
        (
            "Testing server and client with same cipher suite - old TLS 1.2 cipher that client \
             (native-tls) uses, should succeed",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 1,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()),
                        None,
                    )?,
                )
            },
            true, // should succeed
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2",
            auth_opts(
                HttpClientConfig::default(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT + 2,
                    TlsMode::HttpsNoClientCa,
                    JwtAuth::Disabled,
                    Some("TLS_AES_256_GCM_SHA384".to_string()),
                    None,
                )?,
            ),
            #[cfg(target_os = "macos")]
            false, // macOS native-tls may reject TLS1.2->TLS1.3
            #[cfg(not(target_os = "macos"))]
            true, // OpenSSL negotiation succeeds elsewhere
        ),
        (
            "Testing server in TLS 1.3 but client in TLS 1.2 - manually set for client",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 3,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        Some("TLS_AES_256_GCM_SHA384".to_string()),
                        None,
                    )?,
                )
            },
            #[cfg(target_os = "macos")]
            false,
            #[cfg(not(target_os = "macos"))]
            true, // OpenSSL negotiation is flexible
        ),
        (
            "Testing server with invalid cipher suite",
            auth_opts(
                HttpClientConfig::default(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT + 4,
                    TlsMode::HttpsNoClientCa,
                    JwtAuth::Disabled,
                    Some("INVALID_CIPHER_SUITE".to_string()),
                    None,
                )?,
            ),
            false, // should fail
        ),
        (
            "Testing server and client with TLS 1.3 - same cipher suite",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 5,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        Some("TLS_AES_256_GCM_SHA384".to_string()),
                        None,
                    )?,
                )
            },
            #[cfg(target_os = "macos")]
            false, // OpenSSL on macOS rejects TLS1.3 cipher via SSL_CTX_set_cipher_list
            #[cfg(not(target_os = "macos"))]
            true, // should succeed elsewhere
        ),
        (
            "Testing server with tls 1.3 client - tls 1.2/1.3 server",
            {
                let client_http = HttpClientConfig {
                    cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_string()),
                    ..Default::default()
                };
                auth_opts(
                    client_http,
                    build_server_params(
                        default_db_config.clone(),
                        TLS_PORT + 6,
                        TlsMode::HttpsNoClientCa,
                        JwtAuth::Disabled,
                        None,
                        None,
                    )?,
                )
            },
            true, // should succeed
        ),
        (
            "Testing with client that owns a valid certificate issued from a known CA",
            auth_opts(
                client_http_with_cert(),
                build_server_params(
                    default_db_config.clone(),
                    TLS_PORT + 7,
                    TlsMode::HttpsWithClientCa,
                    JwtAuth::Disabled,
                    None,
                    None,
                )?,
            ),
            true, // should succeed
        ),
    ];

    for (index, (description, auth_options, should_succeed)) in test_cases.into_iter().enumerate() {
        let port = TLS_PORT + u16::try_from(index)?;
        info!("==> {description}");
        info!(
            "[test_tls_options] case index={} expect_success={}",
            index, should_succeed
        );
        let result = start_test_server_with_options(
            default_db_config.clone(),
            port,
            auth_options,
            None,
            None,
        )
        .await;

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
