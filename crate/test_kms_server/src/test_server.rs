use std::{
    env,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

use actix_server::ServerHandle;
use cosmian_kms_client::{
    KmsClient, KmsClientConfig, KmsClientError,
    cosmian_kmip::{KmipResultHelper, time_normalize},
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, GetAttributes},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
    kms_client_bail, kms_client_error,
};
use cosmian_kms_server::{
    config::{
        ClapConfig, GoogleCseConfig, HsmConfig, HttpConfig, MainDBConfig, ServerParams,
        SocketServerConfig, WorkspaceConfig,
    },
    start_kms_server::start_kms_server,
};
use cosmian_logger::{error, info, trace, warn};
use tokio::sync::OnceCell;

use crate::test_jwt::get_multiple_jwt_config;

/// Test servers are started once per test-process to avoid "Address already in use" errors
/// when many tests run concurrently.
pub(crate) static ONCE: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_AUTH: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_NON_REVOCABLE_KEY: OnceCell<TestsContext> =
    OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_HSM: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_KEK: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_PRIVILEGED_USERS: OnceCell<TestsContext> = OnceCell::const_new();

const DEFAULT_KMS_SERVER_PORT: u16 = 9998;

fn resolve_test_port(preferred_port: u16) -> Result<u16, KmsClientError> {
    if TcpListener::bind(("127.0.0.1", preferred_port)).is_ok() {
        return Ok(preferred_port);
    }

    let fallback = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| {
        KmsClientError::UnexpectedError(format!(
            "failed to allocate a fallback localhost port for test KMS server: {error}"
        ))
    })?;
    let port = fallback
        .local_addr()
        .map_err(|error| {
            KmsClientError::UnexpectedError(format!(
                "failed to read fallback localhost port for test KMS server: {error}"
            ))
        })?
        .port();
    info!(
        "Preferred test KMS port {preferred_port} is already in use; falling back to port {port}"
    );
    Ok(port)
}

#[inline]
fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Returns `<workspace-root>/test_data`.
fn test_data_dir() -> PathBuf {
    root_dir().join("../../test_data")
}

// ─── Config-file loaders ─────────────────────────────────────────────

/// Load a [`ClapConfig`] from `test_data/configs/server/<name>.toml`.
///
/// Relative TLS cert paths are resolved to absolute paths using the workspace
/// root, so the config works regardless of the test process CWD.
pub fn load_server_config(name: &str) -> Result<ClapConfig, KmsClientError> {
    let config_path = test_data_dir()
        .join("configs/server")
        .join(format!("{name}.toml"));
    let raw = std::fs::read_to_string(&config_path).map_err(|e| {
        KmsClientError::Default(format!(
            "Cannot read server config {}: {e}",
            config_path.display()
        ))
    })?;
    let mut config: ClapConfig = toml::from_str(&raw).map_err(|e| {
        KmsClientError::Default(format!(
            "Cannot parse server config {}: {e}",
            config_path.display()
        ))
    })?;
    // Resolve relative TLS paths to absolute (workspace root = test_data_dir()/..).
    let workspace_root = test_data_dir().join("..");
    let resolve = |p: PathBuf| -> PathBuf {
        if p.is_relative() {
            workspace_root.join(p)
        } else {
            p
        }
    };
    if let Some(f) = config.tls.tls_cert_file.take() {
        config.tls.tls_cert_file = Some(resolve(f));
    }
    if let Some(k) = config.tls.tls_key_file.take() {
        config.tls.tls_key_file = Some(resolve(k));
    }
    if let Some(c) = config.tls.clients_ca_cert_file.take() {
        config.tls.clients_ca_cert_file = Some(resolve(c));
    }
    Ok(config)
}

/// Load a [`KmsClientConfig`] from `test_data/configs/client/<name>.toml`.
///
/// Relative cert paths are resolved to absolute paths using the workspace root.
/// The port in the config file is used as-is; call [`with_server_port`] when
/// the server's port differs from the port baked into the config file.
pub fn load_client_config(name: &str) -> Result<KmsClientConfig, KmsClientError> {
    let config_path = test_data_dir()
        .join("configs/client")
        .join(format!("{name}.toml"));
    let raw = std::fs::read_to_string(&config_path).map_err(|e| {
        KmsClientError::Default(format!(
            "Cannot read client config {}: {e}",
            config_path.display()
        ))
    })?;
    let mut config: KmsClientConfig = toml::from_str(&raw).map_err(|e| {
        KmsClientError::Default(format!(
            "Cannot parse client config {}: {e}",
            config_path.display()
        ))
    })?;
    // Resolve relative cert paths (stored as String) to absolute paths.
    let workspace_root = test_data_dir().join("..");
    let resolve_str = |s: String| -> String {
        let p = PathBuf::from(&s);
        if p.is_relative() {
            workspace_root.join(p).to_string_lossy().into_owned()
        } else {
            s
        }
    };
    if let Some(cert) = config.http_config.ssl_client_pem_cert_path.take() {
        config.http_config.ssl_client_pem_cert_path = Some(resolve_str(cert));
    }
    if let Some(key) = config.http_config.ssl_client_pem_key_path.take() {
        config.http_config.ssl_client_pem_key_path = Some(resolve_str(key));
    }
    Ok(config)
}

/// Override the server-URL port in a loaded [`KmsClientConfig`].
///
/// Use this when a test connects to a server whose port differs from the port
/// baked into the client TOML config — for example, dynamic-port TLS tests or
/// cross-server failure scenarios.
#[must_use]
pub fn with_server_port(mut config: KmsClientConfig, port: u16) -> KmsClientConfig {
    if let Some(colon_pos) = config.http_config.server_url.rfind(':') {
        let after = &config.http_config.server_url[colon_pos + 1..];
        if after.bytes().all(|b| b.is_ascii_digit()) {
            let base = config.http_config.server_url[..colon_pos].to_owned();
            config.http_config.server_url = format!("{base}:{port}");
        }
    }
    config
}

/// Return the name of the TOML server config that matches the `KMS_TEST_DB` env var.
///
/// Defaults to `"test_default"` (`SQLite`) when the variable is absent or unrecognised.
fn default_server_config_name() -> &'static str {
    match env::var_os("KMS_TEST_DB")
        .as_deref()
        .and_then(|v| v.to_str())
    {
        Some("postgresql") => "test_postgres",
        Some("mysql") => "test_mysql",
        #[cfg(feature = "non-fips")]
        Some("redis-findex") => "test_redis_findex",
        _ => "test_default",
    }
}

/// Start a test KMS server in a thread with the default options:
/// No TLS, no certificate authentication
/// # Panics
/// - if the server fails to start
pub async fn start_test_kms_server_with_config(config: ClapConfig) -> &'static TestsContext {
    trace!("Starting test server with config : {:#?}", config);
    ONCE.get_or_try_init(|| async move {
        let server_params = ServerParams::try_from(config).context(
            "Failed to create ServerParams from ClapConfig in start_default_test_kms_server",
        )?;
        start_from_server_params(server_params).await
    })
    .await
    .unwrap_or_else(|e| {
        error!("failed to start default test server: {e}");
        std::process::abort();
    })
}

/// Start the default test KMS server (plain HTTP, port 9998, no authentication).
/// Configuration is loaded from `test_data/configs/server/<db-specific>.toml`.
/// The config name is resolved via `KMS_TEST_DB` env var (defaults to `SQLite`).
/// If the `KMS_USE_KEK` environment variable is set, a KEK-protected server is
/// started instead using `test_kek_fips` / `test_kek_non_fips`.
///
/// # Panics
/// Panics (via `process::abort`) if the server fails to start.
#[allow(clippy::unwrap_used)]
pub async fn start_default_test_kms_server() -> &'static TestsContext {
    trace!("Starting default test server");
    ONCE.get_or_try_init(|| async move {
        let use_kek = env::var_os("KMS_USE_KEK");
        let port = resolve_test_port(DEFAULT_KMS_SERVER_PORT)?;
        match use_kek {
            Some(_use_kek) => {
                let server_params = create_server_params_with_kek(port).await.unwrap();
                start_from_server_params(server_params).await
            }
            None => {
                start_test_server_with_options(
                    get_db_config(port, None),
                    port,
                    AuthenticationOptions::new(),
                    None,
                    None,
                )
                .await
            }
        }
    })
    .await
    .unwrap_or_else(|e| {
        error!("failed to start default test server: {e}");
        std::process::abort();
    })
}

/// Start the mutual-TLS test server (port 9999, no JWT).
/// Loads `test_cert_auth.toml` (PEM, works in both FIPS and non-FIPS mode).
pub async fn start_default_test_kms_server_with_cert_auth() -> &'static TestsContext {
    trace!("Starting test server with cert auth");
    ONCE_SERVER_WITH_AUTH
        .get_or_try_init(|| async move {
            let port = resolve_test_port(DEFAULT_KMS_SERVER_PORT + 1)?;
            let db_config = get_db_config(port, None);

            let server_params = build_server_params_full(BuildServerParamsOptions {
                db_config,
                port,
                tls: TlsMode::HttpsWithClientCa,
                jwt: JwtAuth::Disabled,
                ..Default::default()
            })
            .map_err(|e| {
                KmsClientError::Default(format!(
                    "Failed to build ServerParams from cert-auth config: {e}"
                ))
            })?;
            start_from_server_params(server_params).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with cert auth: {e}");
            std::process::abort();
        })
}

/// Start the non-revocable key test server (plain HTTP, port 10000).
/// Configuration is loaded from `test_data/configs/server/test_non_revocable.toml`.
/// The `non_revocable_key_id` list is injected at runtime after loading the config.
pub async fn start_default_test_kms_server_with_non_revocable_key_ids(
    non_revocable_key_id: Option<Vec<String>>,
) -> &'static TestsContext {
    trace!("Starting test server with non-revocable key ids");
    ONCE_SERVER_WITH_NON_REVOCABLE_KEY
        .get_or_try_init(|| async move {
            let port = resolve_test_port(DEFAULT_KMS_SERVER_PORT + 2)?;
            start_test_server_with_options(
                get_db_config(port, None),
                port,
                AuthenticationOptions::new(),
                non_revocable_key_id,
                None,
            )
            .await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with non-revocable key ids: {e}");
            std::process::abort();
        })
}

/// Start the Utimaco HSM test server (plain HTTP, port 10001).
/// Configuration is loaded from `test_data/configs/server/test_hsm.toml`.
pub async fn start_default_test_kms_server_with_utimaco_hsm() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM");
    ONCE_SERVER_WITH_HSM
        .get_or_try_init(|| async move {
            let port = resolve_test_port(DEFAULT_KMS_SERVER_PORT + 3)?;
            let db_config = get_db_config(port, None);

            let server_params = build_server_params_full(BuildServerParamsOptions {
                db_config,
                port,
                tls: TlsMode::PlainHttp,
                jwt: JwtAuth::Disabled,
                hsm: Some(HsmConfig {
                    hsm_model: "utimaco".to_owned(),
                    hsm_admin: vec!["tech@cosmian.com".to_owned()],
                    hsm_slot: vec![0],
                    hsm_password: vec!["12345678".to_owned()],
                }),
                ..Default::default()
            })
            .map_err(|e| {
                KmsClientError::Default(format!("failed initializing the server config (HSM): {e}"))
            })?;
            start_from_server_params(server_params).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with utimaco hsm: {e}");
            std::process::abort();
        })
}

// Create a KEK in the HSM before running server with `key_encryption_key` arg
async fn create_kek_in_db() -> Result<(PathBuf, String), KmsClientError> {
    let port: u16 = 20000;
    let workspace_dir = std::env::temp_dir().join(format!("kms_test_workspace_{port}"));
    let kek_id = "hsm::0::kek";

    if let Err(e) = std::fs::create_dir_all(&workspace_dir) {
        warn!("Could not create kek workspace dir: {e}");
    }

    let config = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            clear_database: true,
            sqlite_path: workspace_dir.clone(),
            ..MainDBConfig::default()
        },
        workspace: WorkspaceConfig {
            root_data_path: workspace_dir.clone(),
            tmp_path: PathBuf::from("/tmp"),
        },
        http: HttpConfig {
            port,
            ..HttpConfig::default()
        },
        socket_server: SocketServerConfig {
            socket_server_start: false,
            ..SocketServerConfig::default()
        },
        idp_auth: get_multiple_jwt_config(),
        hsm: HsmConfig {
            hsm_model: "utimaco".to_owned(),
            hsm_admin: "tech@cosmian.com".to_owned(),
            hsm_slot: vec![0],
            hsm_password: vec!["12345678".to_owned()],
        },
        kms_public_url: Some(format!("http://localhost:{port}/google_cse")),
        google_cse_config: GoogleCseConfig {
            google_cse_enable: true,
            google_cse_disable_tokens_validation: false,
            google_cse_incoming_url_whitelist: Some(vec!["https://cse.cosmian.com".to_owned()]),
            google_cse_migration_key: None,
        },
        default_username: "tech@cosmian.com".to_owned(),
        ..ClapConfig::default()
    };

    let owner_client_config =
        with_server_port(load_client_config("test_auth_plain_jwt_owner")?, port);
    let ctx = start_temp_test_kms_server(config, owner_client_config).await?;

    // Create the KEK in the HSM
    // Fast path: if the key already exists and is active, we're done.

    let get_attr_request = GetAttributes {
        unique_identifier: Some(UniqueIdentifier::TextString(kek_id.to_owned())),
        attribute_reference: None,
    };
    let resp = ctx
        .get_owner_client()
        .get_attributes(get_attr_request)
        .await;

    if resp.is_err() {
        // Create a request to generate a new symmetric key with activation_date set to now
        // so it will be immediately active
        let create_request = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt
                        | CryptographicUsageMask::Decrypt
                        | CryptographicUsageMask::WrapKey
                        | CryptographicUsageMask::UnwrapKey,
                ),
                object_type: Some(ObjectType::SymmetricKey),
                unique_identifier: Some(UniqueIdentifier::TextString(kek_id.to_owned())),
                activation_date: Some(time_normalize()?),
                ..Default::default()
            },
            protection_storage_masks: None,
        };

        let _response = ctx.get_owner_client().create(create_request).await?;
    }

    // No grant access is required on external keys (e.g., when using HSM crypto oracles)

    ctx.stop_server().await?;

    Ok((workspace_dir, kek_id.to_owned()))
}

async fn create_server_params_with_kek(port: u16) -> Result<ServerParams, KmsClientError> {
    let (workspace_dir, kek_id) = create_kek_in_db().await?;
    trace!(
        "Key encryption key created: {kek_id} in workspace {}",
        workspace_dir.display()
    );

    assert!(
        workspace_dir.exists() && !kek_id.is_empty(),
        "workspace_dir must exist and kek_id must be non-empty"
    );

    let db_config = get_db_config(port, Some(&workspace_dir));

    let reuse_db_config = MainDBConfig {
        clear_database: false,
        ..db_config
    };
    let server_params = build_server_params_full(BuildServerParamsOptions {
        workspace_dir: Some(workspace_dir),
        db_config: reuse_db_config,
        port,
        tls: TlsMode::HttpsWithClientCa,
        jwt: JwtAuth::Enabled,
        hsm: Some(HsmConfig {
            hsm_model: "utimaco".to_owned(),
            hsm_admin: vec!["owner.client@acme.com".to_owned()],
            hsm_slot: vec![0],
            hsm_password: vec!["12345678".to_owned()],
        }),
        key_encryption_key: Some(kek_id),
        ..Default::default()
    })
    .map_err(|e| {
        KmsClientError::Default(format!("failed initializing the server config (HSM): {e}"))
    })?;
    Ok(server_params)
}

/// With Utimaco HSM
///
/// # Panics
/// - if the `workspace_dir` does not exist
/// - if the `kek_id` is empty
#[allow(clippy::unwrap_used)]
pub async fn start_default_test_kms_server_with_utimaco_and_kek() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM and KEK");
    // Build ServerParams with HSM fields directly and start from them
    ONCE_SERVER_WITH_KEK
        .get_or_try_init(|| async move {
            let port = resolve_test_port(DEFAULT_KMS_SERVER_PORT + 4)?;
            let server_params = create_server_params_with_kek(port).await.unwrap();

            start_from_server_params(server_params).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with utimaco hsm: {e}");
            std::process::abort();
        })
}

/// Start the privileged-users test server (TLS+JWT, port 10003).
/// Loads `test_privileged_users.toml` (PEM, works in both FIPS and non-FIPS mode).
/// The `privileged_users` list is injected at runtime after loading the config.
pub async fn start_default_test_kms_server_with_privileged_users(
    privileged_users: Vec<String>,
) -> &'static TestsContext {
    trace!("Starting test server with privileged users");
    ONCE_SERVER_WITH_PRIVILEGED_USERS
        .get_or_try_init(|| async move {
            let port = resolve_test_port(DEFAULT_KMS_SERVER_PORT + 5)?;
            let db_config = get_db_config(port, None);

            // Use Auth0 config for IdP-enabled server
            let server_params = build_server_params_full(BuildServerParamsOptions {
                db_config,
                port,
                tls: TlsMode::HttpsWithClientCa,
                jwt: JwtAuth::Enabled,
                privileged_users: Some(privileged_users),
                ..Default::default()
            })
            .map_err(|e| {
                KmsClientError::Default(format!(
                    "Failed to build ServerParams from privileged-users config: {e}"
                ))
            })?;
            start_from_server_params(server_params).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with privileged users: {e}");
            std::process::abort();
        })
}

#[derive(Debug)]
pub struct TestsContext {
    pub server_port: u16,
    pub owner_client_config: KmsClientConfig,
    pub user_client_config: KmsClientConfig,
    pub server_handle: ServerHandle,
    pub thread_handle: JoinHandle<Result<(), KmsClientError>>,
}

impl TestsContext {
    #[must_use]
    pub fn get_owner_client(&self) -> KmsClient {
        KmsClient::new_with_config(self.owner_client_config.clone()).unwrap_or_else(|e| {
            error!("Can't create a KMS owner client: {e}");
            std::process::abort();
        })
    }

    #[must_use]
    pub fn get_user_client(&self) -> KmsClient {
        KmsClient::new_with_config(self.user_client_config.clone()).unwrap_or_else(|e| {
            error!("Can't create a KMS user client: {e}");
            std::process::abort();
        })
    }

    pub async fn stop_server(self) -> Result<(), KmsClientError> {
        self.server_handle.stop(false).await;
        self.thread_handle
            .join()
            .map_err(|_e| kms_client_error!("failed joining the stop thread"))?
    }
}

// ─── One-shot (non-singleton) server launcher ────────────────────────────────

/// Start a one-shot test KMS server from a [`ClapConfig`].
///
/// Unlike the singleton launchers (`start_default_test_kms_server` etc.), this
/// function starts a fresh server every call — suitable for auth tests that
/// need many servers with different configurations and dynamic ports.
pub async fn start_temp_test_kms_server(
    config: ClapConfig,
    owner_client_config: KmsClientConfig,
) -> Result<TestsContext, KmsClientError> {
    let server_params = ServerParams::try_from(config).map_err(|e| {
        KmsClientError::Default(format!(
            "Failed to build ServerParams in start_temp_test_kms_server: {e}"
        ))
    })?;

    info!(" -- Test KMS server configuration: {:#?}", server_params);
    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    let user_client_config = owner_client_config.clone();
    let server_port = server_params.http_port;

    let (server_handle, thread_handle) = start_test_kms_server(server_params)?;

    wait_for_server_to_start(&owner_client_config)
        .await
        .map_err(|e| {
            error!("Error waiting for server to start: {e:?}");
            KmsClientError::UnexpectedError(e.to_string())
        })?;

    Ok(TestsContext {
        server_port,
        owner_client_config,
        user_client_config,
        server_handle,
        thread_handle,
    })
}

/// Common finalization once the server parameters are fully constructed
fn start_test_kms_server(
    server_params: ServerParams,
) -> Result<(ServerHandle, JoinHandle<Result<(), KmsClientError>>), KmsClientError> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the KMS Server in the future
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                error!("Error building tokio runtime: {e:?}");
                KmsClientError::UnexpectedError(e.to_string())
            })?;

        runtime
            .block_on(start_kms_server(Arc::new(server_params), Some(tx)))
            .map_err(|e| {
                error!("Error starting the KMS server: {e:?}");
                KmsClientError::UnexpectedError(e.to_string())
            })
    });
    trace!("Waiting for test KMS server to start...");
    let server_handle = rx.recv_timeout(Duration::from_secs(25)).map_err(|e| {
        KmsClientError::UnexpectedError(format!("Error getting test KMS server handle: {e}"))
    })?;
    trace!("... got handle ...");
    Ok((server_handle, thread_handle))
}

/// Wait for the server to start by reading the version
async fn wait_for_server_to_start(
    kms_client_config: &KmsClientConfig,
) -> Result<(), KmsClientError> {
    // Depending on the running environment, the server could take a bit of time to start
    // We try to query it with a dummy request until we are sure it is started.
    let kms_client = KmsClient::new_with_config(kms_client_config.clone())?;
    let mut retry = true;
    let mut timeout = 2;
    let mut waiting = 1;
    while retry {
        info!("...checking if the server is up...");
        let result = kms_client.version().await;
        if let Err(KmsClientError::Unauthorized(e)) = result {
            // The server is up with authentication problems
            warn!("Server is up but with authentication problems! Unauthorized: {e}");
            break;
        }
        if result.is_err() {
            timeout -= 1;
            retry = timeout >= 0;
            if retry {
                info!("The server is not up yet, retrying in {waiting}s... ({result:?}) ",);
                tokio::time::sleep(Duration::from_secs(waiting)).await;
                waiting *= 2;
            } else {
                info!("The server is still not up, stop trying.");
                kms_client_bail!("Can't start the kms server to run tests: {result:?}");
            }
        } else {
            info!("UP!");
            retry = false;
        }
    }
    Ok(())
}

/// Derive the client-config names (owner + user) from the server parameters.
///
/// Returns `(owner_name, user_name)` for use with [`load_client_config`].
fn client_config_names(server_params: &ServerParams) -> (&'static str, &'static str) {
    let use_tls = server_params.tls_params.is_some();
    let requires_client_cert = server_params
        .tls_params
        .as_ref()
        .and_then(|tls| tls.clients_ca_cert_pem.as_ref())
        .is_some();
    let has_idp = server_params.identity_provider_configurations.is_some();
    match (use_tls, requires_client_cert, has_idp) {
        (false, _, false) => ("test_auth_plain_owner", "test_auth_plain_user"),
        (false, _, true) => ("test_auth_plain_jwt_owner", "test_auth_plain_jwt_user"),
        (true, false, false) => ("test_auth_https_owner", "test_auth_https_user"),
        (true, false, true) => ("test_auth_https_jwt_owner", "test_auth_https_jwt_user"),
        (true, true, false) => (
            "test_auth_https_client_ca_owner",
            "test_auth_https_client_ca_user",
        ),
        (true, true, true) => (
            "test_auth_https_jwt_cert_owner",
            "test_auth_https_jwt_cert_user",
        ),
    }
}

/// Common finalization once the server parameters are fully constructed.
///
/// Derives owner and user client configs from the server parameters via
/// [`client_config_names`], then waits for the server to be ready.
async fn start_from_server_params(
    server_params: ServerParams,
) -> Result<TestsContext, KmsClientError> {
    let port = server_params.http_port;
    let (owner_name, user_name) = client_config_names(&server_params);
    let owner_client_config = with_server_port(load_client_config(owner_name)?, port);
    let user_client_config = with_server_port(load_client_config(user_name)?, port);

    info!(" -- Test KMS server configuration: {:#?}", server_params);
    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    let server_port = server_params.http_port;
    let (server_handle, thread_handle) = start_test_kms_server(server_params)?;

    wait_for_server_to_start(&owner_client_config)
        .await
        .map_err(|e| {
            error!("Error waiting for server to start: {e:?}");
            KmsClientError::UnexpectedError(e.to_string())
        })?;

    Ok(TestsContext {
        server_port,
        owner_client_config,
        user_client_config,
        server_handle,
        thread_handle,
    })
}

#[cfg(test)]
#[cfg(feature = "non-fips")]
#[allow(clippy::unwrap_in_result)]
#[tokio::test]
async fn test_start_server() -> Result<(), KmsClientError> {
    let mut config = load_server_config("test_default")?;
    config.http.port = 9990;
    let owner_client_config = with_server_port(load_client_config("test_auth_plain_owner")?, 9990);
    let context = start_temp_test_kms_server(config, owner_client_config).await?;
    context.stop_server().await
}
