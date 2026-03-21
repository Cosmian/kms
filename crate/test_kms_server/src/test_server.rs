use std::{
    collections::hash_map::DefaultHasher,
    env,
    hash::{Hash, Hasher},
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

#[inline]
fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[inline]
fn workspace_root() -> PathBuf {
    root_dir().join("../..")
}

/// Returns `<workspace-root>/test_data`.
fn test_data_dir() -> PathBuf {
    root_dir().join("../../test_data")
}

const TEST_PORT_NAMESPACE_BASE: u16 = 20_000;

fn repo_test_namespace_slot() -> u16 {
    let workspace_root = workspace_root()
        .canonicalize()
        .unwrap_or_else(|_| workspace_root());
    let mut hasher = DefaultHasher::new();
    workspace_root.to_string_lossy().hash(&mut hasher);

    let max_slots = u16::MAX - TEST_PORT_NAMESPACE_BASE + 1;
    let hash_bytes = hasher.finish().to_le_bytes();
    let hash_prefix = u16::from_le_bytes([hash_bytes[0], hash_bytes[1]]);

    hash_prefix % max_slots
}

fn repo_test_namespace_suffix() -> String {
    format!("{:03x}", repo_test_namespace_slot())
}

fn namespace_test_path(path: &Path) -> PathBuf {
    if !path.is_absolute() {
        return path.to_path_buf();
    }

    let suffix = repo_test_namespace_suffix();
    if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
        path.with_file_name(format!("{name}_{suffix}"))
    } else {
        path.join(suffix)
    }
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

    config.db.sqlite_path = namespace_test_path(&config.db.sqlite_path);
    config.workspace.root_data_path = namespace_test_path(&config.workspace.root_data_path);

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

fn pick_free_port() -> Result<u16, KmsClientError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| {
        KmsClientError::Default(format!("Cannot allocate a free TCP port for tests: {e}"))
    })?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| KmsClientError::Default(format!("Cannot inspect free TCP port: {e}")))
}

fn replace_port_in_url(url: &str, new_port: u16) -> String {
    if let Some(scheme_idx) = url.find("://") {
        let authority_start = scheme_idx + 3;
        let path_start = url[authority_start..]
            .find('/')
            .map_or(url.len(), |idx| authority_start + idx);
        if let Some(colon_idx_rel) = url[authority_start..path_start].rfind(':') {
            let colon_idx = authority_start + colon_idx_rel;
            let after = &url[colon_idx + 1..path_start];
            if after.bytes().all(|b| b.is_ascii_digit()) {
                return format!("{}:{}{}", &url[..colon_idx], new_port, &url[path_start..]);
            }
        }
    }
    url.to_owned()
}

fn remap_test_server_ports_if_needed(
    server_params: &mut ServerParams,
) -> Result<bool, KmsClientError> {
    let original_http_port = server_params.http_port;
    let new_http_port = pick_free_port()?;
    let mut changed = new_http_port != original_http_port;
    if changed {
        info!(" -- Replacing test HTTP port {original_http_port} with free port {new_http_port}");
    }

    server_params.http_port = new_http_port;

    if let Some(url) = server_params.kms_public_url.as_mut() {
        *url = replace_port_in_url(url, new_http_port);
    }

    if let Some(url) = server_params.ms_dke_service_url.as_mut() {
        *url = replace_port_in_url(url, new_http_port);
    }

    if server_params.start_socket_server {
        let original_socket_port = server_params.socket_server_port;
        let new_socket_port = pick_free_port()?;
        if new_socket_port != original_socket_port {
            changed = true;
            info!(
                " -- Replacing test socket port {original_socket_port} with free port {new_socket_port}"
            );
        }
        server_params.socket_server_port = new_socket_port;
    }

    Ok(changed)
}

/// Return the name of the TOML server config that matches the `KMS_TEST_DB` env var.
///
/// Defaults to `"test/default"` (`SQLite`) when the variable is absent or unrecognised.
fn default_server_config_name() -> &'static str {
    match env::var_os("KMS_TEST_DB")
        .as_deref()
        .and_then(|v| v.to_str())
    {
        Some("postgresql") => "test/postgres",
        Some("mysql") => "test/mysql",
        #[cfg(feature = "non-fips")]
        Some("redis-findex") => "test/redis_findex",
        _ => "test/default",
    }
}

/// Override the `[db]` section of a loaded [`ClapConfig`] when the `KMS_TEST_DB`
/// environment variable is set to a non-SQLite backend.
///
/// This ensures that **all** test-server flavours (cert-auth, non-revocable, HSM,
/// privileged-users, …) honour `KMS_TEST_DB`, not just the default server.
fn apply_kms_test_db_override(config: &mut ClapConfig) {
    let db_type = match env::var_os("KMS_TEST_DB")
        .as_deref()
        .and_then(|v| v.to_str())
    {
        Some(v) => v.to_owned(),
        None => return,
    };
    match db_type.as_str() {
        "postgresql" => {
            let url = option_env!("KMS_POSTGRES_URL")
                .unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms")
                .to_owned();
            config.db.database_type = Some("postgresql".to_owned());
            config.db.database_url = Some(url);
            config.db.clear_database = false;
        }
        "mysql" => {
            let url = option_env!("KMS_MYSQL_URL")
                .unwrap_or("mysql://kms:kms@localhost:3306/kms")
                .to_owned();
            config.db.database_type = Some("mysql".to_owned());
            config.db.database_url = Some(url);
            config.db.clear_database = false;
        }
        #[cfg(feature = "non-fips")]
        "redis-findex" => {
            let url = env::var("REDIS_HOST").map_or_else(
                |_| "redis://localhost:6379".to_owned(),
                |host| format!("redis://{host}:6379"),
            );
            config.db.database_type = Some("redis-findex".to_owned());
            config.db.database_url = Some(url);
            config.db.clear_database = true;
            config.db.redis_master_password = Some("password".to_owned());
        }
        _ => {} // keep whatever the TOML file had (SQLite)
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
        start_from_server_params(server_params, None).await
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
/// started instead using `test/kek`-based client/server fixtures.
///
/// # Panics
/// Panics (via `process::abort`) if the server fails to start.
#[allow(clippy::unwrap_used)]
pub async fn start_default_test_kms_server() -> &'static TestsContext {
    trace!("Starting default test server");
    ONCE.get_or_try_init(|| async move {
        if env::var_os("KMS_USE_KEK").is_some() {
            let server_params = create_server_params_with_kek().await.unwrap();
            start_from_server_params(server_params, Some("test/kek")).await
        } else {
            let config = load_server_config(default_server_config_name())?;
            let server_params = ServerParams::try_from(config).map_err(|e| {
                KmsClientError::Default(format!(
                    "Failed to build ServerParams from default config: {e}"
                ))
            })?;
            start_from_server_params(server_params, Some("test/default")).await
        }
    })
    .await
    .unwrap_or_else(|e| {
        error!("failed to start default test server: {e}");
        std::process::abort();
    })
}

/// Start the mutual-TLS test server (port 9999, no JWT).
/// Loads `test/cert_auth.toml` (PEM, works in both FIPS and non-FIPS mode).
pub async fn start_default_test_kms_server_with_cert_auth() -> &'static TestsContext {
    trace!("Starting test server with cert auth");
    ONCE_SERVER_WITH_AUTH
        .get_or_try_init(|| async move {
            let mut config = load_server_config("test/cert_auth")?;
            apply_kms_test_db_override(&mut config);
            let server_params = ServerParams::try_from(config).map_err(|e| {
                KmsClientError::Default(format!(
                    "Failed to build ServerParams from cert-auth config: {e}"
                ))
            })?;
            start_from_server_params(server_params, Some("test/cert_auth")).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with cert auth: {e}");
            std::process::abort();
        })
}

/// Start the non-revocable key test server (plain HTTP, port 10000).
/// Configuration is loaded from `test_data/configs/server/test/non_revocable.toml`.
/// The `non_revocable_key_id` list is injected at runtime after loading the config.
pub async fn start_default_test_kms_server_with_non_revocable_key_ids(
    non_revocable_key_id: Option<Vec<String>>,
) -> &'static TestsContext {
    trace!("Starting test server with non-revocable key ids");
    ONCE_SERVER_WITH_NON_REVOCABLE_KEY
        .get_or_try_init(|| async move {
            let mut config = load_server_config("test/non_revocable")?;
            config.non_revocable_key_id = non_revocable_key_id;
            apply_kms_test_db_override(&mut config);
            let server_params = ServerParams::try_from(config).map_err(|e| {
                KmsClientError::Default(format!(
                    "Failed to build ServerParams from test/non_revocable.toml: {e}"
                ))
            })?;
            start_from_server_params(server_params, Some("test/non_revocable")).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with non-revocable key ids: {e}");
            std::process::abort();
        })
}

/// Start the Utimaco HSM test server (plain HTTP, port 10001).
/// Configuration is loaded from `test_data/configs/server/test/hsm.toml`.
pub async fn start_default_test_kms_server_with_utimaco_hsm() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM");
    ONCE_SERVER_WITH_HSM
        .get_or_try_init(|| async move {
            let mut config = load_server_config("test/hsm")?;
            apply_kms_test_db_override(&mut config);
            let server_params = ServerParams::try_from(config).map_err(|e| {
                KmsClientError::Default(format!(
                    "Failed to build ServerParams from test/hsm.toml: {e}"
                ))
            })?;
            start_from_server_params(server_params, Some("test/hsm")).await
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
    let workspace_dir = std::env::temp_dir().join(format!(
        "kms_test_workspace_{port}_{}",
        repo_test_namespace_suffix()
    ));
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
            hsm_admin: vec!["tech@cosmian.com".to_owned()],
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
        with_server_port(load_client_config("test/auth_plain_jwt_owner")?, port);
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

async fn create_server_params_with_kek() -> Result<ServerParams, KmsClientError> {
    let (workspace_dir, kek_id) = create_kek_in_db().await?;
    trace!(
        "Key encryption key created: {kek_id} in workspace {}",
        workspace_dir.display()
    );

    assert!(
        workspace_dir.exists() && !kek_id.is_empty(),
        "workspace_dir must exist and kek_id must be non-empty"
    );

    let mut config = load_server_config("test/kek")?;

    // Override workspace and DB paths to reuse the database that holds the freshly-created KEK.
    config.workspace.root_data_path.clone_from(&workspace_dir);
    config.db.sqlite_path = workspace_dir;
    config.key_encryption_key = Some(kek_id);
    config.default_unwrap_type = Some(vec!["All".to_owned()]);

    ServerParams::try_from(config).map_err(|e| {
        KmsClientError::Default(format!("Failed to build ServerParams from kek config: {e}"))
    })
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
            let server_params = create_server_params_with_kek().await.unwrap();

            start_from_server_params(server_params, Some("test/kek")).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with utimaco hsm: {e}");
            std::process::abort();
        })
}

/// Start the privileged-users test server (TLS+JWT, port 10003).
/// Loads `test/privileged_users.toml` (PEM, works in both FIPS and non-FIPS mode).
/// The `privileged_users` list is injected at runtime after loading the config.
pub async fn start_default_test_kms_server_with_privileged_users(
    privileged_users: Vec<String>,
) -> &'static TestsContext {
    trace!("Starting test server with privileged users");
    ONCE_SERVER_WITH_PRIVILEGED_USERS
        .get_or_try_init(|| async move {
            let mut config = load_server_config("test/privileged_users")?;
            config.privileged_users = Some(privileged_users);
            apply_kms_test_db_override(&mut config);
            let server_params = ServerParams::try_from(config).map_err(|e| {
                KmsClientError::Default(format!(
                    "Failed to build ServerParams from privileged-users config: {e}"
                ))
            })?;
            start_from_server_params(server_params, Some("test/privileged_users")).await
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
    /// Absolute path to a config TOML file for the owner identity.
    /// Points to `test_data/configs/client/<name>.toml` for singleton servers,
    /// or to a temp file for non-singleton (auth-test) servers.
    pub owner_conf_path: String,
    /// Absolute path to a config TOML file for the user identity.
    pub user_conf_path: String,
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
    let mut server_params = ServerParams::try_from(config).map_err(|e| {
        KmsClientError::Default(format!(
            "Failed to build ServerParams in start_temp_test_kms_server: {e}"
        ))
    })?;
    remap_test_server_ports_if_needed(&mut server_params)?;

    info!(" -- Test KMS server configuration: {:#?}", server_params);
    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    let server_port = server_params.http_port;
    let owner_client_config = with_server_port(owner_client_config, server_port);
    let user_client_config = owner_client_config.clone();

    // Write temp config files so callers can pass them to CLI subprocesses.
    // The configs may contain in-memory modifications (e.g. access_token injected
    // for auth-test scenarios), so we always write fresh temp files here.
    let owner_conf_path = write_temp_client_conf(&owner_client_config, server_port, "owner")?;
    let user_conf_path = write_temp_client_conf(&user_client_config, server_port, "user")?;

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
        owner_conf_path,
        user_conf_path,
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
        (false, _, false) => ("test/auth_plain_owner", "test/auth_plain_user"),
        (false, _, true) => ("test/auth_plain_jwt_owner", "test/auth_plain_jwt_user"),
        (true, false, false) => ("test/auth_https_owner", "test/auth_https_user"),
        (true, false, true) => ("test/auth_https_jwt_owner", "test/auth_https_jwt_user"),
        (true, true, false) => (
            "test/auth_https_client_ca_owner",
            "test/auth_https_client_ca_user",
        ),
        (true, true, true) => (
            "test/auth_https_jwt_cert_owner",
            "test/auth_https_jwt_cert_user",
        ),
    }
}

/// Serialize a [`KmsClientConfig`] to a temporary TOML file and return the path.
///
/// Used after replacing the server port in client configs, and for non-singleton
/// (temp) servers where the config may have been modified in memory.
fn write_temp_client_conf(
    config: &KmsClientConfig,
    port: u16,
    role: &str,
) -> Result<String, KmsClientError> {
    let path = env::temp_dir().join(format!("kms_{role}_{port}.toml"));
    let toml = toml::to_string(config).map_err(|e| {
        KmsClientError::Default(format!("Cannot serialize client config to TOML: {e}"))
    })?;
    std::fs::write(&path, &toml).map_err(|e| {
        KmsClientError::Default(format!(
            "Cannot write temp client config {}: {e}",
            path.display()
        ))
    })?;
    Ok(path.to_string_lossy().into_owned())
}

/// Common finalization once the server parameters are fully constructed.
///
/// `config_name` is the base name of the server config (e.g. `"test/default"`, `"test/cert_auth"`)
/// used to derive owner/user client config file names (`<name>_owner.toml`, `<name>_user.toml`).
/// When `None`, the names are inferred via [`client_config_names`] and a temp file is written.
async fn start_from_server_params(
    server_params: ServerParams,
    config_name: Option<&str>,
) -> Result<TestsContext, KmsClientError> {
    let mut server_params = server_params;
    remap_test_server_ports_if_needed(&mut server_params)?;
    let port = server_params.http_port;
    let (owner_name, user_name): (String, String) = config_name.map_or_else(
        || {
            let (owner, user) = client_config_names(&server_params);
            (owner.to_owned(), user.to_owned())
        },
        |name| (format!("{name}_owner"), format!("{name}_user")),
    );
    let owner_client_config = with_server_port(load_client_config(&owner_name)?, port);
    let user_client_config = with_server_port(load_client_config(&user_name)?, port);

    let owner_conf_path = write_temp_client_conf(&owner_client_config, port, "owner")?;
    let user_conf_path = write_temp_client_conf(&user_client_config, port, "user")?;

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
        owner_conf_path,
        user_conf_path,
        server_handle,
        thread_handle,
    })
}

#[cfg(test)]
#[cfg(feature = "non-fips")]
#[allow(clippy::unwrap_in_result)]
#[tokio::test]
async fn test_start_server() -> Result<(), KmsClientError> {
    let mut config = load_server_config("test/default")?;
    config.http.port = 9990;
    let owner_client_config = with_server_port(load_client_config("test/auth_plain_owner")?, 9990);
    let context = start_temp_test_kms_server(config, owner_client_config).await?;
    context.stop_server().await
}
