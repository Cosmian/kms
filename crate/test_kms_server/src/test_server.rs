use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

use actix_server::ServerHandle;
use cosmian_kms_client::{
    GmailApiConf, KmsClient, KmsClientConfig, KmsClientError, kms_client_bail, kms_client_error,
    reexport::cosmian_http_client::HttpClientConfig,
};
use cosmian_kms_server::{
    config::{
        ClapConfig, GoogleCseConfig, HsmConfig, HttpConfig, IdpAuthConfig, MainDBConfig,
        ServerParams, SocketServerConfig, TlsConfig, WorkspaceConfig,
    },
    start_kms_server::start_kms_server,
};
use cosmian_logger::{debug, error, info, trace, warn};
use tokio::sync::OnceCell;

use crate::test_jwt::{AUTH0_TOKEN, AUTH0_TOKEN_USER, get_auth0_jwt_config};

/// To run most tests in parallel,
/// We use that to avoid trying to start N KMS servers (one per test)
/// with a default configuration.
/// Otherwise, we get: "Address already in use (os error 98)"
/// for N-1 tests.
pub(crate) static ONCE: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_AUTH: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_NON_REVOCABLE_KEY: OnceCell<TestsContext> =
    OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_HSM: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_HSM_AND_JWT: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_PRIVILEGED_USERS: OnceCell<TestsContext> = OnceCell::const_new();

const DEFAULT_KMS_SERVER_PORT: u16 = 9998;

// Small utilities to reduce repetition
#[inline]
fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMode {
    PlainHttp,
    HttpsNoClientCa,
    HttpsWithClientCa,
}

impl TlsMode {
    const fn use_https(self) -> bool {
        !matches!(self, Self::PlainHttp)
    }

    const fn use_known_ca_list(self) -> bool {
        matches!(self, Self::HttpsWithClientCa)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtAuth {
    Disabled,
    Enabled,
}

impl JwtAuth {
    const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

fn path_to_string(p: &Path) -> Result<String, KmsClientError> {
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| KmsClientError::Default("Can't convert path to string".to_owned()))
}

async fn start_server_once(
    cell: &'static OnceCell<TestsContext>,
    port: u16,
    authentication_options: AuthenticationOptions,
    non_revocable_key_id: Option<Vec<String>>, // first call wins
    privileged_users: Option<Vec<String>>,     // first call wins
) -> Result<&'static TestsContext, KmsClientError> {
    cell.get_or_try_init(|| async move {
        start_test_server_with_options(
            get_db_config(),
            port,
            authentication_options,
            non_revocable_key_id,
            privileged_users,
        )
        .await
    })
    .await
}

fn sqlite_db_config() -> MainDBConfig {
    trace!("TESTS: using sqlite");
    let base = std::env::temp_dir().join("kms_sqlite");
    if let Err(e) = std::fs::create_dir_all(&base) {
        warn!(
            "Could not create sqlite base temp dir ({}): {e}",
            base.display()
        );
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let file_path = base.join(format!("test_sqlite-{ts}.db"));
    if file_path.exists() {
        debug!("Removing existing sqlite db at: {}", file_path.display());
        if let Err(e) = std::fs::remove_file(&file_path) {
            warn!(
                "Could not remove existing sqlite db at {}: {e}",
                file_path.display()
            );
        }
    }
    MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        clear_database: false,
        sqlite_path: file_path,
        ..MainDBConfig::default()
    }
}

fn mysql_db_config() -> MainDBConfig {
    trace!("TESTS: using mysql");
    let mysql_url = option_env!("KMS_MYSQL_URL")
        .unwrap_or("mysql://kms:kms@localhost:3306/kms")
        .to_owned();
    MainDBConfig {
        database_type: Some("mysql".to_owned()),
        clear_database: false,
        database_url: Some(mysql_url),
        ..MainDBConfig::default()
    }
}

fn postgres_db_config() -> MainDBConfig {
    trace!("TESTS: using postgres");
    let postgresql_url = option_env!("KMS_POSTGRES_URL")
        .unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms")
        .to_owned();
    MainDBConfig {
        database_type: Some("postgresql".to_owned()),
        clear_database: false,
        database_url: Some(postgresql_url),
        ..MainDBConfig::default()
    }
}

#[allow(deprecated)] // needed to migrate
#[cfg(feature = "non-fips")]
fn redis_findex_db_config() -> MainDBConfig {
    trace!("TESTS: using redis-findex");
    let url = env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    );
    MainDBConfig {
        database_type: Some("redis-findex".to_owned()),
        clear_database: false,
        unwrapped_cache_max_age: 15,
        database_url: Some(url),
        sqlite_path: PathBuf::default(),
        redis_master_password: Some("password".to_owned()),
        redis_findex_label: Some("label".to_owned()),
    }
}

fn get_db_config() -> MainDBConfig {
    env::var_os("KMS_TEST_DB").map_or_else(sqlite_db_config, |v| match v.to_str().unwrap_or("") {
        #[cfg(feature = "non-fips")]
        "redis-findex" => redis_findex_db_config(),
        "mysql" => mysql_db_config(),
        "postgresql" => postgres_db_config(),
        _ => sqlite_db_config(),
    })
}

/// Start a test KMS server in a thread with the default options:
/// No TLS, no certificate authentication
pub async fn start_default_test_kms_server() -> &'static TestsContext {
    trace!("Starting default test server");
    start_server_once(
        &ONCE,
        DEFAULT_KMS_SERVER_PORT,
        AuthenticationOptions::new(),
        None,
        None,
    )
    .await
    .unwrap_or_else(|e| {
        error!("failed to start default test server: {e}");
        std::process::abort();
    })
}
/// TLS + certificate authentication
pub async fn start_default_test_kms_server_with_cert_auth() -> &'static TestsContext {
    trace!("Starting test server with cert auth");
    ONCE_SERVER_WITH_AUTH
        .get_or_try_init(|| async move {
            let port = DEFAULT_KMS_SERVER_PORT + 1;
            let db_config = get_db_config();

            let server_params = build_server_params_full(BuildServerParamsOptions {
                db_config,
                port,
                tls: TlsMode::HttpsWithClientCa,
                jwt: JwtAuth::Disabled,
                server_tls_cipher_suites: None,
                api_token_id: None,
                privileged_users: None,
                non_revocable_key_id: None,
                hsm: None,
            })
            .map_err(|e| {
                KmsClientError::Default(format!(
                    "failed initializing the server config (cert auth): {e}"
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

/// revocable key IDs
pub async fn start_default_test_kms_server_with_non_revocable_key_ids(
    non_revocable_key_id: Option<Vec<String>>,
) -> &'static TestsContext {
    trace!("Starting test server with non-revocable key ids");
    start_server_once(
        &ONCE_SERVER_WITH_NON_REVOCABLE_KEY,
        DEFAULT_KMS_SERVER_PORT + 2,
        AuthenticationOptions::new(),
        non_revocable_key_id,
        None,
    )
    .await
    .unwrap_or_else(|e| {
        error!("failed to start test server with non-revocable key ids: {e}");
        std::process::abort();
    })
}

/// With Utimaco HSM
pub async fn start_default_test_kms_server_with_utimaco_hsm() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM");
    // Build ServerParams with HSM fields directly and start from them
    ONCE_SERVER_WITH_HSM
        .get_or_try_init(|| async move {
            let port = DEFAULT_KMS_SERVER_PORT + 3;
            let db_config = get_db_config();

            let server_params = build_server_params_full(BuildServerParamsOptions {
                db_config,
                port,
                tls: TlsMode::PlainHttp,
                jwt: JwtAuth::Disabled,
                hsm: Some(HsmConfig {
                    hsm_model: "utimaco".to_owned(),
                    hsm_admin: "tech@cosmian.com".to_owned(),
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

/// With Utimaco HSM
pub async fn start_default_test_kms_server_with_utimaco_hsm_and_jwt() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM and JWT Auth");
    // Build ServerParams with HSM fields directly and start from them
    ONCE_SERVER_WITH_HSM_AND_JWT
        .get_or_try_init(|| async move {
            let port = DEFAULT_KMS_SERVER_PORT + 4;
            let db_config = get_db_config();

            let server_params = build_server_params_full(BuildServerParamsOptions {
                db_config,
                port,
                tls: TlsMode::PlainHttp,
                jwt: JwtAuth::Enabled,
                hsm: Some(HsmConfig {
                    hsm_model: "utimaco".to_owned(),
                    hsm_admin: "tech@cosmian.com".to_owned(),
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

/// Privileged users
pub async fn start_default_test_kms_server_with_privileged_users(
    privileged_users: Vec<String>,
) -> &'static TestsContext {
    trace!("Starting test server with privileged users");
    ONCE_SERVER_WITH_PRIVILEGED_USERS
        .get_or_try_init(|| async move {
            let port = DEFAULT_KMS_SERVER_PORT + 5;
            let db_config = get_db_config();

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
                    "failed initializing the server config (privileged users): {e}"
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCertPolicy {
    /// Send a client certificate when the server requires it (default cert if none is provided)
    Send,
    /// Do not send any client certificate
    Suppress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiTokenPolicy {
    /// Send API token if provided by the client configuration (default)
    SendIfProvided,
    /// Do not send API token even if provided
    Suppress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtPolicy {
    /// Auto-inject a default `JWT` when the server has an `IdP` and no token was provided (default)
    AutoDefault,
    /// Never send a `JWT`
    Suppress,
}

pub struct ClientAuthOptions {
    pub http: HttpClientConfig,
    pub client_cert: ClientCertPolicy,
    pub api_token: ApiTokenPolicy,
    pub jwt: JwtPolicy,
}

impl Default for ClientAuthOptions {
    fn default() -> Self {
        Self {
            http: HttpClientConfig::default(),
            client_cert: ClientCertPolicy::Send,
            api_token: ApiTokenPolicy::SendIfProvided,
            jwt: JwtPolicy::AutoDefault,
        }
    }
}

#[derive(Default)]
pub struct AuthenticationOptions {
    pub client: ClientAuthOptions,
    pub server_params: Option<ServerParams>,
}

impl AuthenticationOptions {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: ClientAuthOptions::default(),
            server_params: None,
        }
    }
}

/// Options container to avoid `too_many_arguments` on the builder
#[derive(Clone)]
pub struct BuildServerParamsOptions {
    pub db_config: MainDBConfig,
    pub port: u16,
    pub tls: TlsMode,
    pub jwt: JwtAuth,
    pub server_tls_cipher_suites: Option<String>,
    pub api_token_id: Option<String>,
    pub privileged_users: Option<Vec<String>>,
    pub non_revocable_key_id: Option<Vec<String>>,
    pub hsm: Option<HsmConfig>,
}

impl std::fmt::Debug for BuildServerParamsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildServerParamsOptions")
            .field("db_config", &"<redacted>")
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("jwt", &self.jwt)
            .field("server_tls_cipher_suites", &self.server_tls_cipher_suites)
            .field("api_token_id", &self.api_token_id)
            .field("privileged_users", &self.privileged_users)
            .field("non_revocable_key_id", &self.non_revocable_key_id)
            .field("hsm", &self.hsm.as_ref().map(|_| "<provided>"))
            .finish()
    }
}

impl Default for BuildServerParamsOptions {
    fn default() -> Self {
        Self {
            db_config: MainDBConfig::default(),
            port: 0,
            tls: TlsMode::PlainHttp,
            jwt: JwtAuth::Disabled,
            server_tls_cipher_suites: None,
            api_token_id: None,
            privileged_users: None,
            non_revocable_key_id: None,
            hsm: None,
        }
    }
}

/// Start a KMS server in a thread with the given options
pub async fn start_test_server_with_options(
    db_config: MainDBConfig,
    port: u16,
    authentication_options: AuthenticationOptions,
    non_revocable_key_id: Option<Vec<String>>,
    privileged_users: Option<Vec<String>>,
) -> Result<TestsContext, KmsClientError> {
    // Destructure options to avoid borrow/move conflicts
    let AuthenticationOptions {
        client,
        server_params: server_params_opt,
    } = authentication_options;
    let client_opts = &client;
    // Generate server params
    let server_params = generate_server_params(
        db_config,
        port,
        server_params_opt,
        non_revocable_key_id,
        privileged_users,
    )?;

    // Create a (object owner) conf
    let owner_client_config = generate_owner_conf(&server_params, client_opts)?;

    info!(" -- Test KMS server configuration: {:#?}", server_params);
    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    // generate a user conf
    let use_jwt_token = server_params.identity_provider_configurations.is_some();
    let user_client_config = generate_user_conf(&owner_client_config, use_jwt_token, client_opts)?;
    let server_port = server_params.http_port;

    let (server_handle, thread_handle) = start_test_kms_server(server_params)?;

    // wait for the server to be up
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

/// Start a test KMS server with the given config in a separate thread
fn start_test_kms_server(
    server_params: ServerParams,
) -> Result<(ServerHandle, JoinHandle<Result<(), KmsClientError>>), KmsClientError> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the KMS Server in the future
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
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

fn server_tls_config(mode: TlsMode, server_tls_cipher_suites: Option<String>) -> TlsConfig {
    if !mode.use_https() {
        return TlsConfig::default();
    }
    let clients_ca = mode
        .use_known_ca_list()
        .then(|| root_dir().join("../../test_data/certificates/client_server/ca/stack_of_ca.pem"));
    TlsConfig {
        tls_p12_file: Some(
            root_dir()
                .join("../../test_data/certificates/client_server/server/kmserver.acme.com.p12"),
        ),
        tls_p12_password: Some("password".to_owned()),
        clients_ca_cert_file: clients_ca,
        tls_cipher_suites: server_tls_cipher_suites,
    }
}

pub fn build_server_params_full(
    opts: BuildServerParamsOptions,
) -> Result<ServerParams, KmsClientError> {
    // Create a unique workspace path for each test to avoid race conditions
    let workspace_dir = std::env::temp_dir().join(format!("kms_test_workspace_{}", opts.port));

    let idp_auth = if opts.jwt.is_enabled() {
        // Issuer must match the JWTs embedded in test_kms_server::test_jwt
        get_auth0_jwt_config()
    } else {
        IdpAuthConfig::default()
    };

    let mut clap = ClapConfig {
        idp_auth,
        socket_server: SocketServerConfig {
            // Start socket server when HTTPS and client cert auth are used
            socket_server_start: opts.tls.use_https() && opts.tls.use_known_ca_list(),
            socket_server_port: opts.port + 100,
            ..Default::default()
        },
        workspace: WorkspaceConfig {
            root_data_path: workspace_dir.clone(),
            tmp_path: workspace_dir.join("tmp"),
        },
        db: opts.db_config,
        tls: server_tls_config(opts.tls, opts.server_tls_cipher_suites),
        http: HttpConfig {
            port: opts.port,
            api_token_id: opts.api_token_id,
            ..HttpConfig::default()
        },
        // Expose Google CSE endpoints in tests and relax token validation
        kms_public_url: Some(format!("http://localhost:{}/google_cse", opts.port)),
        google_cse_config: GoogleCseConfig {
            google_cse_enable: true,
            google_cse_disable_tokens_validation: !opts.jwt.is_enabled(),
            google_cse_incoming_url_whitelist: Some(vec!["https://cse.cosmian.com".to_owned()]),
            google_cse_migration_key: None,
        },
        non_revocable_key_id: opts.non_revocable_key_id,
        privileged_users: opts.privileged_users,
        default_username: "tech@cosmian.com".to_owned(),
        ..ClapConfig::default()
    };

    // If HSM options were provided, set them under the nested HSM config
    if let Some(h) = opts.hsm {
        clap.hsm = h;
    }

    ServerParams::try_from(clap).map_err(|e| {
        KmsClientError::Default(format!(
            "Failed to build ServerParams for test harness: {e}"
        ))
    })
}

// Convenience builder used by CLI tests and simple scenarios
pub fn build_server_params(
    db_config: MainDBConfig,
    port: u16,
    tls: TlsMode,
    jwt: JwtAuth,
    server_tls_cipher_suites: Option<String>,
    api_token_id: Option<String>,
) -> Result<ServerParams, KmsClientError> {
    build_server_params_full(BuildServerParamsOptions {
        db_config,
        port,
        tls,
        jwt,
        server_tls_cipher_suites,
        api_token_id,
        ..Default::default()
    })
}

fn generate_server_params(
    db_config: MainDBConfig,
    port: u16,
    server_params_opt: Option<ServerParams>,
    non_revocable_key_id: Option<Vec<String>>,
    privileged_users: Option<Vec<String>>,
) -> Result<ServerParams, KmsClientError> {
    if let Some(sp) = server_params_opt {
        return Ok(sp);
    }
    build_server_params_full(BuildServerParamsOptions {
        db_config,
        port,
        tls: TlsMode::PlainHttp,
        jwt: JwtAuth::Disabled,
        privileged_users,
        non_revocable_key_id,
        ..Default::default()
    })
}

/// Common finalization once the server parameters are fully constructed
async fn start_from_server_params(
    server_params: ServerParams,
) -> Result<TestsContext, KmsClientError> {
    // Create a (object owner) conf
    let owner_client_config = generate_owner_conf(&server_params, &ClientAuthOptions::default())?;

    info!(" -- Test KMS server configuration: {:#?}", server_params);
    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    // generate a user conf
    let use_jwt_token = server_params.identity_provider_configurations.is_some();
    let user_client_config = generate_user_conf(
        &owner_client_config,
        use_jwt_token,
        &ClientAuthOptions::default(),
    )?;
    let server_port = server_params.http_port;

    let (server_handle, thread_handle) = start_test_kms_server(server_params)?;

    // wait for the server to be up
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

fn set_access_token(
    use_jwt_token: bool,
    use_api_token: bool,
    access_token: Option<String>,
    api_token: Option<String>,
) -> Option<String> {
    if use_jwt_token {
        trace!("Setting access token for JWT: {access_token:?}");
        access_token
    } else if use_api_token {
        trace!("Setting access token for API: {api_token:?}");
        api_token
    } else {
        None
    }
}

fn generate_owner_conf(
    server_params: &ServerParams,
    client_opts: &ClientAuthOptions,
) -> Result<KmsClientConfig, KmsClientError> {
    // This creates a root dir
    let root_path = root_dir();

    let gmail_api_conf: Option<GmailApiConf> = env::var("TEST_GMAIL_API_CONF")
        .ok()
        .and_then(|config| serde_json::from_str(&config).ok());

    let use_client_cert_auth = server_params
        .tls_params
        .as_ref()
        .and_then(|tls| tls.clients_ca_cert_pem.as_ref())
        .is_some();

    let use_jwt_token = match client_opts.jwt {
        JwtPolicy::Suppress => false,
        JwtPolicy::AutoDefault => {
            server_params.identity_provider_configurations.is_some()
                && client_opts.http.access_token.is_none()
        }
    };

    let use_api_token = client_opts.http.access_token.is_some()
        && client_opts.api_token == ApiTokenPolicy::SendIfProvided;

    let mut http_conf = client_opts.http.clone();
    http_conf.server_url = if server_params.tls_params.is_some() {
        format!("https://localhost:{}", server_params.http_port)
    } else {
        format!("http://localhost:{}", server_params.http_port)
    };
    http_conf.accept_invalid_certs = true;
    http_conf.access_token = set_access_token(
        use_jwt_token,
        use_api_token,
        Some(AUTH0_TOKEN.to_owned()),
        if use_api_token {
            client_opts.http.access_token.clone()
        } else {
            None
        },
    );
    if use_client_cert_auth {
        // If the server requires client certs: either don't send them (if requested),
        // or auto-provide a default cert when none is configured explicitly.
        if client_opts.client_cert == ClientCertPolicy::Suppress {
            http_conf.ssl_client_pkcs12_path = None;
            http_conf.ssl_client_pkcs12_password = None;
        } else {
            if http_conf.ssl_client_pkcs12_path.is_none() {
                let p = root_path.join(
                    "../../test_data/certificates/client_server/owner/owner.client.acme.com.p12",
                );
                http_conf.ssl_client_pkcs12_path = Some(path_to_string(&p)?);
            }
            if http_conf.ssl_client_pkcs12_password.is_none() {
                http_conf.ssl_client_pkcs12_password = Some("password".to_owned());
            }
        }
    } else {
        // If server doesn't require client cert, don't send one
        http_conf.ssl_client_pkcs12_path = None;
        http_conf.ssl_client_pkcs12_password = None;
    }

    let conf = KmsClientConfig {
        http_config: http_conf,
        gmail_api_conf,
        print_json: None,
    };

    Ok(conf)
}

/// Generate a user configuration for user.client@acme.com and return the file path
fn generate_user_conf(
    owner_client_conf: &KmsClientConfig,
    use_jwt_token: bool,
    client_opts: &ClientAuthOptions,
) -> Result<KmsClientConfig, KmsClientError> {
    // This creates root dir
    let root_dir = root_dir();

    let mut conf = owner_client_conf.clone();
    if client_opts.client_cert == ClientCertPolicy::Suppress {
        conf.http_config.ssl_client_pkcs12_path = None;
        conf.http_config.ssl_client_pkcs12_password = None;
    } else {
        conf.http_config.ssl_client_pkcs12_path = {
            let p = root_dir
                .join("../../test_data/certificates/client_server/user/user.client.acme.com.p12");
            Some(path_to_string(&p)?)
        };
        conf.http_config.ssl_client_pkcs12_password = Some("password".to_owned());
    }
    conf.http_config.access_token = set_access_token(
        matches!(client_opts.jwt, JwtPolicy::AutoDefault) && use_jwt_token,
        client_opts.api_token == ApiTokenPolicy::SendIfProvided
            && conf.http_config.access_token.is_some(),
        Some(AUTH0_TOKEN_USER.to_owned()),
        None,
    );

    Ok(conf)
}

#[cfg(test)]
#[allow(clippy::unwrap_in_result)]
#[tokio::test]
async fn test_start_server() -> Result<(), KmsClientError> {
    let context = start_test_server_with_options(
        sqlite_db_config(),
        DEFAULT_KMS_SERVER_PORT + 20,
        AuthenticationOptions::new(),
        None,
        None,
    )
    .await?;
    context.stop_server().await
}
