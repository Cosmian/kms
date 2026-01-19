use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
    vec,
};

use actix_server::ServerHandle;
use cosmian_kms_client::{
    GmailApiConf, KmsClient, KmsClientConfig, KmsClientError,
    cosmian_kmip::time_normalize,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, GetAttributes},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
    kms_client_bail, kms_client_error,
    reexport::cosmian_http_client::HttpClientConfig,
};
use cosmian_kms_server::{
    config::{
        ClapConfig, GoogleCseConfig, HsmConfig, HttpConfig, IdpAuthConfig, MainDBConfig,
        ServerParams, SocketServerConfig, TlsConfig, WorkspaceConfig,
    },
    start_kms_server::start_kms_server,
};
use cosmian_logger::{error, info, trace, warn};
use tokio::sync::OnceCell;

use crate::test_jwt::{AUTH0_TOKEN, AUTH0_TOKEN_USER, get_multiple_jwt_config};

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
pub(crate) static ONCE_SERVER_WITH_KEK: OnceCell<TestsContext> = OnceCell::const_new();
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

fn sqlite_db_config(workspace_dir: Option<&PathBuf>) -> MainDBConfig {
    let base = workspace_dir.map_or_else(
        || std::env::temp_dir().join("kms_sqlite"),
        std::clone::Clone::clone,
    );
    trace!("TESTS: using sqlite at base dir: {}", base.display());
    if let Err(e) = std::fs::create_dir_all(&base) {
        warn!(
            "Could not create sqlite base temp dir ({}): {e}",
            base.display()
        );
    }
    MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        clear_database: true,
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
#[allow(clippy::as_conversions)]
fn redis_findex_db_config(port: u16) -> MainDBConfig {
    trace!("TESTS: using redis-findex");
    let mut url = env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    );
    // Compute a logical DB index from the port to isolate concurrent servers.
    // Using a small ring to keep index bounded.
    let db_index: u8 = (port % 16) as u8;
    // Ensure the redis URL carries the DB index (e.g., redis://host:6379/5)
    // If the URL already has a trailing "/<digits>", replace it; otherwise append it
    let has_db_suffix = url
        .rsplit('/')
        .next()
        .is_some_and(|s| s.chars().all(|c| c.is_ascii_digit()));
    if has_db_suffix {
        if let Some(pos) = url.rfind('/') {
            url.truncate(pos + 1);
            url.push_str(&db_index.to_string());
        }
    } else {
        if !url.ends_with('/') {
            url.push('/');
        }
        url.push_str(&db_index.to_string());
    }

    MainDBConfig {
        database_type: Some("redis-findex".to_owned()),
        clear_database: true,
        unwrapped_cache_max_age: 15,
        max_connections: None,
        database_url: Some(url),
        sqlite_path: PathBuf::default(),
        redis_master_password: Some("password".to_owned()),
    }
}

#[allow(clippy::used_underscore_binding)]
fn get_db_config(_port: u16, workspace_dir: Option<&PathBuf>) -> MainDBConfig {
    env::var_os("KMS_TEST_DB").map_or_else(
        || sqlite_db_config(workspace_dir),
        |v| match v.to_str().unwrap_or("") {
            #[cfg(feature = "non-fips")]
            "redis-findex" => redis_findex_db_config(_port),
            "mysql" => mysql_db_config(),
            "postgresql" => postgres_db_config(),
            _ => sqlite_db_config(workspace_dir),
        },
    )
}

/// Start a test KMS server in a thread with the default options:
/// No TLS, no certificate authentication
/// # Panics
/// - if the server fails to start
#[allow(clippy::unwrap_used)]
pub async fn start_default_test_kms_server() -> &'static TestsContext {
    trace!("Starting default test server");
    ONCE.get_or_try_init(|| async move {
        let use_kek = env::var_os("KMS_USE_KEK");
        match use_kek {
            Some(_use_kek) => {
                let server_params = create_server_params_with_kek().await.unwrap();
                start_from_server_params(server_params).await
            }
            None => {
                start_test_server_with_options(
                    get_db_config(DEFAULT_KMS_SERVER_PORT, None),
                    DEFAULT_KMS_SERVER_PORT,
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

/// TLS + certificate authentication
pub async fn start_default_test_kms_server_with_cert_auth() -> &'static TestsContext {
    trace!("Starting test server with cert auth");
    ONCE_SERVER_WITH_AUTH
        .get_or_try_init(|| async move {
            let port = DEFAULT_KMS_SERVER_PORT + 1;
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
    ONCE_SERVER_WITH_NON_REVOCABLE_KEY
        .get_or_try_init(|| async move {
            start_test_server_with_options(
                get_db_config(DEFAULT_KMS_SERVER_PORT + 2, None),
                DEFAULT_KMS_SERVER_PORT + 2,
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

/// With Utimaco HSM
pub async fn start_default_test_kms_server_with_utimaco_hsm() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM");
    // Build ServerParams with HSM fields directly and start from them
    ONCE_SERVER_WITH_HSM
        .get_or_try_init(|| async move {
            let port = DEFAULT_KMS_SERVER_PORT + 3;
            let db_config = get_db_config(port, None);

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

// Create a KEK in the HSM before running server with `key_encryption_key` arg
async fn create_kek_in_db() -> Result<(PathBuf, String), KmsClientError> {
    let port = 20000;
    let workspace_dir = std::env::temp_dir().join(format!("kms_test_workspace_{port}"));
    let kek_id = "hsm::0::kek";
    let db_config = MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        clear_database: true,
        ..MainDBConfig::default()
    };

    let ctx = start_test_server_with_options(
        db_config.clone(),
        port,
        AuthenticationOptions {
            client: ClientAuthOptions {
                http: HttpClientConfig::default(),
                jwt: JwtPolicy::AutoDefault,
                ..Default::default()
            },
            server_params: Some(build_server_params_full(BuildServerParamsOptions {
                workspace_dir: Some(workspace_dir.clone()),
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
            })?),
        },
        None,
        None,
    )
    .await?;

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

    // No grant access is required on external keys (e.g., when using HSM encryption oracles)

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

    let port = DEFAULT_KMS_SERVER_PORT + 4;
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
            hsm_admin: "owner.client@acme.com".to_owned(),
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
            let server_params = create_server_params_with_kek().await.unwrap();

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
    pub workspace_dir: Option<PathBuf>,
    pub db_config: MainDBConfig,
    pub port: u16,
    pub tls: TlsMode,
    pub jwt: JwtAuth,
    pub server_tls_cipher_suites: Option<String>,
    pub api_token_id: Option<String>,
    pub privileged_users: Option<Vec<String>>,
    pub non_revocable_key_id: Option<Vec<String>>,
    pub hsm: Option<HsmConfig>,
    pub key_encryption_key: Option<String>,
}

impl std::fmt::Debug for BuildServerParamsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildServerParamsOptions")
            .field("workspace_dir", &self.workspace_dir)
            .field("db_config", &"<redacted>")
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("jwt", &self.jwt)
            .field("server_tls_cipher_suites", &self.server_tls_cipher_suites)
            .field("api_token_id", &self.api_token_id)
            .field("privileged_users", &self.privileged_users)
            .field("non_revocable_key_id", &self.non_revocable_key_id)
            .field("hsm", &self.hsm.as_ref().map(|_| "<provided>"))
            .field(
                "key_encryption_key",
                &self.key_encryption_key.as_ref().map(|_| "<provided>"),
            )
            .finish()
    }
}

impl Default for BuildServerParamsOptions {
    fn default() -> Self {
        Self {
            workspace_dir: None,
            db_config: MainDBConfig::default(),
            port: 0,
            tls: TlsMode::PlainHttp,
            jwt: JwtAuth::Disabled,
            server_tls_cipher_suites: None,
            api_token_id: None,
            privileged_users: None,
            non_revocable_key_id: None,
            hsm: None,
            key_encryption_key: None,
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
            // error!("Error waiting for server to start: {e:?}");
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

fn server_tls_config(mode: TlsMode, server_tls_cipher_suites: Option<String>) -> TlsConfig {
    if !mode.use_https() {
        return TlsConfig::default();
    }
    let clients_ca = mode
        .use_known_ca_list()
        .then(|| root_dir().join("../../test_data/certificates/client_server/ca/ca.crt"));
    #[cfg(feature = "non-fips")]
    {
        TlsConfig {
            tls_p12_file: Some(
                root_dir().join(
                    "../../test_data/certificates/client_server/server/kmserver.acme.com.p12",
                ),
            ),
            tls_p12_password: Some("password".to_owned()),
            clients_ca_cert_file: clients_ca,
            tls_cipher_suites: server_tls_cipher_suites,
        }
    }
    #[cfg(not(feature = "non-fips"))]
    {
        TlsConfig {
            tls_cert_file: Some(
                root_dir().join(
                    "../../test_data/certificates/client_server/server/kmserver.acme.com.crt",
                ),
            ),
            tls_key_file: Some(
                root_dir().join(
                    "../../test_data/certificates/client_server/server/kmserver.acme.com.key",
                ),
            ),
            // Server cert is directly signed by root CA, no intermediate chain needed
            tls_chain_file: None,
            clients_ca_cert_file: clients_ca,
            tls_cipher_suites: server_tls_cipher_suites,
        }
    }
}

pub fn build_server_params_full(
    opts: BuildServerParamsOptions,
) -> Result<ServerParams, KmsClientError> {
    // Create a unique workspace path for each test to avoid race conditions
    let workspace_dir = if let Some(workspace_dir) = opts.workspace_dir {
        workspace_dir
    } else {
        std::env::temp_dir().join(format!("kms_test_workspace_{}", opts.port))
    };
    info!(
        "Using workspace dir for test KMS server: {}",
        workspace_dir.display()
    );

    // Database configuration is already isolated for redis-findex within get_db_config(port)
    let db_cfg = opts.db_config;

    let idp_auth = if opts.jwt.is_enabled() {
        // Issuer must match the JWTs embedded in test_kms_server::test_jwt
        get_multiple_jwt_config()
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
            root_data_path: workspace_dir,
            tmp_path: PathBuf::from("./"),
        },
        // db: opts.db_config,
        db: db_cfg,
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
        key_encryption_key: opts.key_encryption_key.clone(),
        default_unwrap_type: if opts.key_encryption_key.is_some() {
            Some(vec!["All"].into_iter().map(String::from).collect())
        } else {
            None
        },
        ..ClapConfig::default()
    };

    // If HSM options were provided, set them under the nested HSM config
    if let Some(h) = opts.hsm {
        clap.hsm = h;
    }

    trace!(
        "Building ServerParams for test harness with ClapConfig: {:#?}",
        clap
    );
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

    // Server requests client cert only if a clients CA is configured,
    // but the caller may explicitly suppress sending a client identity.
    let server_requests_client_cert = server_params
        .tls_params
        .as_ref()
        .and_then(|tls| tls.clients_ca_cert_pem.as_ref())
        .is_some();
    let caller_suppresses_client_cert =
        matches!(client_opts.client_cert, ClientCertPolicy::Suppress);
    let use_client_cert_auth = server_requests_client_cert && !caller_suppresses_client_cert;

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
        // Client certificate is mandatory when server requests it.
        // Respect any explicit client identity provided by the caller; otherwise, inject defaults.
        #[cfg(feature = "non-fips")]
        {
            let has_pkcs12 = http_conf.ssl_client_pkcs12_path.is_some();
            let has_pem = http_conf.ssl_client_pem_cert_path.is_some()
                && http_conf.ssl_client_pem_key_path.is_some();

            if !has_pkcs12 && !has_pem {
                // Inject default owner PKCS#12 only if caller didn't provide an identity
                let p = root_path.join(
                    "../../test_data/certificates/client_server/owner/owner.client.acme.com.p12",
                );
                http_conf.ssl_client_pkcs12_path = Some(path_to_string(&p)?);
                http_conf.ssl_client_pkcs12_password = Some("password".to_owned());
                // Ensure PEM fields are cleared in non-FIPS when using PKCS#12
                http_conf.ssl_client_pem_cert_path = None;
                http_conf.ssl_client_pem_key_path = None;
            } else if has_pkcs12 {
                // PKCS#12 provided by caller takes precedence; clear PEM to avoid ambiguity
                http_conf.ssl_client_pem_cert_path = None;
                http_conf.ssl_client_pem_key_path = None;
            } else {
                // PEM provided by caller in non-FIPS: honor it; ensure PKCS#12 is cleared
                http_conf.ssl_client_pkcs12_path = None;
                http_conf.ssl_client_pkcs12_password = None;
            }
        }
        #[cfg(not(feature = "non-fips"))]
        {
            // In FIPS mode, use PEM certificate and key; PKCS#12 must not be used.
            let has_pem = http_conf.ssl_client_pem_cert_path.is_some()
                && http_conf.ssl_client_pem_key_path.is_some();
            if !has_pem {
                // Inject default owner PEM identity only if caller didn't provide one
                let cert_p = root_path.join(
                    "../../test_data/certificates/client_server/owner/owner.client.acme.com.crt",
                );
                let key_p = root_path.join(
                    "../../test_data/certificates/client_server/owner/owner.client.acme.com.key",
                );
                http_conf.ssl_client_pem_cert_path = Some(path_to_string(&cert_p)?);
                http_conf.ssl_client_pem_key_path = Some(path_to_string(&key_p)?);
            }
            // Always clear PKCS#12 in FIPS
            http_conf.ssl_client_pkcs12_path = None;
            http_conf.ssl_client_pkcs12_password = None;
        }
    } else {
        // If server doesn't require client cert, don't send one
        http_conf.ssl_client_pkcs12_path = None;
        http_conf.ssl_client_pkcs12_password = None;
        http_conf.ssl_client_pem_cert_path = None;
        http_conf.ssl_client_pem_key_path = None;
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
    let is_https = conf.http_config.server_url.starts_with("https://");
    if is_https {
        // For HTTPS, client certificate is mandatory for test clients.
        // Use PKCS#12 in non-FIPS, and PEM cert/key in FIPS mode.
        // Always set the dedicated "user" identity (not the owner's).
        #[cfg(feature = "non-fips")]
        {
            let p = root_dir
                .join("../../test_data/certificates/client_server/user/user.client.acme.com.p12");
            conf.http_config.ssl_client_pkcs12_path = Some(path_to_string(&p)?);
            conf.http_config.ssl_client_pkcs12_password = Some("password".to_owned());
            conf.http_config.ssl_client_pem_cert_path = None;
            conf.http_config.ssl_client_pem_key_path = None;
        }
        #[cfg(not(feature = "non-fips"))]
        {
            let cert_p = root_dir
                .join("../../test_data/certificates/client_server/user/user.client.acme.com.crt");
            let key_p = root_dir
                .join("../../test_data/certificates/client_server/user/user.client.acme.com.key");
            conf.http_config.ssl_client_pem_cert_path = Some(path_to_string(&cert_p)?);
            conf.http_config.ssl_client_pem_key_path = Some(path_to_string(&key_p)?);
            conf.http_config.ssl_client_pkcs12_path = None;
            conf.http_config.ssl_client_pkcs12_password = None;
        }
    } else {
        // For HTTP, ensure no TLS identity is configured to avoid builder errors.
        conf.http_config.ssl_client_pkcs12_path = None;
        conf.http_config.ssl_client_pkcs12_password = None;
        conf.http_config.ssl_client_pem_cert_path = None;
        conf.http_config.ssl_client_pem_key_path = None;
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
#[cfg(feature = "non-fips")]
#[allow(clippy::unwrap_in_result)]
#[tokio::test]
async fn test_start_server() -> Result<(), KmsClientError> {
    let context = start_test_server_with_options(
        sqlite_db_config(None),
        DEFAULT_KMS_SERVER_PORT + 20,
        AuthenticationOptions::new(),
        None,
        None,
    )
    .await?;
    context.stop_server().await
}
