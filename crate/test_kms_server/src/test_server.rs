#![allow(
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::struct_excessive_bools,
    clippy::struct_field_names
)]
use std::{
    env,
    path::PathBuf,
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
        ClapConfig, HttpConfig, IdpAuthConfig, MainDBConfig, ServerParams, SocketServerConfig,
        TlsConfig,
    },
    start_kms_server::start_kms_server,
};
use tempfile::TempDir;
use tokio::sync::OnceCell;
use tracing::{info, log::error, trace, warn};

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
pub(crate) static ONCE_SERVER_WITH_PRIVILEGED_USERS: OnceCell<TestsContext> = OnceCell::const_new();

const DEFAULT_KMS_SERVER_PORT: u16 = 9998;

fn sqlite_db_config() -> MainDBConfig {
    trace!("TESTS: using sqlite");
    let tmp_dir = TempDir::new().unwrap();
    let file_path = tmp_dir.path().join("test_sqlite.db");
    // let file_path = PathBuf::from("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
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
    ONCE.get_or_try_init(|| {
        start_test_server_with_options(
            get_db_config(),
            DEFAULT_KMS_SERVER_PORT,
            AuthenticationOptions {
                use_jwt_token: false,
                use_https: false,
                use_known_ca_list: false,
                api_token_id: None,
                api_token: None,
                ..Default::default()
            },
            None,
            None,
            None,
        )
    })
    .await
    .unwrap()
}
/// TLS + certificate authentication
pub async fn start_default_test_kms_server_with_cert_auth() -> &'static TestsContext {
    trace!("Starting test server with cert auth");
    ONCE_SERVER_WITH_AUTH
        .get_or_try_init(|| {
            start_test_server_with_options(
                get_db_config(),
                DEFAULT_KMS_SERVER_PORT + 1,
                AuthenticationOptions {
                    use_jwt_token: false,
                    use_https: true,
                    use_known_ca_list: true,
                    api_token_id: None,
                    api_token: None,
                    ..Default::default()
                },
                None,
                None,
                None,
            )
        })
        .await
        .unwrap()
}
/// revocable key IDs
pub async fn start_default_test_kms_server_with_non_revocable_key_ids(
    non_revocable_key_id: Option<Vec<String>>,
) -> &'static TestsContext {
    trace!("Starting test server with non-revocable key ids");
    ONCE_SERVER_WITH_NON_REVOCABLE_KEY
        .get_or_try_init(|| {
            start_test_server_with_options(
                get_db_config(),
                DEFAULT_KMS_SERVER_PORT + 2,
                AuthenticationOptions {
                    use_jwt_token: false,
                    use_https: true,
                    use_known_ca_list: true,
                    api_token_id: None,
                    api_token: None,
                    ..Default::default()
                },
                non_revocable_key_id,
                None,
                None,
            )
        })
        .await
        .unwrap()
}

/// revocable key IDs
pub async fn start_default_test_kms_server_with_utimaco_hsm() -> &'static TestsContext {
    trace!("Starting test server with non-revocable key ids");
    ONCE_SERVER_WITH_HSM
        .get_or_try_init(|| {
            start_test_server_with_options(
                get_db_config(),
                DEFAULT_KMS_SERVER_PORT + 3,
                AuthenticationOptions {
                    use_jwt_token: false,
                    use_https: false,
                    use_known_ca_list: false,
                    api_token_id: None,
                    api_token: None,
                    ..Default::default()
                },
                None,
                Some(HsmOptions {
                    hsm_model: "utimaco".to_owned(),
                    hsm_admin: "admin".to_owned(),
                    hsm_slot: vec![0],
                    hsm_password: vec!["12345678".to_owned()],
                }),
                None,
            )
        })
        .await
        .unwrap()
}

/// Privileged users
pub async fn start_default_test_kms_server_with_privileged_users(
    privileged_users: Vec<String>,
) -> &'static TestsContext {
    trace!("Starting test server with privileged users");
    ONCE_SERVER_WITH_PRIVILEGED_USERS
        .get_or_try_init(|| {
            start_test_server_with_options(
                get_db_config(),
                DEFAULT_KMS_SERVER_PORT + 4,
                AuthenticationOptions {
                    use_jwt_token: true,
                    use_https: false,
                    use_known_ca_list: false,
                    api_token_id: None,
                    api_token: None,
                    ..Default::default()
                },
                None,
                None,
                Some(privileged_users),
            )
        })
        .await
        .unwrap()
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
        KmsClient::new_with_config(self.owner_client_config.clone())
            .expect("Can't create a KMS owner client")
    }

    #[must_use]
    pub fn get_user_client(&self) -> KmsClient {
        KmsClient::new_with_config(self.user_client_config.clone())
            .expect("Can't create a KMS user client")
    }

    pub async fn stop_server(self) -> Result<(), KmsClientError> {
        self.server_handle.stop(false).await;
        self.thread_handle
            .join()
            .map_err(|_e| kms_client_error!("failed joining the stop thread"))?
    }
}

#[derive(Default)]
pub struct AuthenticationOptions {
    pub use_jwt_token: bool,
    pub use_https: bool,
    pub use_known_ca_list: bool,
    pub pkcs12_client_cert: Option<String>,
    pub api_token_id: Option<String>,
    pub api_token: Option<String>,
    pub server_tls_cipher_suites: Option<String>,
    pub client_tls_cipher_suites: Option<String>,

    // Client credential configuration (all false by default)
    pub do_not_send_client_certificate: bool, // True = don't send client certificate even when required
    pub do_not_send_api_token: bool,          // True = do not send an API token
    pub do_not_send_jwt_token: bool,          // True = do not send a JWT token
}

pub struct HsmOptions {
    /// The HSM model.
    /// Trustway Proteccio and Utimaco General purpose HSMs are supported.
    pub hsm_model: String,

    /// The username of the HSM admin.
    /// The HSM admin can create objects on the HSM, destroy them, and potentially export them.
    pub hsm_admin: String,

    /// HSM slot number. The slots used must be listed.
    /// Repeat this option to specify multiple slots
    /// while specifying a password for each slot (or an empty string for no password)
    /// e.g.
    /// ```sh
    ///   --hsm_slot 1 --hsm_password password1 \
    ///   --hsm_slot 2 --hsm_password password2
    ///```
    pub hsm_slot: Vec<usize>,

    /// Password for the user logging in to the HSM Slot specified with `--hsm_slot`
    /// Provide an empty string for no password
    /// see `--hsm_slot` for more information
    pub hsm_password: Vec<String>,
}

/// Start a KMS server in a thread with the given options
pub async fn start_test_server_with_options(
    db_config: MainDBConfig,
    port: u16,
    authentication_options: AuthenticationOptions,
    non_revocable_key_id: Option<Vec<String>>,
    hsm_options: Option<HsmOptions>,
    privileged_users: Option<Vec<String>>,
) -> Result<TestsContext, KmsClientError> {
    let server_params = generate_server_params(
        db_config.clone(),
        port,
        &authentication_options,
        non_revocable_key_id,
        &hsm_options,
        privileged_users,
    )?;

    // Create a (object owner) conf
    let owner_client_config = generate_owner_conf(&server_params, &authentication_options)?;

    info!(" -- Test KMS server configuration: {:#?}", server_params);

    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    // generate a user conf
    let user_client_config =
        generate_user_conf(&owner_client_config, authentication_options.use_jwt_token)
            .expect("Can't generate user conf");
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

fn generate_tls_config(
    use_https: bool,
    use_known_ca_list: bool,
    tls_cipher_suites: Option<String>,
) -> TlsConfig {
    // This is the crate root dir
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut tls_config = TlsConfig::default();
    if use_https {
        tls_config.tls_p12_file = Some(
            root_dir
                .join("../../test_data/certificates/client_server/server/kmserver.acme.com.p12"),
        );
        assert!(
            tls_config.tls_p12_file.as_ref().unwrap().exists(),
            "File not found: {}",
            tls_config.tls_p12_file.unwrap().display()
        );
        tls_config.tls_p12_password = Some("password".to_owned());
        if use_known_ca_list {
            tls_config.clients_ca_cert_file = Some(
                root_dir.join("../../test_data/certificates/client_server/ca/stack_of_ca.pem"),
            );
            assert!(tls_config.clients_ca_cert_file.as_ref().unwrap().exists());
        }
        tls_config.tls_cipher_suites = tls_cipher_suites;
    }
    tls_config
}

fn generate_server_params(
    db_config: MainDBConfig,
    port: u16,
    authentication_options: &AuthenticationOptions,
    non_revocable_key_id: Option<Vec<String>>,
    hsm_options: &Option<HsmOptions>,
    privileged_users: Option<Vec<String>>,
) -> Result<ServerParams, KmsClientError> {
    // Configure the server
    let clap_config = ClapConfig {
        idp_auth: if authentication_options.use_jwt_token {
            get_auth0_jwt_config()
        } else {
            IdpAuthConfig::default()
        },
        socket_server: SocketServerConfig {
            //Start the socket server automatically if both HTTPS and client cert authentication are used
            socket_server_start: authentication_options.use_https
                && authentication_options.use_known_ca_list,
            socket_server_port: port + 100,
            ..Default::default()
        },
        db: db_config,
        tls: generate_tls_config(
            authentication_options.use_https,
            authentication_options.use_known_ca_list,
            authentication_options.server_tls_cipher_suites.clone(),
        ),
        http: HttpConfig {
            port,
            api_token_id: authentication_options.api_token_id.clone(),
            ..HttpConfig::default()
        },
        non_revocable_key_id,
        hsm_admin: hsm_options
            .as_ref()
            .map_or_else(String::new, |h| h.hsm_admin.clone()),
        hsm_model: hsm_options
            .as_ref()
            .map_or_else(String::new, |h| h.hsm_model.clone()),
        hsm_slot: hsm_options
            .as_ref()
            .map_or_else(Vec::new, |h| h.hsm_slot.clone()),
        hsm_password: hsm_options
            .as_ref()
            .map_or_else(Vec::new, |h| h.hsm_password.clone()),
        privileged_users,
        ..ClapConfig::default()
    };
    ServerParams::try_from(clap_config)
        .map_err(|e| KmsClientError::Default(format!("failed initializing the server config: {e}")))
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
    authentication_options: &AuthenticationOptions,
) -> Result<KmsClientConfig, KmsClientError> {
    // This creates a root dir
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let gmail_api_conf: Option<GmailApiConf> = env::var("TEST_GMAIL_API_CONF")
        .ok()
        .and_then(|config| serde_json::from_str(&config).ok());

    let use_client_cert_auth = server_params
        .tls_params
        .as_ref()
        .and_then(|tls| tls.clients_ca_cert_pem.as_ref())
        .is_some()
        && !authentication_options.do_not_send_client_certificate;

    let use_jwt_token = server_params.identity_provider_configurations.is_some()
        && !authentication_options.do_not_send_jwt_token;

    let use_api_token =
        authentication_options.api_token.is_some() && !authentication_options.do_not_send_api_token;

    let conf = KmsClientConfig {
        http_config: HttpClientConfig {
            server_url: if server_params.tls_params.is_some() {
                format!("https://localhost:{}", server_params.http_port)
            } else {
                format!("http://localhost:{}", server_params.http_port)
            },
            accept_invalid_certs: true,
            access_token: set_access_token(
                use_jwt_token,
                use_api_token,
                Some(AUTH0_TOKEN.to_owned()),
                authentication_options.api_token.clone(),
            ),
            ssl_client_pkcs12_path: if use_client_cert_auth {
                if let Some(pkcs12_client_cert) = authentication_options.pkcs12_client_cert.as_ref()
                {
                    Some(pkcs12_client_cert.clone())
                } else {
                    let p = root_dir.join(
                        "../../test_data/certificates/client_server/owner/owner.client.acme.com.\
                         p12",
                    );
                    Some(
                        p.to_str()
                            .ok_or_else(|| {
                                KmsClientError::Default("Can't convert path to string".to_owned())
                            })?
                            .to_owned(),
                    )
                }
            } else {
                None
            },
            ssl_client_pkcs12_password: if use_client_cert_auth {
                Some("password".to_owned())
            } else {
                None
            },
            cipher_suites: authentication_options.client_tls_cipher_suites.clone(),
            ..HttpClientConfig::default()
        },
        gmail_api_conf,
        print_json: None,
    };

    Ok(conf)
}

/// Generate a user configuration for user.client@acme.com and return the file path
fn generate_user_conf(
    owner_client_conf: &KmsClientConfig,
    use_jwt_token: bool,
) -> Result<KmsClientConfig, KmsClientError> {
    // This creates root dir
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut conf = owner_client_conf.clone();
    conf.http_config.ssl_client_pkcs12_path = {
        let p = root_dir
            .join("../../test_data/certificates/client_server/user/user.client.acme.com.p12");
        Some(
            p.to_str()
                .ok_or_else(|| KmsClientError::Default("Can't convert path to string".to_owned()))?
                .to_owned(),
        )
    };
    conf.http_config.ssl_client_pkcs12_password = Some("password".to_owned());
    conf.http_config.access_token = set_access_token(
        use_jwt_token,
        false,
        Some(AUTH0_TOKEN_USER.to_owned()),
        None,
    );

    Ok(conf)
}

#[cfg(test)]
#[tokio::test]
async fn test_start_server() -> Result<(), KmsClientError> {
    let context = start_test_server_with_options(
        sqlite_db_config(),
        DEFAULT_KMS_SERVER_PORT + 20,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: true,
            use_known_ca_list: true,
            api_token_id: None,
            api_token: None,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    context.stop_server().await
}
