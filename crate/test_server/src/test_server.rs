use std::{
    env,
    path::PathBuf,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

use actix_server::ServerHandle;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use cosmian_kms_client::{
    client_bail, client_error,
    cosmian_kmip::crypto::{secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH},
    write_json_object_to_file, ClientConf, ClientError, GmailApiConf, KmsClient,
};
use cosmian_kms_server::{
    config::{ClapConfig, DBConfig, HttpConfig, HttpParams, JwtAuthConfig, ServerParams},
    core::extra_database_params::ExtraDatabaseParams,
    kms_server::start_kms_server,
};
use tempfile::TempDir;
use tokio::sync::OnceCell;
use tracing::{info, trace};

use crate::test_jwt::{get_auth0_jwt_config, AUTH0_TOKEN};

/// In order to run most tests in parallel,
/// we use that to avoid to try to start N KMS servers (one per test)
/// with a default configuration.
/// Otherwise, we get: "Address already in use (os error 98)"
/// for N-1 tests.
pub(crate) static ONCE: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_AUTH: OnceCell<TestsContext> = OnceCell::const_new();

fn sqlite_db_config() -> DBConfig {
    trace!("TESTS: using sqlite");
    let tmp_dir = TempDir::new().unwrap();
    let file_path = tmp_dir.path().join("test_sqlite.db");
    // let file_path = PathBuf::from("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
    }
    DBConfig {
        database_type: Some("sqlite".to_string()),
        clear_database: true,
        sqlite_path: file_path,
        ..DBConfig::default()
    }
}

fn sqlite_enc_db_config() -> DBConfig {
    trace!("TESTS: using sqlite-enc");
    let tmp_dir = TempDir::new().unwrap();
    // SQLCipher uses a directory
    let dir_path = tmp_dir.path().join("test_sqlite_enc.db");
    if dir_path.exists() {
        std::fs::remove_dir_all(&dir_path).unwrap();
    }
    std::fs::create_dir_all(&dir_path).unwrap();
    DBConfig {
        database_type: Some("sqlite-enc".to_string()),
        clear_database: true,
        sqlite_path: dir_path,
        ..DBConfig::default()
    }
}

fn mysql_db_config() -> DBConfig {
    trace!("TESTS: using mysql");
    let mysql_url = option_env!("KMS_MYSQL_URL")
        .unwrap_or("mysql://kms:kms@localhost:3306/kms")
        .to_string();
    DBConfig {
        database_type: Some("mysql".to_string()),
        clear_database: true,
        database_url: Some(mysql_url),
        ..DBConfig::default()
    }
}

fn postgres_db_config() -> DBConfig {
    trace!("TESTS: using postgres");
    let postgresql_url = option_env!("KMS_POSTGRES_URL")
        .unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms")
        .to_string();
    DBConfig {
        database_type: Some("postgresql".to_string()),
        clear_database: true,
        database_url: Some(postgresql_url),
        ..DBConfig::default()
    }
}

fn redis_findex_db_config() -> DBConfig {
    trace!("TESTS: using redis-findex");
    let url = if let Ok(var_env) = env::var("REDIS_HOST") {
        format!("redis://{var_env}:6379")
    } else {
        "redis://localhost:6379".to_owned()
    };
    DBConfig {
        database_type: Some("redis-findex".to_string()),
        clear_database: true,
        database_url: Some(url),
        sqlite_path: Default::default(),
        redis_master_password: Some("password".to_string()),
        redis_findex_label: Some("label".to_string()),
    }
}

fn get_db_config() -> DBConfig {
    env::var_os("KMS_TEST_DB").map_or_else(sqlite_enc_db_config, |v| {
        match v.to_str().unwrap_or("") {
            "redis-findex" => redis_findex_db_config(),
            "mysql" => mysql_db_config(),
            "sqlite" => sqlite_db_config(),
            "postgresql" => postgres_db_config(),
            _ => sqlite_enc_db_config(),
        }
    })
}

/// Start a test KMS server in a thread with the default options:
/// No TLS, no certificate authentication
pub async fn start_default_test_kms_server() -> &'static TestsContext {
    trace!("Starting default test server");
    ONCE.get_or_try_init(|| {
        start_test_server_with_options(
            get_db_config(),
            9990,
            AuthenticationOptions {
                use_jwt_token: false,
                use_https: false,
                use_client_cert: false,
                api_token_id: None,
                api_token: None,
            },
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
                9991,
                AuthenticationOptions {
                    use_jwt_token: false,
                    use_https: true,
                    use_client_cert: true,
                    api_token_id: None,
                    api_token: None,
                },
            )
        })
        .await
        .unwrap()
}

pub struct TestsContext {
    pub owner_client_conf_path: String,
    pub user_client_conf_path: String,
    pub owner_client_conf: ClientConf,
    pub server_handle: ServerHandle,
    pub thread_handle: JoinHandle<Result<(), ClientError>>,
}

impl TestsContext {
    pub async fn stop_server(self) -> Result<(), ClientError> {
        self.server_handle.stop(false).await;
        self.thread_handle
            .join()
            .map_err(|_e| client_error!("failed joining th stop thread"))?
    }
}

pub struct AuthenticationOptions {
    pub use_jwt_token: bool,
    pub use_https: bool,
    pub use_client_cert: bool,
    pub api_token_id: Option<String>,
    pub api_token: Option<String>,
}

/// Start a KMS server in a thread with the given options
pub async fn start_test_server_with_options(
    db_config: DBConfig,
    port: u16,
    authentication_options: AuthenticationOptions,
) -> Result<TestsContext, ClientError> {
    cosmian_logger::log_utils::log_init(None);
    let server_params = generate_server_params(db_config.clone(), port, &authentication_options)?;

    // Create a (object owner) conf
    let (owner_client_conf_path, mut owner_client_conf) =
        generate_owner_conf(&server_params, authentication_options.api_token.clone())?;
    let kms_client = owner_client_conf.initialize_kms_client(None, None, false)?;

    info!(
        "Starting KMS test server at URL: {} with server params {:?}",
        owner_client_conf.kms_server_url, &server_params
    );

    let (server_handle, thread_handle) = start_test_kms_server(server_params);

    // wait for the server to be up
    wait_for_server_to_start(&kms_client)
        .await
        .expect("server timeout");

    if db_config.database_type.clone().unwrap() == "sqlite-enc" {
        // Configure a database and create the kms json file
        let database_secret = kms_client.new_database().await?;

        // Rewrite the conf with the correct database secret
        owner_client_conf.kms_database_secret = Some(database_secret);
        write_json_object_to_file(&owner_client_conf, &owner_client_conf_path)
            .expect("Can't write owner CLI conf path");
    }

    // generate a user conf
    let user_client_conf_path =
        generate_user_conf(port, &owner_client_conf).expect("Can't generate user conf");

    Ok(TestsContext {
        owner_client_conf_path,
        user_client_conf_path,
        owner_client_conf,
        server_handle,
        thread_handle,
    })
}

/// Start a test KMS server with the given config in a separate thread
fn start_test_kms_server(
    server_params: ServerParams,
) -> (ServerHandle, JoinHandle<Result<(), ClientError>>) {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the KMS Server future
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(start_kms_server(server_params, Some(tx)))
            .map_err(|e| ClientError::UnexpectedError(e.to_string()))
    });
    trace!("Waiting for test KMS server to start...");
    let server_handle = rx
        .recv_timeout(Duration::from_secs(25))
        .expect("Can't get test KMS server handle after 25 seconds");
    trace!("... got handle ...");
    (server_handle, thread_handle)
}

/// Wait for the server to start by reading the version
async fn wait_for_server_to_start(kms_client: &KmsClient) -> Result<(), ClientError> {
    // Depending on the running environment, the server could take a bit of time to start
    // We try to query it with a dummy request until be sure it is started.
    let mut retry = true;
    let mut timeout = 5;
    let mut waiting = 1;
    while retry {
        info!("...checking if the server is up...");
        let result = kms_client.version().await;
        if result.is_err() {
            timeout -= 1;
            retry = timeout >= 0;
            if retry {
                info!("The server is not up yet, retrying in {waiting}s... ({result:?}) ",);
                thread::sleep(Duration::from_secs(waiting));
                waiting *= 2;
            } else {
                info!("The server is still not up, stop trying");
                client_bail!("Can't start the kms server to run tests");
            }
        } else {
            info!("UP!");
            retry = false;
        }
    }
    Ok(())
}

fn generate_http_config(
    port: u16,
    use_https: bool,
    use_client_cert: bool,
    api_token_id: Option<String>,
) -> HttpConfig {
    // This create root dir
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    if use_https {
        if use_client_cert {
            HttpConfig {
                port,
                https_p12_file: Some(root_dir.join("certificates/server/kmserver.acme.com.p12")),
                https_p12_password: Some("password".to_owned()),
                authority_cert_file: Some(root_dir.join("certificates/server/ca.crt")),
                api_token_id,
                ..HttpConfig::default()
            }
        } else {
            HttpConfig {
                port,
                https_p12_file: Some(root_dir.join("certificates/server/kmserver.acme.com.p12")),
                https_p12_password: Some("password".to_owned()),
                api_token_id,
                ..HttpConfig::default()
            }
        }
    } else {
        HttpConfig {
            port,
            api_token_id,
            ..HttpConfig::default()
        }
    }
}

fn generate_server_params(
    db_config: DBConfig,
    port: u16,
    authentication_options: &AuthenticationOptions,
) -> Result<ServerParams, ClientError> {
    // Configure the server
    let clap_config = ClapConfig {
        auth: if authentication_options.use_jwt_token {
            get_auth0_jwt_config()
        } else {
            JwtAuthConfig::default()
        },
        db: db_config,
        http: generate_http_config(
            port,
            authentication_options.use_https,
            authentication_options.use_client_cert,
            authentication_options.api_token_id.clone(),
        ),
        ..ClapConfig::default()
    };
    ServerParams::try_from(clap_config)
        .map_err(|e| ClientError::Default(format!("failed initializing the server config: {e}")))
}

fn set_access_token(server_params: &ServerParams, api_token: Option<String>) -> Option<String> {
    if server_params.identity_provider_configurations.is_some() {
        trace!("Setting access token for JWT: {AUTH0_TOKEN:?}");
        Some(AUTH0_TOKEN.to_string())
    } else if api_token.is_some() {
        trace!("Setting access token for API: {api_token:?}");
        api_token
    } else {
        None
    }
}

fn generate_owner_conf(
    server_params: &ServerParams,
    api_token: Option<String>,
) -> Result<(String, ClientConf), ClientError> {
    // This create root dir
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Create a conf
    let owner_client_conf_path = format!("/tmp/owner_kms_{}.json", server_params.port);

    let gmail_api_conf: Option<GmailApiConf> = std::env::var("TEST_GMAIL_API_CONF")
        .ok()
        .and_then(|config| serde_json::from_str(&config).ok());

    let owner_client_conf = ClientConf {
        kms_server_url: if matches!(server_params.http_params, HttpParams::Https(_)) {
            format!("https://0.0.0.0:{}", server_params.port)
        } else {
            format!("http://0.0.0.0:{}", server_params.port)
        },
        accept_invalid_certs: true,
        kms_access_token: set_access_token(server_params, api_token),
        ssl_client_pkcs12_path: if server_params.authority_cert_file.is_some() {
            #[cfg(not(target_os = "macos"))]
            let p = root_dir.join("certificates/owner/owner.client.acme.com.p12");
            #[cfg(target_os = "macos")]
            let p = root_dir.join("certificates/owner/owner.client.acme.com.old.format.p12");
            Some(
                p.to_str()
                    .ok_or_else(|| ClientError::Default("Can't convert path to string".to_owned()))?
                    .to_string(),
            )
        } else {
            None
        },
        ssl_client_pkcs12_password: if server_params.authority_cert_file.is_some() {
            Some("password".to_owned())
        } else {
            None
        },
        gmail_api_conf,

        // We use the private key since the private key is the public key with additional information.
        ..ClientConf::default()
    };
    // write the conf to a file
    write_json_object_to_file(&owner_client_conf, &owner_client_conf_path)
        .expect("Can't write owner CLI conf path");

    Ok((owner_client_conf_path, owner_client_conf))
}

/// Generate a user configuration for user.client@acme.com and return the file path
fn generate_user_conf(port: u16, owner_client_conf: &ClientConf) -> Result<String, ClientError> {
    // This create root dir
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut user_conf = owner_client_conf.clone();
    user_conf.ssl_client_pkcs12_path = {
        #[cfg(not(target_os = "macos"))]
        let p = root_dir.join("certificates/user/user.client.acme.com.p12");
        #[cfg(target_os = "macos")]
        let p = root_dir.join("certificates/user/user.client.acme.com.old.format.p12");
        Some(
            p.to_str()
                .ok_or_else(|| ClientError::Default("Can't convert path to string".to_owned()))?
                .to_string(),
        )
    };
    user_conf.ssl_client_pkcs12_password = Some("password".to_owned());

    // write the user conf
    let user_conf_path = format!("/tmp/user_kms_{port}.json");
    write_json_object_to_file(&user_conf, &user_conf_path)?;

    // return the path
    Ok(user_conf_path)
}

/// Generate an invalid configuration for sqlite-enc
/// by changing the database secret  and return the file path
#[must_use]
pub fn generate_invalid_conf(correct_conf: &ClientConf) -> String {
    // Create a new database key
    let db_key = Secret::<AES_256_GCM_KEY_LENGTH>::new_random()
        .expect("Failed to generate rand bytes for generate_invalid_conf");

    let mut invalid_conf = correct_conf.clone();
    // and a temp file
    let invalid_conf_path = "/tmp/invalid_conf.json".to_owned();
    // Generate a wrong token with valid group id
    let secrets = b64
        .decode(
            correct_conf
                .kms_database_secret
                .as_ref()
                .expect("missing database secret")
                .clone(),
        )
        .expect("Can't decode token");
    let mut secrets =
        serde_json::from_slice::<ExtraDatabaseParams>(&secrets).expect("Can't deserialize token");
    secrets.key = db_key; // bad secret
    let token = b64.encode(serde_json::to_string(&secrets).expect("Can't encode token"));
    invalid_conf.kms_database_secret = Some(token);
    write_json_object_to_file(&invalid_conf, &invalid_conf_path)
        .expect("Can't write CONF_PATH_BAD_KEY");
    invalid_conf_path
}

#[cfg(test)]
#[tokio::test]
async fn test_start_server() -> Result<(), ClientError> {
    let context = start_test_server_with_options(
        sqlite_enc_db_config(),
        9990,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: true,
            use_client_cert: true,
            api_token_id: None,
            api_token: None,
        },
    )
    .await?;
    context.stop_server().await
}
