use std::{
    path::PathBuf,
    process::Command,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

use actix_server::ServerHandle;
use assert_cmd::prelude::{CommandCargoExt, OutputAssertExt};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use cosmian_kms_server::{
    config::{
        db::DBConfig, http::HTTPConfig, jwt_auth_config::JwtAuthConfig, ClapConfig, ServerConfig,
    },
    error::KmsError,
    result::KResult,
    start_kms_server,
};
use cosmian_kms_utils::types::ExtraDatabaseParams;
use tokio::sync::OnceCell;
use tracing::trace;

use super::extract_uids::extract_database_secret;
use crate::{
    actions::shared::utils::write_to_json_file,
    cli_bail,
    config::{CliConf, KMS_CLI_CONF_ENV},
    error::CliError,
    tests::PROG_NAME,
};

// Test auth0 Config
<<<<<<< HEAD
const AUTH0_JWT_ISSUER_URI: &str = "https://kms-cosmian.eu.auth0.com";
=======
const AUTH0_JWT_ISSUER_URI: &str = "https://console-dev.eu.auth0.com/";
const AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlJqaTdXRDRaZWJZaVh0bXFoOWUyeSJ9.eyJuaWNrbmFtZSI6ImFsaWNlIiwibmFtZSI6ImFsaWNlQGNvc21pYW4uY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyLzUzYTU2MTY5MmFiZWRkZWI4NTE5YzFjNjMxNTczNzA3P3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGYWwucG5nIiwidXBkYXRlZF9hdCI6IjIwMjMtMDEtMjdUMTQ6MDA6MjEuNjUyWiIsImVtYWlsIjoiYWxpY2VAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9jb25zb2xlLWRldi5ldS5hdXRoMC5jb20vIiwiYXVkIjoiYngyV2xMclM3cXIzNWl5TnFVVlRzOWpNbzgzNG84bUMiLCJpYXQiOjE2NzQ4MjgyOTIsImV4cCI6MTY3NDg2NDI5Miwic3ViIjoiYXV0aDB8NjMwYzkyMmEwNjc3ZjVmOTUzMjJhYjVlIiwic2lkIjoiaFV1MzlGNlhuX0VYQ1ljcldNQUtBWndLYTdlLWlpczQiLCJub25jZSI6ImNtOTZTWEpZY1U1SE9FdFJVV1oxU3pOVFpHSXpVRlJ6V1RGNWRVcDJVa0o1VDJjd1dtWmthVll4YXc9PSJ9.jTV4sFgXAoOIA7d_Xz4W8f8GmGwCqFkO0WVuuH6HyPxf093uWzo0DdjGY9jG7T3Jhxgf9uDAZEh-6txb43_uPGpt2N3uGn00B7XGI05RqzSgCX7e2pVU6SiFpRZF6uchdHIIxPjmAqEheZ3fTeQndg2BfEuO0XTUH-Og3w_hsnK0k20B1zDeZc1XRZ_UEqkmqRym66f3tbj1QbDb-Ogtf1t5AupRRDzTR8VgC6Z6PW5sTCpdJ49Zd-gHNZ7yKJOTw39wG26791uKganovJDqYL12UfForCBrXNE-6QtmUT-Adm_duKezAqEKm_9cZI4BTNpy3tLr2vW9HMeaUtr9hQ";
>>>>>>> fe5c0eb (reworking TLSS tests)

pub fn get_auth0_jwt_config() -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_issuer_uri: Some(AUTH0_JWT_ISSUER_URI.to_owned()),
        jwks_uri: None,
        jwt_audience: None,
    }
}

/// We use that to avoid to try to start N servers (one per test)
/// Otherwise we got: "Address already in use (os error 98)"
/// for N-1 tests.
pub static ONCE: OnceCell<TestsContext> = OnceCell::const_new();

pub struct TestsContext {
    pub cli_conf_path: String,
    pub cli_conf: CliConf,
    pub server_handle: ServerHandle,
    pub thread_handle: thread::JoinHandle<KResult<()>>,
}

impl TestsContext {
    pub async fn stop_server(self) {
        self.server_handle.stop(false).await;
        self.thread_handle.join().unwrap().unwrap();
        println!("Server stopped\n");
    }
}

/// Start a server with the given config in a separate thread
async fn start_server(
    server_config: ServerConfig,
) -> Result<(ServerHandle, JoinHandle<Result<(), KmsError>>), CliError> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();
    let tokio_handle = tokio::runtime::Handle::current();
    let thread_handle =
        thread::spawn(move || tokio_handle.block_on(start_kms_server(server_config, Some(tx))));
    trace!("Waiting for server to start...");
    let server_handle = rx
        .recv_timeout(Duration::from_secs(25))
        .expect("Can't get server handle after 25 seconds");
    trace!("... got handle ...");
    Ok((server_handle, thread_handle))
}

/// Create a new database and return the database secret
pub fn fetch_version(cli_conf_path: &str) -> Result<String, CliError> {
    // Configure a database and create the kms json file
    let mut cmd = Command::cargo_bin(PROG_NAME).expect("Can't execute the server-version command");
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("server-version");

    let success = cmd.assert().success();
    let output = success.get_output();
    let version: &str = std::str::from_utf8(&output.stdout).expect("Can't recover command output");

    Ok(version.to_owned())
}

/// Wait for the server to start by reading the version
async fn wait_for_server_to_start(cli_conf_path: &str) -> Result<(), CliError> {
    // Depending on the running environment, the server could take a bit of time to start
    // We try to query it with a dummy request until be sure it is started.
    let mut retry = true;
    let mut timeout = 5;
    let mut waiting = 1;
    while retry {
        print!("...checking if the server is up...");
        let result = fetch_version(cli_conf_path);

        if result.is_err() {
            timeout -= 1;
            retry = timeout >= 0;
            if retry {
                println!("The server is not up yet, retrying in {waiting}s... ({result:?}) ",);
                thread::sleep(std::time::Duration::from_secs(waiting));
                waiting *= 2;
            } else {
                println!("The server is still not up, stop trying");
                cli_bail!("Can't start the kms server to run tests");
            }
        } else {
            println!("UP!");
            retry = false;
        }
    }
    Ok(())
}

/// Create a new database and return the database secret
pub fn create_new_database(cli_conf_path: &str) -> Result<String, CliError> {
    // Configure a database and create the kms json file
    let mut cmd = Command::cargo_bin(PROG_NAME).expect("Can't execute new database command");
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("new-database");

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout).expect("Can't recover command output");

    // Get the secret
    let database_secret =
        extract_database_secret(stdout).expect("Can't extract database secret from cmd output");

    Ok(database_secret.to_owned())
}

/// Start a test server with the default options: JWT authentication and encrypted database, no TLS
pub async fn init_test_server() -> TestsContext {
    init_test_server_options(9990, true, false, false).await
}

/// Start a server in a thread with the given options
pub async fn init_test_server_options(
    port: u16,
    use_jwt_token: bool,
    use_https: bool,
    use_client_cert: bool,
) -> TestsContext {
    let _ = env_logger::builder().is_test(true).try_init();
    let cli_conf_path = format!("/tmp/kms_{port}.json");

    // Configure the serveur
    let clap_config = ClapConfig {
        auth: if use_jwt_token {
            get_auth0_jwt_config()
        } else {
            JwtAuthConfig::default()
        },
        db: DBConfig {
            database_type: "sqlite-enc".to_string(),
            ..Default::default()
        },
        http: if use_https {
            if use_client_cert {
                HTTPConfig {
                    port,
                    https_p12_file: Some(PathBuf::from(
                        "test_data/certificates/kmserver.acme.com.p12",
                    )),
                    https_p12_password: "password".to_string(),
                    authority_cert_file: Some(PathBuf::from("test_data/certificates/ca.crt")),
                    ..Default::default()
                }
            } else {
                HTTPConfig {
                    port,
                    https_p12_file: Some(PathBuf::from(
                        "test_data/certificates/kmserver.acme.com.p12",
                    )),
                    https_p12_password: "password".to_string(),
                    ..Default::default()
                }
            }
        } else {
            HTTPConfig {
                port,
                ..Default::default()
            }
        },
        ..Default::default()
    };
    let server_config = ServerConfig::try_from(&clap_config)
        .await
        .map_err(|e| format!("failed initializing the server config: {e}"))
        .unwrap();

    // Generate a CLI Conf.
    // We will update it later by appending the database secret
    let mut cli_conf = CliConf {
        kms_server_url: if use_https {
            format!("https://0.0.0.0:{port}")
        } else {
            format!("http://0.0.0.0:{port}")
        },
        accept_invalid_certs: true,
        kms_access_token: if use_jwt_token {
            Some(AUTH0_TOKEN.to_string())
        } else {
            None
        },
        ssl_client_pkcs12_path: if use_client_cert {
            Some("test_data/certificates/owner.client.acme.com.p12".to_string())
        } else {
            None
        },
        ssl_client_pkcs12_password: if use_client_cert {
            Some("password".to_string())
        } else {
            None
        },
        ..Default::default()
    };
    // write the conf to a file
    write_to_json_file(&cli_conf, &cli_conf_path).expect("Can't write CLI conf path");

    // Start the server on a independent thread
    println!(
        "Starting test server at URL: {} with server config {:?}",
        cli_conf.kms_server_url, &clap_config
    );
    let (server_handle, thread_handle) = start_server(server_config)
        .await
        .expect("Can't start server");

    // wait for the server to be up
    wait_for_server_to_start(&cli_conf_path)
        .await
        .expect("server timeout");

    // Configure a database and create the kms json file
    let database_secret =
        create_new_database(&cli_conf_path).expect("failed configuring a database");

    // Rewrite the conf with the correct database secret
    cli_conf.kms_database_secret = Some(database_secret);
    write_to_json_file(&cli_conf, &cli_conf_path).expect("Can't write CLI conf path");

    TestsContext {
        cli_conf_path,
        cli_conf,
        server_handle,
        thread_handle,
    }
}

/// Generate an invalid configuration by changin the database secret  and return the file path
pub(crate) fn generate_invalid_conf(correct_conf: &CliConf) -> String {
    let mut invalid_conf = correct_conf.clone();
    let invalid_conf_path = "/tmp/kms_bad_key.bad";
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
        serde_json::from_slice::<ExtraDatabaseParams>(&secrets).expect("Can't deserialized token");
    secrets.key = [42_u8; 32]; // bad secret
    let token = b64.encode(serde_json::to_string(&secrets).expect("Can't encode token"));
    invalid_conf.kms_database_secret = Some(token);
    write_to_json_file(&invalid_conf, &invalid_conf_path.to_string())
        .expect("Can't write CONF_PATH_BAD_KEY");
    invalid_conf_path.to_string()
}
