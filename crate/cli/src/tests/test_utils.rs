use std::{
    fs::File,
    io::{BufReader, BufWriter, Read},
    path::PathBuf,
    process::Command,
};

use assert_cmd::prelude::{CommandCargoExt, OutputAssertExt};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use cosmian_kms_server::config::{
    db::DBConfig, http::HTTPConfig, init_config, jwt_auth_config::JwtAuthConfig, Config,
};
use cosmian_kms_utils::types::ExtraDatabaseParams;
use reqwest::Identity;
use tokio::sync::OnceCell;
#[cfg(not(feature = "staging"))]
use {cosmian_kms_server::start_kms_server, reqwest::ClientBuilder, std::thread};

use super::{utils::extract_uids::extract_database_secret, CONF_PATH, PROG_NAME};
use crate::{
    config::{CliConf, KMS_CLI_CONF_ENV},
    error::CliError,
    tests::CONF_PATH_BAD_KEY,
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
pub static ONCE: OnceCell<()> = OnceCell::const_new();

#[cfg(not(feature = "staging"))]
#[tokio::main]
pub async fn start_test_server() {
    start_kms_server().await.unwrap();
}

/// If staging feature is enabled, it relies on a remote server running in a enclave
/// Otherwise it starts a local server
pub async fn init_test_server() {
    init_test_server_options(true, false, false).await
}
pub async fn init_test_server_options(use_jwt_token: bool, use_https: bool, use_client_cert: bool) {
    let _ = env_logger::builder().is_test(true).try_init();
    // Configure the serveur
    let config = Config {
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
                    https_p12_file: Some(PathBuf::from(
                        "test_data/certificates/kmserver.cosmian.com.p12",
                    )),
                    https_p12_password: "password".to_string(),
                    authority_cert_file: Some(PathBuf::from("test_data/certificates/ca.crt")),
                    ..Default::default()
                }
            } else {
                HTTPConfig {
                    https_p12_file: Some(PathBuf::from(
                        "test_data/certificates/kmserver.cosmian.com.p12",
                    )),
                    https_p12_password: "password".to_string(),
                    ..Default::default()
                }
            }
        } else {
            HTTPConfig::default()
        },
        ..Default::default()
    };
    init_config(&config)
        .await
        .map_err(|e| format!("failed initializing the server config: {e}"))
        .unwrap();

    // Read the conf. We will update it later by appending the secret token
    let mut cli_conf = CliConf {
        kms_server_url: if use_https {
            "https://localhost:9998".to_string()
        } else {
            "http://localhost:9998".to_string()
        },
        accept_invalid_certs: true,
        kms_access_token: if use_jwt_token {
            Some(AUTH0_TOKEN.to_string())
        } else {
            None
        },
        ssl_client_pkcs12_path: if use_client_cert {
            Some("test_data/certificates/client.cosmian.com.p12".to_string())
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
    //serde_json::from_reader(BufReader::new(file)).expect("cannot deserialize CLI cfg");

    println!("Using: {}", cli_conf.kms_server_url);

    #[cfg(not(feature = "staging"))]
    {
        async fn fetch_version(cli_conf: &CliConf) -> Result<reqwest::Response, CliError> {
            let builder = ClientBuilder::new();
            // If a PKCS12 file is provided, use it to build the client
            let builder = match &cli_conf.ssl_client_pkcs12_path {
                Some(ssl_client_pkcs12) => {
                    let mut pkcs12 = BufReader::new(File::open(ssl_client_pkcs12)?);
                    let mut pkcs12_bytes = vec![];
                    pkcs12.read_to_end(&mut pkcs12_bytes)?;
                    let pkcs12 = Identity::from_pkcs12_der(
                        &pkcs12_bytes,
                        cli_conf.ssl_client_pkcs12_password.as_deref().unwrap_or(""),
                    )?;
                    builder.identity(pkcs12)
                }
                None => builder,
            };
            let response = builder
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap()
                .post(format!("{}/version", &cli_conf.kms_server_url))
                .json("{}")
                .send()
                .await?;
            Ok(response)
        }

        if fetch_version(&cli_conf).await.is_ok() {
            // a server is already running, use that
            println!("Using already running server");
            return
        }

        // Start the server on a independent thread
        thread::spawn(start_test_server);

        // Depending on the running environment, the server could take a bit of time to start
        // We try to query it with a dummy request until be sure it is started.
        let mut retry = true;
        let mut timeout = 5;
        let mut waiting = 1;
        while retry {
            let result = fetch_version(&cli_conf).await;

            if result.is_err() {
                timeout -= 1;
                retry = timeout >= 0;
                if retry {
                    println!("The server is not up yet, retrying in {waiting}s... ({result:?}) ",);
                    thread::sleep(std::time::Duration::from_secs(waiting));
                    waiting *= 2;
                } else {
                    println!("The server is still not up, stop trying");
                    panic!("Can't start the kms server to run tests");
                }
            } else {
                println!("The server is up!");
                retry = false
            }
        }
    }

    // Create a json
    let file = File::create(CONF_PATH).expect("Can't create CONF_PATH");
    serde_json::to_writer(BufWriter::new(file), &cli_conf).expect("Can't write CONF_PATH");

    // Configure a database and create the kms json file
    let mut cmd = Command::cargo_bin(PROG_NAME).expect("Can't execute new database command");
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg("new-database");

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout).expect("Can't recover command output");

    // Get the token
    let database_secret =
        extract_database_secret(stdout).expect("Can't extract database secret from cmd output");

    // Rewrite the conf with the correct database secret
    cli_conf.kms_database_secret = Some(database_secret.to_string());
    let file = File::create(CONF_PATH).expect("Can't create CONF_PATH");
    serde_json::to_writer(BufWriter::new(file), &cli_conf).expect("Can't write CONF_PATH");

    // Generate a wrong token with valid group id
    let secrets = b64.decode(database_secret).expect("Can't decode token");
    let mut secrets =
        serde_json::from_slice::<ExtraDatabaseParams>(&secrets).expect("Can't deserialized token");
    secrets.key = String::from("bad");
    let token = b64.encode(serde_json::to_string(&secrets).expect("Can't encode token"));
    cli_conf.kms_database_secret = Some(token);
    let file = File::create(CONF_PATH_BAD_KEY).expect("Can't create CONF_PATH_BAD_KEY");
    serde_json::to_writer(BufWriter::new(file), &cli_conf).expect("can't write CONF_PATH_BAD_KEY");
}
