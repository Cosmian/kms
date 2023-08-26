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
use cloudproof::reexport::crypto_core::{CsRng, RandomFixedSizeCBytes, SymmetricKey};
use cosmian_kms_server::{
    config::{
        db::DBConfig,
        http::HTTPConfig,
        jwe::{JWEConfig, Jwk},
        jwt_auth_config::JwtAuthConfig,
        ClapConfig, ServerConfig,
    },
    kms_server::start_kms_server,
};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use rand::SeedableRng;
use tokio::sync::OnceCell;
use tracing::trace;

use super::extract_uids::extract_database_secret;
use crate::{
    actions::shared::utils::write_json_object_to_file,
    cli_bail,
    config::{CliConf, KMS_CLI_CONF_ENV},
    error::CliError,
    tests::PROG_NAME,
};

// Test auth0 Config
const AUTH0_JWT_ISSUER_URI: &str = "https://kms-cosmian.eu.auth0.com/";
const AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjVVU1FrSVlULW9QMWZrcjQtNnRrciJ9.eyJuaWNrbmFtZSI6InRlY2giLCJuYW1lIjoidGVjaEBjb3NtaWFuLmNvbSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci81MmZiMzFjOGNjYWQzNDU4MTIzZDRmYWQxNDA4NTRjZj9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRnRlLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDIzLTA1LTMwVDA5OjMxOjExLjM4NloiLCJlbWFpbCI6InRlY2hAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImlzcyI6Imh0dHBzOi8va21zLWNvc21pYW4uZXUuYXV0aDAuY29tLyIsImF1ZCI6IkszaXhldXhuVDVrM0Roa0tocWhiMXpYbjlFNjJGRXdJIiwiaWF0IjoxNjg1NDM5MDc0LCJleHAiOjE2ODU0NzUwNzQsInN1YiI6ImF1dGgwfDYzZDNkM2VhOTNmZjE2NDJjNzdkZjkyOCIsInNpZCI6ImJnVUNuTTNBRjVxMlpaVHFxMTZwclBCMi11Z0NNaUNPIiwibm9uY2UiOiJVRUZWTlZWeVluWTVUbHBwWjJScGNqSmtVMEZ4TmxkUFEwc3dTVGMwWHpaV2RVVmtkVnBEVGxSMldnPT0ifQ.HmU9fFwZ-JjJVlSy_PTei3ys0upeWQbWWiESmKBtRSClGnAXJNCpwuP4Jw7fgKn-8IBf-PYmP1_54u2Rw3RcJFVl7EblVoGMghYxVq5hViGpd00st3VwZmyCwOUz2CE5RBnBAoES4C8xA3zWg6oau0xjFQbC3jNU20eyFYMDewXA8UXCHQrEiQ56ylqSbyqlBbQIWbmOO4m5w2WDkx0bVyyJ893JfIJr_NANEQMJITYo8Mp_iHCyKp7llsfgCt07xN8ZqnsrMsJ15zC1n50bHGrTQisxURS1dpuFXF1hfrxhzogxYMX8CEISjsFgROjPY84GRMmvpYZfyaJbDDql3A";

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
    pub owner_cli_conf_path: String,
    pub user_cli_conf_path: String,
    pub owner_cli_conf: CliConf,
    pub server_handle: ServerHandle,
    pub thread_handle: thread::JoinHandle<Result<(), CliError>>,
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
) -> Result<(ServerHandle, JoinHandle<Result<(), CliError>>), CliError> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();
    let tokio_handle = tokio::runtime::Handle::current();
    let thread_handle = thread::spawn(move || {
        tokio_handle
            .block_on(start_kms_server(server_config, Some(tx)))
            .map_err(|e| CliError::ServerError(e.to_string()))
    });
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
    init_test_server_options(9990, false, true, true, false).await
}

/// Start a server in a thread with the given options
pub async fn init_test_server_options(
    port: u16,
    use_jwt_token: bool,
    use_https: bool,
    use_client_cert: bool,
    use_jwe_encryption: bool,
) -> TestsContext {
    let _ = env_logger::builder().is_test(true).try_init();

    // Create a conf
    let owner_cli_conf_path = format!("/tmp/owner_kms_{port}.json");

    let jwe_private_key_json =
        "{\"kty\": \"OKP\",\"d\": \"MPEVJwdRqGM_qhJOUb5hR0Xr9EvwMLZGnkf-eDj5fU8\",\"use\": \
         \"enc\",\"crv\": \"X25519\",\"kid\": \"DX3GC+Fx3etxfRJValQNbqaB0gs=\",\"x\": \
         \"gdF-1TtAjsFqNWr9nwhGUlFG38qrDUqYgcILgtYrpTY\",\"alg\": \"ECDH-ES\"}";

    let jwk_private_key: Option<Jwk> = if use_jwe_encryption {
        Some(jwe_private_key_json.parse().expect("Wrong JWK private key"))
    } else {
        None
    };

    // Configure the serveur
    let clap_config = ClapConfig {
        auth: if use_jwt_token {
            get_auth0_jwt_config()
        } else {
            JwtAuthConfig::default()
        },
        db: DBConfig {
            database_type: "sqlite-enc".to_string(),
            clear_database: true,
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
        jwe: JWEConfig {
            jwk_private_key: jwk_private_key.clone(),
        },
        ..Default::default()
    };
    let server_config = ServerConfig::try_from(&clap_config)
        .await
        .map_err(|e| format!("failed initializing the server config: {e}"))
        .unwrap();

    // Generate a CLI Conf.
    // We will update it later by appending the database secret
    let mut owner_cli_conf = CliConf {
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
        jwe_public_key: if use_jwe_encryption {
            Some(jwe_private_key_json.to_string())
        } else {
            None
        }, // We use the private key since the private key is the public key with additional information.
        ..Default::default()
    };
    // write the conf to a file
    write_json_object_to_file(&owner_cli_conf, &owner_cli_conf_path)
        .expect("Can't write owner CLI conf path");

    // Start the server on a independent thread
    println!(
        "Starting test server at URL: {} with server config {:?}",
        owner_cli_conf.kms_server_url, &clap_config
    );
    let (server_handle, thread_handle) = start_server(server_config)
        .await
        .expect("Can't start server");

    // wait for the server to be up
    wait_for_server_to_start(&owner_cli_conf_path)
        .await
        .expect("server timeout");

    // Configure a database and create the kms json file
    let database_secret =
        create_new_database(&owner_cli_conf_path).expect("failed configuring a database");

    // Rewrite the conf with the correct database secret
    owner_cli_conf.kms_database_secret = Some(database_secret);
    write_json_object_to_file(&owner_cli_conf, &owner_cli_conf_path)
        .expect("Can't write owner CLI conf path");

    // generate a user conf
    let user_cli_conf_path =
        generate_user_conf(port, &owner_cli_conf).expect("Can't generate user conf");

    TestsContext {
        owner_cli_conf_path,
        user_cli_conf_path,
        owner_cli_conf,
        server_handle,
        thread_handle,
    }
}

/// Generate a user configuration for user.client@acme.com and return the file path
pub(crate) fn generate_user_conf(port: u16, owner_cli_conf: &CliConf) -> Result<String, CliError> {
    let mut user_conf = owner_cli_conf.clone();
    user_conf.ssl_client_pkcs12_path =
        Some("test_data/certificates/user.client.acme.com.p12".to_string());

    // write the user conf
    let user_conf_path = format!("/tmp/user_kms_{port}.json");
    write_json_object_to_file(&user_conf, &user_conf_path)?;

    // return the path
    Ok(user_conf_path)
}

/// Generate an invalid configuration by changin the database secret  and return the file path
pub(crate) fn generate_invalid_conf(correct_conf: &CliConf) -> String {
    // Create a new database key
    let mut cs_rng = CsRng::from_entropy();
    let db_key = SymmetricKey::<32>::new(&mut cs_rng);

    let mut invalid_conf = correct_conf.clone();
    // and a temp file
    let invalid_conf_path = "/tmp/invalid_conf.json".to_string();
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
    secrets.key = db_key; // bad secret
    let token = b64.encode(serde_json::to_string(&secrets).expect("Can't encode token"));
    invalid_conf.kms_database_secret = Some(token);
    write_json_object_to_file(&invalid_conf, &invalid_conf_path)
        .expect("Can't write CONF_PATH_BAD_KEY");
    invalid_conf_path
}
