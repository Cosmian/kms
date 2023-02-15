use std::{
    fs::File,
    io::{BufReader, BufWriter},
    process::Command,
};

use assert_cmd::prelude::{CommandCargoExt, OutputAssertExt};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use cosmian_kms_server::config::{auth0::Auth0Config, db::DBConfig, init_config, Config};
use cosmian_kms_utils::types::ExtraDatabaseParams;
use tokio::sync::OnceCell;
#[cfg(not(feature = "staging"))]
use {cosmian_kms_server::start_kms_server, reqwest::ClientBuilder, std::thread};

use super::{
    utils::extract_uids::extract_database_secret, CONF_PATH, PATTERN_CONF_PATH, PROG_NAME,
};
use crate::{
    config::{CliConf, KMS_CLI_CONF_ENV},
    tests::CONF_PATH_BAD_KEY,
};

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
    let _ = env_logger::builder().is_test(true).try_init();
    // Configure the serveur
    let config = Config {
        auth0: Auth0Config {
            auth0_authority_domain: Some("console-dev.eu.auth0.com".to_string()),
        },
        db: DBConfig {
            database_type: "sqlite-enc".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    init_config(&config)
        .await
        .map_err(|e| format!("failed initializing the config: {e}"))
        .unwrap();

    // Read the conf. We will update it later by appending the secret token
    let file = File::open(PATTERN_CONF_PATH).expect("");
    let mut cli_conf: CliConf =
        serde_json::from_reader(BufReader::new(file)).expect("cannot deserialize CLI cfg");

    println!("Using: {}", cli_conf.kms_server_url);

    #[cfg(not(feature = "staging"))]
    {
        // Start the server on a independent thread
        thread::spawn(|| start_test_server());

        // Depending on the running environment, the server could take a bit of time to start
        // We try to query it with a dummy request until be sure it is started.
        let mut retry = true;
        let mut timeout = 5;
        let mut waiting = 1;
        while retry {
            let result = ClientBuilder::new()
                .build()
                .unwrap()
                .post(format!("{}/version", cli_conf.kms_server_url))
                .json("{}")
                .send()
                .await;

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

    // Configure a database and create the kms json file
    let mut cmd = Command::cargo_bin(PROG_NAME).expect("Can't execute configure command");
    cmd.env(KMS_CLI_CONF_ENV, PATTERN_CONF_PATH);
    cmd.arg("configure");

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout).expect("Can't recover command output");

    // Get the token
    let token =
        extract_database_secret(stdout).expect("Can't extract database secret from cmd output");

    // Create a json
    cli_conf.kms_database_secret = Some(token.to_string());
    let file = File::create(CONF_PATH).expect("Can't create CONF_PATH");
    serde_json::to_writer(BufWriter::new(file), &cli_conf).expect("Can't write CONF_PATH");

    // Generate a wrong token with valid group id
    let secrets = b64.decode(token).expect("Can't decode token");
    let mut secrets =
        serde_json::from_slice::<ExtraDatabaseParams>(&secrets).expect("Can't deserialized token");
    secrets.key = String::from("bad");
    let token = b64.encode(serde_json::to_string(&secrets).expect("Can't encode token"));
    cli_conf.kms_database_secret = Some(token);
    let file = File::create(CONF_PATH_BAD_KEY).expect("Can't create CONF_PATH_BAD_KEY");
    serde_json::to_writer(BufWriter::new(file), &cli_conf).expect("can't write CONF_PATH_BAD_KEY");
}
