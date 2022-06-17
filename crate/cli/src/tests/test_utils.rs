use std::{fs, thread};

use cosmian_kms_server::{
    config::{auth::AuthConfig, db::DBConfig, init_config, Config},
    start_kms_server,
};
use reqwest::ClientBuilder;
use tokio::sync::OnceCell;

/// We use that to avoid to try to start N servers (one per test)
/// Otherwise we got: "Address already in use (os error 98)"
/// for N-1 tests.
pub static ONCE: OnceCell<()> = OnceCell::const_new();

#[tokio::main]
pub async fn start_test_server() {
    start_kms_server().await.unwrap();
}

/// Start a server for testing
pub async fn init_test_server() {
    // Configure the serveur
    let config = Config {
        auth: AuthConfig {
            delegated_authority_domain: "dev-1mbsbmin.us.auth0.com".to_string(),
        },
        db: DBConfig {
            sqlcipher: true,
            ..Default::default()
        },
        ..Default::default()
    };
    init_config(&config).await.unwrap();

    // We mock the creation of a database by the server (to force the group_id and the key)
    let db_test = config
        .workspace
        .public_path
        .join("129779770570336941908439893874924049192.sqlite");
    if db_test.exists() {
        fs::remove_file(&db_test).expect("Can't remove the previous test database file");
    }
    fs::File::create(&db_test).expect("Can't create a fresh testdatabase file");

    // Start the server on a independent thread
    thread::spawn(start_test_server);

    // Depending on the running environment, the server could take a bit of time to start
    // We try to query it with a dummy request until be sure it is started.
    let mut retry = true;
    let mut timeout = 5;
    let mut waiting = 1;
    while retry {
        let result = ClientBuilder::new()
            .build()
            .unwrap()
            .post("http://127.0.0.1:9998/kmip/2_1")
            .json("{}")
            .send()
            .await;

        if result.is_err() {
            timeout -= 1;
            retry = timeout >= 0;
            if retry {
                println!("The server is not up yet, retrying in {}s...", waiting);
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
