mod add_attribute_1_4;
mod config;
mod create_1_4;
mod create_2_1;
mod discover_versions;
mod query;

const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 11112;

use std::{
    sync::{mpsc, Arc, OnceLock},
    thread,
    time::Duration,
};

use actix_web::dev::ServerHandle;
use cosmian_kms_client::{KmsClientError, SocketClient, SocketClientConfig};
use futures::executor::block_on;
use tracing::{error, info, trace};

use crate::{
    config::ServerParams, start_kms_server::start_kms_server, tests::test_utils::https_clap_config,
};

/// The test server context maintains a strong ref to the handles.
struct TestServerCtx {
    server_handle: ServerHandle,
    thread_handle: Option<thread::JoinHandle<Result<(), KmsClientError>>>,
}

impl Drop for TestServerCtx {
    fn drop(&mut self) {
        trace!("Dropping test KMS server context...");
        // Stop
        block_on(async {
            self.server_handle.stop(true).await;
        });
        if let Some(handle) = self.thread_handle.take() {
            trace!("Waiting for test KMS server thread to finish...");
            handle.join().unwrap().unwrap();
        }
        info!("Test KMS server shut down.");
    }
}

/// Starts the test server if it is not already running.
fn start_test_server() -> &'static TestServerCtx {
    static SERVER_HANDLES: OnceLock<TestServerCtx> = OnceLock::new();

    SERVER_HANDLES.get_or_init(|| {
        let mut server_params = ServerParams::try_from(https_clap_config()).unwrap();
        TEST_HOST.clone_into(&mut server_params.http_hostname);
        server_params.http_port = TEST_PORT - 1;
        TEST_HOST.clone_into(&mut server_params.socket_server_hostname);
        server_params.socket_server_port = TEST_PORT;

        let (tx, rx) = mpsc::channel::<ServerHandle>();

        let thread_handle = thread::spawn(move || {
            // allow others `spawn` to happen within the KMS Server future
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(start_kms_server(Arc::new(server_params), Some(tx)))
                .map_err(|e| {
                    error!("Failed to start KMS server: {}", e);
                    KmsClientError::UnexpectedError(e.to_string())
                })
        });
        trace!("Waiting for test KMS server to start...");
        let server_handle = rx
            .recv_timeout(Duration::from_secs(25))
            .expect("Can't get test KMS server handle after 25 seconds");
        trace!("... server started");

        TestServerCtx {
            server_handle,
            thread_handle: Some(thread_handle),
        }
    })
}

/// Creates a new socket client with the default configuration.
fn new_socket_client() -> SocketClient {
    SocketClient::new(SocketClientConfig {
        host: "localhost".to_owned(),
        port: 11112,
        client_p12: include_bytes!(
            "../../../../../test_data/client_server/user/user.client.acme.com.p12"
        )
        .to_vec(),
        client_p12_secret: "password".to_owned(),
        server_ca_cert_pem: include_str!("../../../../../test_data/client_server/ca/ca.crt")
            .to_owned(),
    })
    .expect("Failed to create socket client")
}

/// Creates a new socket client connected to the test server.
/// This will start the test server if it is not already running.
fn get_client() -> SocketClient {
    let _server_handles = start_test_server();
    new_socket_client()
}
