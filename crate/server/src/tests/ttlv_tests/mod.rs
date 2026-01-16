mod add_attribute_1_4;
mod add_attribute_2_1;
mod config;
mod create_1_4;
mod create_2_1;
mod create_dsa;
mod create_dsa_invalid_size;
mod create_get_dsa;
mod decrypt_1_4;
mod decrypt_2_1;
mod discover_versions;
mod encrypt_1_4;
mod encrypt_2_1;
mod get_1_0;
mod get_1_4;
mod get_2_1;
mod get_attribute_1_4;
mod get_attribute_2_1;
mod get_attribute_list_1_0;
mod get_attribute_list_1_4;
mod get_dsa_unsupported_format;
mod import_1_4;
mod import_2_1;
mod integrations;
mod locate_1_4;
mod locate_2_1;
mod normative_tests;
#[cfg(not(target_os = "windows"))]
mod pykmip;
mod query;
mod register_1_4;
mod register_2_1;
mod socket_client;

const TEST_HOST: &str = "127.0.0.1";

use std::{
    sync::{Arc, OnceLock, mpsc},
    thread,
    time::Duration,
};

use actix_web::dev::ServerHandle;
use cosmian_logger::{info, trace};
use futures::{TryFutureExt, executor::block_on};
use socket_client::{SocketClient, SocketClientConfig};

use crate::{
    config::ServerParams, error::KmsError, start_kms_server::start_kms_server,
    tests::test_utils::https_clap_config,
};

/// The test server context maintains a strong ref to the handles.
struct TestServerCtx {
    server_handle: ServerHandle,
    thread_handle: Option<thread::JoinHandle<Result<(), KmsError>>>,
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
fn start_test_server(socket_port: u16) -> &'static TestServerCtx {
    static SERVER_HANDLES: OnceLock<TestServerCtx> = OnceLock::new();
    let mut https_config = https_clap_config();
    https_config.socket_server.socket_server_port = socket_port;
    https_config.socket_server.socket_server_hostname = TEST_HOST.to_owned();
    https_config.http.port = socket_port - 1;
    https_config.http.hostname = TEST_HOST.to_owned();

    SERVER_HANDLES.get_or_init(|| {
        let server_params = ServerParams::try_from(https_config).unwrap();

        let (tx, rx) = mpsc::channel::<ServerHandle>();

        let thread_handle = thread::spawn(move || {
            // allow others `spawn` to happen within the KMS Server future
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(
                    start_kms_server(Arc::new(server_params), Some(tx)).map_err(|e| {
                        tracing::error!("Failed to start Test KMS server: {e}");
                        e
                    }),
                )
        });
        trace!("Waiting for test KMS server to start...");
        let server_handle = rx
            .recv_timeout(Duration::from_secs(25))
            .expect("Can't get test KMS server handle");
        trace!("... server started");

        TestServerCtx {
            server_handle,
            thread_handle: Some(thread_handle),
        }
    })
}

/// Creates a new socket client with the default configuration.
fn new_socket_client(socket_port: u16) -> SocketClient {
    SocketClient::new(SocketClientConfig {
        host: "localhost".to_owned(),
        port: socket_port,
        client_p12: include_bytes!(
            "../../../../../test_data/certificates/client_server/user/user.client.acme.com.p12"
        )
        .to_vec(),
        client_p12_secret: "password".to_owned(),
        server_ca_cert_pem: include_str!(
            "../../../../../test_data/certificates/client_server/ca/ca.crt"
        )
        .to_owned(),
    })
    .expect("Failed to create socket client")
}

/// Creates a new socket client connected to the test server.
/// This will start the test server if it is not already running.
fn get_client() -> SocketClient {
    let _server_handles = start_test_server(11112);
    new_socket_client(11112)
}
