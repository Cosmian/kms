mod add_attribute_1_4;
mod add_attribute_2_1;
mod attribute_version_gating;
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
mod register_operation_policy_name_1_0;
mod socket_client;

const TEST_HOST: &str = "127.0.0.1";

use std::{
    net::TcpListener,
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

/// The test server context maintains a strong ref to the handles, plus the
/// actual (OS-assigned) socket server port so callers within the same process
/// can connect to it after the singleton has been initialized.
struct TestServerCtx {
    server_handle: ServerHandle,
    thread_handle: Option<thread::JoinHandle<Result<(), KmsError>>>,
    socket_port: u16,
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

/// Starts the test server (used by [`get_client`]) if it is not already
/// running, allocating OS-assigned free ports for both the HTTP and socket
/// servers.
///
/// `cargo-nextest` runs every test in its own process, so previously
/// hard-coding fixed ports (11112/11111) meant that concurrent test processes
/// raced to bind the same port ("Address already in use"). Allocating
/// ephemeral ports per process removes that race entirely while keeping full
/// test parallelism (no serialization needed).
fn start_test_server() -> &'static TestServerCtx {
    static SERVER_HANDLES: OnceLock<TestServerCtx> = OnceLock::new();

    SERVER_HANDLES.get_or_init(|| {
        let mut https_config = https_clap_config();
        https_config.socket_server.socket_server_hostname = TEST_HOST.to_owned();
        https_config.http.hostname = TEST_HOST.to_owned();

        // Pre-bind the HTTP listener on an OS-assigned free port and hand it
        // directly to `start_kms_server`, which accepts it to avoid the
        // bind/drop/re-bind race that a port-probe-then-release approach would have.
        let http_listener = TcpListener::bind((TEST_HOST, 0))
            .expect("Failed to allocate a free port for the test HTTP server");
        let http_port = http_listener
            .local_addr()
            .expect("Failed to read the allocated HTTP port")
            .port();
        https_config.http.port = http_port;

        // The socket server does not (yet) support taking a pre-bound
        // listener, so probe a free port and release it right before the real
        // server binds it. This is the same accepted TOCTOU trade-off already
        // used for the socket server port in `test_kms_server::allocate_dynamic_port`.
        let socket_probe = TcpListener::bind((TEST_HOST, 0))
            .expect("Failed to allocate a free port for the test socket server");
        let socket_port = socket_probe
            .local_addr()
            .expect("Failed to read the allocated socket port")
            .port();
        drop(socket_probe);
        https_config.socket_server.socket_server_port = socket_port;

        let server_params = ServerParams::try_from(https_config).unwrap();

        let (tx, rx) = mpsc::channel::<ServerHandle>();

        let thread_handle = thread::spawn(move || {
            // allow others `spawn` to happen within the KMS Server future
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(
                    start_kms_server(Arc::new(server_params), Some(tx), Some(http_listener))
                        .map_err(|e| {
                            tracing::error!("Failed to start Test KMS server: {e}");
                            e
                        }),
                )
        });
        trace!("Waiting for test KMS server to start...");
        let server_handle = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("Can't get test KMS server handle");
        trace!("... server started");

        TestServerCtx {
            server_handle,
            thread_handle: Some(thread_handle),
            socket_port,
        }
    })
}

/// Starts a test server bound to a caller-chosen, fixed socket port.
///
/// Only used by the (`#[ignore]`d, run manually) `pykmip` integration test,
/// whose external Python test suite is hard-coded to connect to a specific
/// port. It is never exercised by the default test run, so the fixed port
/// does not create the cross-process contention that [`start_test_server`]
/// used to have.
fn start_test_server_with_fixed_port(socket_port: u16) -> &'static TestServerCtx {
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
                    start_kms_server(Arc::new(server_params), Some(tx), None).map_err(|e| {
                        tracing::error!("Failed to start Test KMS server: {e}");
                        e
                    }),
                )
        });
        trace!("Waiting for test KMS server to start...");
        let server_handle = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("Can't get test KMS server handle");
        trace!("... server started");

        TestServerCtx {
            server_handle,
            thread_handle: Some(thread_handle),
            socket_port,
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
    let server_handles = start_test_server();
    new_socket_client(server_handles.socket_port)
}
