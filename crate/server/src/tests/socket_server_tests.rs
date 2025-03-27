use std::{net::TcpStream, sync::OnceLock, thread, time::Duration};

use cosmian_kmip::{
    kmip_1_4::{
        kmip_messages::{RequestMessage, RequestMessageBatchItem, RequestMessageHeader},
        kmip_operations::{Operation, Query},
        kmip_types::{OperationEnumeration, ProtocolVersion, QueryFunction},
    },
    ttlv::KmipFlavor::Kmip1,
};
use cosmian_kms_client::{SocketClient, SocketClientConfig};
use cosmian_logger::log_init;
use tracing::info;

use crate::socket_server::{create_rustls_server_config, SocketServer, SocketServerConfig};

const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 5696;

pub(crate) static SOCKET_SERVER_ONCE: OnceLock<thread::JoinHandle<()>> = OnceLock::new();

fn start_socket_server() -> &'static thread::JoinHandle<()> {
    SOCKET_SERVER_ONCE.get_or_init(|| {
        let config = load_test_config();
        let server = SocketServer::instantiate(&config).expect("Failed to instantiate server");

        thread::spawn(move || {
            server
                .start(|username, request| {
                    // log the username
                    info!("Received request from user: {}", username);
                    // Echo the request back
                    request.to_vec()
                })
                .expect("Failed to start server");
        })
    })
}

fn load_test_config() -> SocketServerConfig<'static> {
    let server_p12_der = include_bytes!("./certificates/socket_server/server.p12").to_vec();
    let server_p12_password = "secret".to_owned();
    let client_ca_cert_pem = include_str!("./certificates/socket_server/ca.crt").to_owned();

    SocketServerConfig {
        host: TEST_HOST.to_owned(),
        port: TEST_PORT,
        p12,
        client_ca_cert_pem,
    }
}

#[test]
fn test_server_instantiation() {
    let config = load_test_config();
    let server = SocketServer::instantiate(&config);
    server.expect("Failed to instantiate server");
}

#[test]
fn test_invalid_client_ca_cert() {
    let mut config = load_test_config();
    "invalid certificate data"
        .as_bytes()
        .clone_into(&mut config.client_ca_cert_pem);
    let server = SocketServer::instantiate(&config);
    assert!(server.is_err());
}

#[test]
fn test_server_binding() {
    let config = load_test_config();
    let server = SocketServer::instantiate(&config).expect("Failed to instantiate server");

    let _server_thread = thread::spawn(move || {
        let _unused = server.start(|_username, req| req.to_vec());
    });

    thread::sleep(Duration::from_millis(100));

    let result = TcpStream::connect(format!("{TEST_HOST}:{TEST_PORT}"));
    result.expect("Failed to connect to server");

    // Let the test finish and the thread terminate
}

#[test]
fn test_rustls_server_config() {
    let config = load_test_config();

    let result = create_rustls_server_config(
        &config.server_p12_der,
        &config.server_p12_password,
        &config.client_ca_cert_pem,
    );

    result.expect("Failed to create rustls server config");
}

#[test]
fn test_socket_server_with_socket_client() {
    log_init(Some("debug"));
    let _server_thread = start_socket_server();

    let socket_client = SocketClient::new(SocketClientConfig {
        host: "localhost".to_owned(),
        port: 5696,
        client_p12: include_bytes!("./certificates/socket_server/client.p12").to_vec(),
        client_p12_secret: "secret".to_owned(),
        server_ca_cert_pem: include_str!("./certificates/socket_server/ca.crt").to_owned(),
    })
    .expect("Failed to create socket client");

    let query = Query {
        query_function: vec![QueryFunction::QueryOperations, QueryFunction::QueryObjects],
    };
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            maximum_response_size: Some(1_048_576),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItem {
            operation: OperationEnumeration::Query,
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: Operation::Query(query),
            message_extension: None,
        }],
    };

    let response = socket_client
        .send_request::<RequestMessage, RequestMessage>(Kmip1, &request_message)
        .expect("Failed to send request");

    assert_eq!(response, request_message);
}
