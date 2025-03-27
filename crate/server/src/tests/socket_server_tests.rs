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
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use tracing::info;

use crate::socket_server::{create_rustls_server_config, SocketServer, SocketServerParams};

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

// Static config for tests
static mut TEST_P12: Option<ParsedPkcs12_2> = None;
static mut TEST_CLIENT_CA_CERT_PEM: Option<Vec<u8>> = None;

fn load_test_config() -> SocketServerParams<'static> {
    // Initialize the static data if needed
    unsafe {
        if TEST_P12.is_none() {
            // let server_p12_der = include_bytes!("./certificates/socket_server/server.p12");
            let server_p12_der =
                include_bytes!("../../../../test_data/client_server/server/kmserver.acme.com.p12");
            let server_p12_password = "password";

            // Parse the PKCS#12 object
            let sealed_p12 =
                Pkcs12::from_der(server_p12_der).expect("TLS configuration. Failed opening P12");
            TEST_P12 = Some(
                sealed_p12
                    .parse2(server_p12_password)
                    .expect("TLS configuration. Failed to decrypt P12"),
            );

            // Store client CA cert
            TEST_CLIENT_CA_CERT_PEM =
                Some(include_bytes!("../../../../test_data/client_server/server/ca.crt").to_vec());
            // Some(include_bytes!("./certificates/socket_server/ca.crt").to_vec());
        }

        SocketServerParams {
            host: TEST_HOST.to_owned(),
            port: TEST_PORT,
            p12: TEST_P12.as_ref().unwrap(),
            client_ca_cert_pem: TEST_CLIENT_CA_CERT_PEM.as_ref().unwrap(),
        }
    }
}

#[test]
fn test_server_instantiation() {
    let config = load_test_config();
    let server = SocketServer::instantiate(&config);
    server.expect("Failed to instantiate server");
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

    let result = create_rustls_server_config(&config);
    result.expect("Failed to create rustls server config");
}

#[test]
fn test_socket_server_with_socket_client() {
    log_init(Some("debug"));
    let _server_thread = start_socket_server();

    let socket_client = SocketClient::new(SocketClientConfig {
        host: "localhost".to_owned(),
        port: 5696,
        client_p12: include_bytes!(
            "../../../../test_data/client_server/user/user.client.acme.com.p12"
        )
        .to_vec(),
        client_p12_secret: "password".to_owned(),
        server_ca_cert_pem: include_str!("../../../../test_data/client_server/server/ca.crt")
            .to_owned(),
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
