use std::{
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use actix_web::dev::ServerHandle;
use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::ProtocolVersion,
    },
    kmip_1_4::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Operation, Query},
        kmip_types::{OperationEnumeration, QueryFunction},
    },
    ttlv::KmipFlavor::Kmip1,
};
use cosmian_kms_client::{KmsClientError, SocketClient, SocketClientConfig};
use cosmian_logger::log_init;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use tracing::{error, trace};

use crate::{
    config::ServerParams,
    socket_server::{create_rustls_server_config, SocketServer, SocketServerParams},
    start_kms_server::start_kms_server,
    tests::test_utils::https_clap_config,
};

const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 5696;

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
                Some(include_bytes!("../../../../test_data/client_server/ca/ca.crt").to_vec());
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
    log_init(option_env!("RUST_LOG"));
    let config = load_test_config();
    let server = SocketServer::instantiate(&config);
    server.expect("Failed to instantiate server");
}

#[test]
fn test_rustls_server_config() {
    log_init(option_env!("RUST_LOG"));
    let config = load_test_config();

    let result = create_rustls_server_config(&config);
    result.expect("Failed to create rustls server config");
}

#[test]
fn test_socket_server_with_socket_client() {
    log_init(option_env!("RUST_LOG"));

    let server_params = Arc::new(ServerParams::try_from(https_clap_config()).unwrap());

    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let _thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the KMS Server future
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(start_kms_server(server_params, Some(tx)))
            .map_err(|e| {
                error!("Failed to start KMS server: {}", e);
                KmsClientError::UnexpectedError(e.to_string())
            })
    });
    trace!("Waiting for test KMS server to start...");
    let _server_handle = rx
        .recv_timeout(Duration::from_secs(25))
        .expect("Can't get test KMS server handle after 25 seconds");
    trace!("... got handle ...");

    let socket_client = SocketClient::new(SocketClientConfig {
        host: "localhost".to_owned(),
        port: 5695,
        client_p12: include_bytes!(
            "../../../../test_data/client_server/user/user.client.acme.com.p12"
        )
        .to_vec(),
        client_p12_secret: "password".to_owned(),
        server_ca_cert_pem: include_str!("../../../../test_data/client_server/ca/ca.crt")
            .to_owned(),
    })
    .expect("Failed to create socket client");

    let query = Query {
        query_function: Some(vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
        ]),
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
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(query),
                message_extension: None,
            },
        )],
    };

    let response = socket_client
        .send_request::<RequestMessage, RequestMessage>(Kmip1, &request_message)
        .expect("Failed to send request");

    assert_eq!(response, request_message);
}
