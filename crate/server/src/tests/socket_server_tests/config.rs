use cosmian_logger::log_init;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use crate::{
    socket_server::{create_rustls_server_config, SocketServer, SocketServerParams},
    tests::socket_server_tests::{TEST_HOST, TEST_PORT},
};

// Static config for tests
static mut TEST_P12: Option<ParsedPkcs12_2> = None;
static mut TEST_CLIENT_CA_CERT_PEM: Option<Vec<u8>> = None;

fn load_test_config() -> SocketServerParams<'static> {
    // Initialize the static data if needed
    unsafe {
        if TEST_P12.is_none() {
            // let server_p12_der = include_bytes!("./certificates/socket_server/server.p12");
            let server_p12_der = include_bytes!(
                "../../../../../test_data/client_server/server/kmserver.acme.com.p12"
            );
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
                Some(include_bytes!("../../../../../test_data/client_server/ca/ca.crt").to_vec());
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
