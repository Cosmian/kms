use std::sync::LazyLock;

use cosmian_logger::log_init;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use crate::{
    openssl_providers::init_openssl_providers_for_tests,
    socket_server::{SocketServer, SocketServerParams, create_openssl_acceptor},
    tests::ttlv_tests::TEST_HOST,
};

// Static config for tests
static TEST_P12: LazyLock<ParsedPkcs12_2> = LazyLock::new(|| {
    init_openssl_providers_for_tests();
    let server_p12_der = include_bytes!(
        "../../../../../test_data/certificates/client_server/server/kmserver.acme.com.p12"
    );
    let server_p12_password = "password";
    let sealed_p12 =
        Pkcs12::from_der(server_p12_der).expect("TLS configuration. Failed opening P12");
    sealed_p12
        .parse2(server_p12_password)
        .expect("TLS configuration. Failed to decrypt P12")
});

static TEST_CLIENT_CA_CERT_PEM: LazyLock<Vec<u8>> = LazyLock::new(|| {
    include_bytes!("../../../../../test_data/certificates/client_server/ca/ca.crt").to_vec()
});

fn load_test_config() -> SocketServerParams<'static> {
    SocketServerParams {
        host: TEST_HOST.to_owned(),
        port: 11117,
        p12: &TEST_P12,
        client_ca_cert_pem: &TEST_CLIENT_CA_CERT_PEM,
        cipher_suites: None,
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

    let result = create_openssl_acceptor(&config);
    result.expect("Failed to create rustls server config");
}
