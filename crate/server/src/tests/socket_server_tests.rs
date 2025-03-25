use std::{fs, net::TcpStream, path::Path, thread, time::Duration};

use crate::socket_server::{create_rustls_server_config, SocketServer, SocketServerConfig};

const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 5696;

fn load_test_config() -> SocketServerConfig {
    let test_dir = Path::new("./certificates/socket_server");

    let server_p12_der = fs::read(test_dir.join("server.p12")).expect("Failed to read server.p12");

    let server_p12_password = "password".to_owned();

    let client_ca_cert_pem =
        fs::read_to_string(test_dir.join("client_ca.crt")).expect("Failed to read client_ca.crt");

    SocketServerConfig {
        host: TEST_HOST.to_owned(),
        port: TEST_PORT,
        server_p12_der,
        server_p12_password,
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
fn test_invalid_server_password() {
    let mut config = load_test_config();
    "wrong_password".clone_into(&mut config.server_p12_password);
    let server = SocketServer::instantiate(&config);
    assert!(server.is_err());
}

#[test]
fn test_invalid_client_ca_cert() {
    let mut config = load_test_config();
    "invalid certificate data".clone_into(&mut config.client_ca_cert_pem);
    let server = SocketServer::instantiate(&config);
    assert!(server.is_err());
}

#[test]
fn test_server_binding() {
    let config = load_test_config();
    let server = SocketServer::instantiate(&config).expect("Failed to instantiate server");

    let _server_thread = thread::spawn(move || {
        let _unused = server.start(<[u8]>::to_vec);
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
