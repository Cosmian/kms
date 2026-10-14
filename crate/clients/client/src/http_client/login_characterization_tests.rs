//! Characterization tests for the `OAuth2` callback server of `LoginState`.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    sync::mpsc,
    thread,
    time::Duration,
};

use super::LoginState;

/// Send a raw HTTP GET to the callback server and return the full raw response.
fn browser_get(port: u16, path_query: &str, tx: mpsc::Sender<String>) {
    let path_query = path_query.to_owned();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let request = format!(
            "GET {path_query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        tx.send(response).unwrap();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn characterization_receive_authorization_parameters_returns_query_and_ok_page() {
    const PORT: u16 = 17_951;
    let (tx, rx) = mpsc::channel();
    browser_get(PORT, "/authorization?code=abc%20def&state=xyz&extra=", tx);

    let (params, handle) = LoginState::receive_authorization_parameters(PORT).unwrap();

    let expected: HashMap<String, String> = HashMap::from([
        ("code".to_owned(), "abc def".to_owned()),
        ("state".to_owned(), "xyz".to_owned()),
        ("extra".to_owned(), String::new()),
    ]);
    assert_eq!(params, expected);

    let response = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.ends_with("You can now close this window."),
        "{response}"
    );
    handle.stop(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn characterization_receive_authorization_parameters_port_in_use() {
    const PORT: u16 = 17_952;
    let _listener = std::net::TcpListener::bind(("127.0.0.1", PORT)).unwrap();
    let err = LoginState::receive_authorization_parameters(PORT).unwrap_err();
    assert!(
        err.to_string()
            .contains("cannot bind port 17952 for OAuth2 callback: "),
        "{err}"
    );
}
