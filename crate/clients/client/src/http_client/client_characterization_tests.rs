//! Characterization tests for the `accept_invalid_certs` serialization rule of
//! `HttpClientConfig`.

use super::HttpClientConfig;

#[test]
fn characterization_http_client_config_serialization_skips_false_accept_invalid_certs() {
    let json = serde_json::to_string(&HttpClientConfig::default()).unwrap();
    assert_eq!(json, r#"{"server_url":"http://127.0.0.1:9998"}"#);
}

#[test]
fn characterization_http_client_config_serialization_keeps_true_accept_invalid_certs() {
    let config = HttpClientConfig {
        accept_invalid_certs: true,
        ..HttpClientConfig::default()
    };
    let json = serde_json::to_string(&config).unwrap();
    assert_eq!(
        json,
        r#"{"accept_invalid_certs":true,"server_url":"http://127.0.0.1:9998"}"#
    );
}
