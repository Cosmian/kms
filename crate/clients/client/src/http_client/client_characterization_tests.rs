//! Characterization tests for `split_for_retry` and the `accept_invalid_certs`
//! serialization rule of `HttpClientConfig`.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use super::{HttpClient, HttpClientConfig};

#[tokio::test]
async fn characterization_split_for_retry_copies_request() {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://127.0.0.1:9998/kmip/2_1?x=1")
        .version(http::Version::HTTP_11)
        .header("X-First", "one")
        .header("X-First", "uno")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from_static(b"payload")))
        .unwrap();

    let (original, retry) = HttpClient::split_for_retry(request).unwrap();

    assert_eq!(original.method(), http::Method::POST);
    assert_eq!(retry.method(), http::Method::POST);
    assert_eq!(retry.uri(), original.uri());
    assert_eq!(
        retry.uri().to_string(),
        "http://127.0.0.1:9998/kmip/2_1?x=1"
    );
    assert_eq!(retry.version(), http::Version::HTTP_11);
    assert_eq!(retry.headers(), original.headers());
    let first: Vec<_> = retry.headers().get_all("X-First").iter().collect();
    assert_eq!(first, ["one", "uno"]);
    assert_eq!(retry.headers().len(), 3);
    let retry_body = retry.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(retry_body, Bytes::from_static(b"payload"));
    let original_body = original.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(original_body, Bytes::from_static(b"payload"));
}

#[tokio::test]
async fn characterization_split_for_retry_empty_body() {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/relative")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (original, retry) = HttpClient::split_for_retry(request).unwrap();
    assert_eq!(original.uri(), "/relative");
    assert_eq!(retry.uri(), "/relative");
    assert_eq!(retry.method(), http::Method::GET);
    assert!(retry.headers().is_empty());
    assert!(
        retry
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

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
