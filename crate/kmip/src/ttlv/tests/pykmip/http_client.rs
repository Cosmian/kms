#![allow(dead_code)]
//! `PyKMIP` test client for sending KMIP requests to a local server.
use reqwest::blocking::{Client, Response};
use tracing::info;

use crate::{error::result::KmipResult, KmipError, KmipResultHelper};

// load the string content at compile time
const CLIENT_KEY: &str = include_str!("client.key");
const CLIENT_CERTIFICATE: &str = include_str!("client.crt");
const SERVER_CA_CERTIFICATE: &str = include_str!("server.crt");
const CLIENT_P12: &[u8; 2691] = include_bytes!("client.p12");

/// Configuration for the `PyKMIP` test client
pub(crate) struct PyKmipHttpClientConfig {
    /// Server URL
    pub url: String,
    /// Client certificate path (PEM format, X509)
    pub client_cert_pem: String,
    /// Client key path (PEM format, PKCS#8 or SEC1)
    pub client_key_pem: String,
    /// Path to server CA certificate (PEM format, X509)
    pub server_ca_cert_pem: String,
}

impl Default for PyKmipHttpClientConfig {
    fn default() -> Self {
        Self {
            url: "https://localhost:5696/kmip".to_owned(),
            client_cert_pem: CLIENT_CERTIFICATE.to_owned(),
            client_key_pem: CLIENT_KEY.to_owned(),
            server_ca_cert_pem: SERVER_CA_CERTIFICATE.to_owned(),
        }
    }
}

/// Client for communicating with a `PyKMIP` server
pub(crate) struct PyKmipHttpClient {
    client: Client,
    config: PyKmipHttpClientConfig,
}

impl PyKmipHttpClient {
    /// Create a new `PyKMIP` client with the specified configuration
    pub(crate) fn new(config: PyKmipHttpClientConfig) -> KmipResult<Self> {
        // Create client identity from cert and key
        let pem = format!("{}\n{}", config.client_key_pem, config.client_cert_pem);
        // let pem = config.client_key_pem.to_owned();
        info!("Client identity PEM: {}", pem);
        // let identity = reqwest::Identity::from_pem(pem.as_bytes())
        //     .context("Failed to create identity from client certificate and key")?;
        // info!(
        //     "Client identity created from certificate and key: {:#?}",
        //     identity
        // );

        let identity = reqwest::Identity::from_pkcs8_pem(
            config.client_cert_pem.as_bytes(),
            config.client_key_pem.as_bytes(),
        )
        .context("Failed to set password for client identity")?;

        // let identity = reqwest::Identity::from_pkcs12_der(CLIENT_P12, "secret")
        //     .context("Failed to set password for client identity")?;

        info!(
            "Client identity created from certificate and key: {:#?}",
            identity
        );

        // Create CA certificate
        let ca_cert = reqwest::Certificate::from_pem(config.server_ca_cert_pem.as_bytes())
            .context("Failed to create certificate from CA certificate data")?;

        // Create HTTP client with TLS configuration
        let client = Client::builder()
            .identity(identity)
            .add_root_certificate(ca_cert)
            .danger_accept_invalid_certs(true)
            // .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .use_native_tls()
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self { client, config })
    }

    /// Send a KMIP request to the server and return the response
    pub(crate) fn send_request(&self, data: &[u8]) -> KmipResult<Vec<u8>> {
        info!("Body: {}", hex::encode(data));

        // Build the request
        let request = self
            .client
            .post(&self.config.url)
            .header("Pragma", "no-cache")
            .header("Cache-Control", "no-cache")
            .header("Content-Type", "application/octet-stream")
            .header("Connection", "keep-alive")
            .header("Content-Length", data.len())
            .version(reqwest::Version::HTTP_11) // Force HTTP 1.1
            .body(data.to_vec());

        // Log request headers
        info!(
            "Request headers: {:#?}",
            request
                .try_clone()
                .context("request cloning failed")?
                .build()
                .context("context building failed")?
                .headers()
        );

        // Send the request
        let response = request
            .send()
            .context("Failed to send request to PyKMIP server")?;

        // Log response headers
        info!("Response headers: {:#?}", response.headers());

        Self::handle_response(response)
    }

    fn handle_response(response: Response) -> KmipResult<Vec<u8>> {
        if !response.status().is_success() {
            return Err(KmipError::Default(format!(
                "PyKMIP server returned error status: {} - {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        let body = response
            .bytes()
            .context("Failed to read response body")?
            .to_vec();

        Ok(body)
    }
}

/// Helper function to create a `PyKMIP` client with default configuration
pub(crate) fn create_default_client() -> KmipResult<PyKmipHttpClient> {
    PyKmipHttpClient::new(PyKmipHttpClientConfig::default())
}

#[cfg(test)]
mod tests {
    use cosmian_logger::log_init;

    use super::*;
    use crate::{
        kmip_1_4::{
            kmip_messages::{RequestMessage, RequestMessageBatchItem, RequestMessageHeader},
            kmip_operations::{Operation, Query},
            kmip_types::{OperationEnumeration, ProtocolVersion, QueryFunction},
        },
        ttlv::to_ttlv,
    };

    #[test]
    #[ignore] // Requires a running PyKMIP server
    fn test_connect_to_pykmip_server() {
        log_init(Some("trace"));
        let client = create_default_client().unwrap();

        // Create a simple KMIP request (placeholder for TTLV-encoded KMIP data)
        let request_data = request_message();

        let response = client.send_request(&request_data).unwrap();

        // Check that we got a response
        assert!(!response.is_empty());
    }

    fn request_message() -> Vec<u8> {
        // KMIP Request Message in Rust
        let request_message = RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 4,
                },
                maximum_response_size: Some(256),
                batch_count: 1,
                ..Default::default()
            },
            batch_item: vec![RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(Query {
                    query_function: vec![
                        QueryFunction::QueryOperations,
                        QueryFunction::QueryObjects,
                    ],
                }),
                message_extension: None,
            }],
        };

        // Serializer
        let ttlv = to_ttlv(&request_message).unwrap();
        info!("Request TTLV: {:#?}", ttlv);
        ttlv.to_bytes_1_4().unwrap()
    }
}
