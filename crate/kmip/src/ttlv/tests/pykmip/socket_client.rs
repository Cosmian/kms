use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use native_tls::{Identity, TlsConnector};
use tracing::info;

use crate::{error::result::KmipResult, KmipError, KmipResultHelper};

// load the string content at compile time - same as http_client.rs
const SERVER_CA_CERTIFICATE: &str = include_str!("server.crt");
const CLIENT_P12: &[u8; 2691] = include_bytes!("client.p12");

/// Configuration for the `PyKMIP` socket client
#[derive(Clone)]
pub(crate) struct PyKmipSocketClientConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Client PKCS#12 certificate and key
    pub client_p12: Vec<u8>,
    /// Client PKCS#12 secret
    pub client_p12_secret: String,
    /// Server CA certificate (PEM format, X509)
    pub server_ca_cert_pem: String,
}

impl Default for PyKmipSocketClientConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_owned(),
            port: 5696,
            client_p12: CLIENT_P12.to_vec(),
            client_p12_secret: "secret".to_owned(),
            server_ca_cert_pem: SERVER_CA_CERTIFICATE.to_owned(),
        }
    }
}

/// Client for communicating with a `PyKMIP` server over TLS socket
pub(crate) struct PyKmipSocketClient {
    config: PyKmipSocketClientConfig,
    connector: Arc<TlsConnector>,
}

impl PyKmipSocketClient {
    /// Create a new `PyKMIP` socket client with the specified configuration
    pub(crate) fn new(config: PyKmipSocketClientConfig) -> KmipResult<Self> {
        // Create client identity from cert and key
        let identity = Identity::from_pkcs12(&config.client_p12, &config.client_p12_secret)
            .context("Failed to create identity from client PKCS#12")?;

        // Build TLS connector with client certificate authentication
        let connector = TlsConnector::builder()
            .identity(identity)
            .add_root_certificate(
                native_tls::Certificate::from_pem(config.server_ca_cert_pem.as_bytes())
                    .context("Failed to create certificate from CA certificate data")?,
            )
            // Force TLS 1.2
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
            .max_protocol_version(Some(native_tls::Protocol::Tlsv12))
            .danger_accept_invalid_certs(true)
            .build()
            .context("Failed to build TLS connector")?;

        Ok(Self {
            config,
            connector: Arc::new(connector),
        })
    }

    /// Send a KMIP request to the server and return the response
    pub(crate) fn send_request(&self, data: &[u8]) -> KmipResult<Vec<u8>> {
        info!("Sending request: {}", hex::encode(data));

        // Connect to server
        let stream = TcpStream::connect((self.config.host.as_str(), self.config.port))
            .context("Failed to connect to PyKMIP server")?;

        // Establish TLS connection
        let mut tls_stream = self
            .connector
            .connect(&self.config.host, stream)
            .context("Failed to establish TLS connection")?;

        // Send request data
        tls_stream
            .write_all(data)
            .context("Failed to send request data")?;
        tls_stream.flush().context("Failed to flush TLS stream")?;

        info!("Request sent");

        // Read response
        let mut response = Vec::new();
        tls_stream
            .read_to_end(&mut response)
            .context("Failed to read response")?;

        if response.is_empty() {
            return Err(KmipError::Default(
                "Received empty response from server".to_owned(),
            ));
        }

        info!("Received response: {}", hex::encode(&response));
        Ok(response)
    }
}

/// Helper function to create a `PyKMIP` socket client with default configuration
pub(crate) fn create_default_client() -> KmipResult<PyKmipSocketClient> {
    PyKmipSocketClient::new(PyKmipSocketClientConfig::default())
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
        ttlv::{self, to_ttlv},
    };

    #[test]
    #[ignore] // Requires a running PyKMIP server
    fn test_connect_to_pykmip_server() {
        log_init(Some("trace"));
        let client = create_default_client().unwrap();

        // Create a simple KMIP request (same as HTTP client test)
        let request_data = request_message();
        let response = client.send_request(&request_data).unwrap();

        info!("Response length: {}", response.len());
        info!("Response: {}", hex::encode(&response));

        let ttlv = ttlv::TTLV::from_bytes_1_4(&response).unwrap();
        info!("Response TTLV: {:#?}", ttlv);

        // Check that we got a response
        assert!(!response.is_empty());
    }

    fn request_message() -> Vec<u8> {
        // KMIP Request Message (same as HTTP client test)
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
                request_payload: Operation::Query(Query {
                    query_function: vec![
                        QueryFunction::QueryOperations,
                        QueryFunction::QueryObjects,
                    ],
                }),
                message_extension: None,
            }],
        };

        let ttlv = to_ttlv(&request_message).unwrap();
        info!("Request TTLV: {:#?}", ttlv);
        ttlv.to_bytes_1_4().unwrap()
    }
}
