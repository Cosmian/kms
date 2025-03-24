use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use native_tls::{Identity, TlsConnector};
use tracing::{debug, info};

use crate::{error::result::KmipResult, KmipResultHelper};

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
        // Read 8 bytes of the TTLV header
        let mut header = [0_u8; 8];
        tls_stream
            .read_exact(&mut header)
            .context("Failed to read response header")?;
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // Read the rest of the response
        let mut response = vec![0_u8; length];
        tls_stream
            .read_exact(&mut response)
            .context("Failed to read response")?;

        // concat the header and the rest of the response
        let response = [header.to_vec(), response].concat();

        // Log response
        debug!("Received response: {}", hex::encode(&response));

        // Return response
        Ok(response)
    }
}

/// Helper function to create a `PyKMIP` socket client with default configuration
pub(crate) fn create_default_client() -> KmipResult<PyKmipSocketClient> {
    PyKmipSocketClient::new(PyKmipSocketClientConfig::default())
}
