//! Socket client for communicating with a `py_kmip` server over TLS socket.
//! This client uses a PKCS#12 client certificate for authentication
//! and a server CA certificate for verifying the server's certificate.
//! The client is thread-safe and can be shared across threads
//! using `Arc`
use std::{
    collections::HashMap,
    fmt,
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, OnceLock},
};

use cosmian_kms_client_utils::reexport::cosmian_kmip::ttlv::{
    KmipFlavor, TTLV, from_ttlv, to_ttlv,
};
use cosmian_logger::debug;
use native_tls::{Identity, TlsConnector};
use serde::{Serialize, de::DeserializeOwned};

use crate::result::{KResult, KResultHelper};

/// Configuration for the `py_kmip` socket client
#[derive(Clone)]
pub(super) struct SocketClientConfig {
    /// Server hostname
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

/// Client for communicating with a `py_kmip` server over TLS socket.
///
/// This client uses a PKCS#12 client certificate for authentication
/// and a server CA certificate for verifying the server's certificate.
/// The client is thread-safe and can be shared across threads
/// using `Arc`
pub(super) struct SocketClient {
    config: SocketClientConfig,
    connector: Arc<TlsConnector>,
}

impl SocketClient {
    /// Create a new `py_kmip` socket client with the specified configuration
    ///
    /// # Arguments
    /// * `config` - Configuration for the socket client
    ///
    /// # Returns
    /// * `SocketClient` - A new socket client
    ///
    /// # Errors
    /// * If the PKCS#12 file cannot be parsed
    /// * If the TLS connector cannot be built
    /// * If the server CA certificate cannot be parsed
    /// * If the identity cannot be created
    /// * If the identity cannot be cached
    /// * If the identity cannot be retrieved from the cache
    /// * If the identity cannot be created from the PKCS#12 file
    pub(super) fn new(config: SocketClientConfig) -> KResult<Self> {
        // Create or retrieve client identity from cache
        // The reason we need this is that macOS keychain will sometimes complain
        // that "The specified item already exists in the keychain" when trying to create an identity
        let identity = {
            // Use a static cache for identities to avoid repeated parsing of PKCS12 files
            static IDENTITY_CACHE: OnceLock<Mutex<HashMap<Vec<u8>, Identity>>> = OnceLock::new();
            let cache = IDENTITY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

            let mut cache = cache.lock().context("Identity cache lock poisoned")?;

            // Try to get from cache first
            if let Some(cached_identity) = cache.get(&config.client_p12) {
                cached_identity.clone()
            } else {
                // Create new identity and cache it
                let identity = Identity::from_pkcs12(&config.client_p12, &config.client_p12_secret)
                    .context("Failed to create identity from client PKCS#12")?;
                cache.insert(config.client_p12.clone(), identity.clone());
                identity
            }
        };

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
    /// This method serializes the request to TTLV, then to bytes,
    /// sends the bytes to the server, reads the response bytes,
    /// deserializes the response bytes to TTLV, then to the response object
    ///
    /// # Arguments
    ///
    /// * `kmip_flavor` - KMIP flavor to use for serialization
    /// * `request` - Request object to send
    ///
    /// # Returns
    ///
    /// * `RESP` - Response object
    ///
    /// # Errors
    ///
    /// * If serialization or deserialization fails
    /// * If sending or receiving data fails
    /// * If the server returns an error response
    /// * If the response is invalid
    #[allow(clippy::cognitive_complexity)]
    pub(super) fn send_request<
        REQ: Serialize + fmt::Display,
        RESP: DeserializeOwned + fmt::Display,
    >(
        &self,
        kmip_flavor: KmipFlavor,
        request: &REQ,
    ) -> KResult<RESP> {
        debug!("REQ:\n{}", request);
        // Serialize to TTLV
        let ttlv_request = to_ttlv(request).context("Failed to serialize request to TTLV")?;
        debug!("TTLV REQ:\n{:#?}", ttlv_request);
        // Serialize to bytes
        let request_data = ttlv_request
            .to_bytes(kmip_flavor)
            .context("Failed to serialize TTLV to bytes")?;

        // Send request
        let response_data = self.send_raw_request(&request_data)?;

        // Deserialize response
        let ttlv_response = TTLV::from_bytes(&response_data, kmip_flavor)
            .context("Failed to deserialize response TTLV")?;

        debug!("TTLV RESP:\n{:#?}", ttlv_response);

        // Deserialize response
        let response = from_ttlv(ttlv_response)?;
        debug!("RESP:\n{}", response);

        Ok(response)
    }

    /// Send a KMIP request to the server and return the response
    pub(super) fn send_raw_request(&self, data: &[u8]) -> KResult<Vec<u8>> {
        debug!("Sending request: {}", hex::encode(data));

        // Connect to server
        let stream = TcpStream::connect((self.config.host.as_str(), self.config.port))
            .context("Failed to connect to py_kmip server")?;

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

        debug!("Request sent");

        // Read response
        // Read 8 bytes of the TTLV header
        let mut header = [0_u8; 8];
        tls_stream
            .read_exact(&mut header)
            .context("Failed to read response header")?;
        let length = usize::try_from(u32::from_be_bytes([
            header[4], header[5], header[6], header[7],
        ]))?;

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
