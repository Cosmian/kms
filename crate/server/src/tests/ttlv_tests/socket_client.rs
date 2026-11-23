//! Socket client for communicating with a `py_kmip` server over TLS socket.
//! This client uses a PKCS#12 client certificate for authentication
//! and a server CA certificate for verifying the server's certificate.
//! The client is thread-safe and can be shared across threads
//! using `Arc`
use std::{
    fmt,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use cosmian_kms_client_utils::reexport::cosmian_kmip::ttlv::{
    KmipFlavor, TTLV, from_ttlv, to_ttlv,
};
use cosmian_logger::debug;
use openssl::{
    pkcs12::Pkcs12,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
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
    connector: Arc<SslConnector>,
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
    /// * If the PKCS#12 file cannot be parsed or decrypted
    /// * If the TLS connector cannot be built
    /// * If the server CA certificate cannot be parsed
    pub(super) fn new(config: SocketClientConfig) -> KResult<Self> {
        let p12 = Pkcs12::from_der(&config.client_p12)
            .context("Failed to parse client PKCS#12")?
            .parse2(&config.client_p12_secret)
            .context("Failed to decrypt client PKCS#12")?;

        // Build TLS connector with client certificate authentication
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .context("Failed to create TLS connector")?;
        if let Some(cert) = &p12.cert {
            builder
                .set_certificate(cert)
                .context("Failed to set client certificate")?;
        }
        if let Some(key) = &p12.pkey {
            builder
                .set_private_key(key)
                .context("Failed to set client private key")?;
        }
        for ca in p12.ca.into_iter().flatten() {
            builder
                .add_extra_chain_cert(ca)
                .context("Failed to add client chain certificate")?;
        }
        builder
            .cert_store_mut()
            .add_cert(
                X509::from_pem(config.server_ca_cert_pem.as_bytes())
                    .context("Failed to create certificate from CA certificate data")?,
            )
            .context("Failed to add CA certificate")?;
        // Force TLS 1.2
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .context("Failed to set min TLS version")?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .context("Failed to set max TLS version")?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

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
        let response = from_ttlv(&ttlv_response)?;
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
