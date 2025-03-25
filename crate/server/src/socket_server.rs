use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Once},
    thread,
};

use openssl::pkcs12::Pkcs12;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig, ServerConnection,
};
use tracing::{debug, error, info, trace};

use crate::{
    error::KmsError,
    result::{KResult, KResultHelper},
};
static INIT_CRYPTO: Once = Once::new();

/// Initialize the crypto provider used by rustls.
/// Use AWS LC crypto provider which is FIPS certified
fn initialize_aws_lc_crypto_provider() {
    {
        INIT_CRYPTO.call_once(|| {
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            if let Err(_e) = provider.install_default() {
                let err = "Failed to install the aws_lc crypto provider".to_owned();
                error!("{err}");
                // Downstream code will likely fail but graciously
            }
        });
    }
}

/// Configuration for the `PyKMIP` socket server
#[derive(Clone)]
pub struct SocketServerConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Server certificates and key (PKCS#12 format)
    pub server_p12_der: Vec<u8>,
    /// Server PKCS#12 password
    pub server_p12_password: String,
    /// Client CA certificate (PEM format, X509)
    pub client_ca_cert_pem: String,
}

/// Server for handling `PyKMIP` requests over TLS socket
pub struct SocketServer {
    host: String,
    port: u16,
    server_config: Arc<ServerConfig>,
}

impl SocketServer {
    /// Create a new `PyKMIP` socket server with the specified configuration
    ///
    /// # Errors
    /// - If the server certificates and key are invalid
    /// - If the client CA certificate is invalid
    /// - If the server fails to bind to the specified host and port
    pub fn instantiate(config: &SocketServerConfig) -> KResult<Self> {
        let server_config = Arc::new(create_rustls_server_config(
            &config.server_p12_der,
            &config.server_p12_password,
            &config.client_ca_cert_pem,
        )?);
        Ok(Self {
            host: config.host.clone(),
            port: config.port,
            server_config,
        })
    }

    /// Start the server and listen for incoming connections
    /// The `request_handler` function is called for each incoming request.
    /// The function should take a byte slice as input and return a byte vector as output.
    /// The server runs in a separate thread for each client connection.
    /// The server will continue to run until an error occurs
    /// or the process is terminated.
    ///
    /// # Errors
    /// - If the server fails to bind to the specified host and port
    /// - If an error occurs while handling a client connection
    pub fn start<F>(&self, request_handler: F) -> KResult<()>
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).context(&format!("Failed to bind to {addr}"))?;

        info!("Server listening on {}", addr);

        let server_config = self.server_config.clone();
        let handler = Arc::new(request_handler);

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let server_config = server_config.clone();
                    let handler = handler.clone();

                    thread::spawn(move || {
                        if let Err(e) = handle_client(&mut stream, server_config, &handler) {
                            error!("Error handling client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        }

        Ok(())
    }
}

fn handle_client(
    stream: &mut TcpStream,
    server_config: Arc<ServerConfig>,
    handler: &Arc<impl Fn(&[u8]) -> Vec<u8> + Send + Sync>,
) -> KResult<()> {
    // Accept TLS connection
    let peer_addr = stream
        .peer_addr()
        .map_or("[N/A]".to_owned(), |sa| sa.to_string());
    debug!("Client connected from {}", peer_addr);

    let mut server_connection = ServerConnection::new(server_config)
        .context("Failed to create rustls server connection")?;

    let mut tls_stream = rustls::Stream::new(&mut server_connection, stream);

    loop {
        // Read 8 bytes of the TTLV header
        let mut header = [0_u8; 8];
        match tls_stream.read_exact(&mut header) {
            Ok(()) => {
                // Parse length from header
                let length = usize::try_from(u32::from_be_bytes([
                    header[4], header[5], header[6], header[7],
                ]))
                .context("Failed to parse request length")?;

                // Read the rest of the request
                let mut request_body = vec![0_u8; length];
                tls_stream
                    .read_exact(&mut request_body)
                    .context("Failed to read request body")?;

                // Concatenate header and body
                let request = [header.to_vec(), request_body].concat();

                debug!("Received request: {}", hex::encode(&request));

                // Process the request
                let response = handler(&request);

                // Send the response
                tls_stream
                    .write_all(&response)
                    .context("Failed to send response")?;

                tls_stream.flush().context("Failed to flush TLS stream")?;

                trace!("Response sent to {}", peer_addr);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client disconnected
                info!("Client {} disconnected", peer_addr);
                break;
            }
            Err(e) => {
                return Err(e).context("Failed to read request header");
            }
        }
    }

    Ok(())
}

// Client Certificate Authentication
// Build a rustls ServerConfig supporting client cert auth
pub(crate) fn create_rustls_server_config(
    server_p12_der: &[u8],
    server_p12_password: &str,
    client_ca_cert_pem: &str,
) -> KResult<ServerConfig> {
    // We need an initialized crypto provider to use rustls
    initialize_aws_lc_crypto_provider();

    // Parse the byte vector as a PKCS#12 object - this uses openssl
    let sealed_p12 = Pkcs12::from_der(server_p12_der)?;
    let p12 = sealed_p12
        .parse2(server_p12_password)
        .context("HTTPS configuration")?;

    let mut certs: Vec<CertificateDer> = Vec::new();

    let Some(server_cert) = p12.cert else {
        return Err(KmsError::Certificate(
            "No server certificate found in PKCS#12 file".to_owned(),
        ));
    };
    let server_cert = server_cert
        .to_der()
        .context("Failed to encode server certificate in DER bytes")?;
    certs.push(CertificateDer::from(server_cert));
    if let Some(cas) = p12.ca {
        for ca in cas.iter().rev() {
            let der_bytes = ca
                .to_der()
                .context("Failed to encode CA certificate in DER bytes")?;
            certs.push(CertificateDer::from(der_bytes));
        }
    }

    let Some(server_private_key) = p12.pkey else {
        return Err(KmsError::Certificate(
            "No server private key found in PKCS#12 file".to_owned(),
        ));
    };
    let server_private_key_pkcs8 = server_private_key
        .private_key_to_pkcs8()
        .context("Failed to generate the server private key as PKCS#8")?;
    let server_private_key = PrivatePkcs8KeyDer::from(server_private_key_pkcs8);

    // Create the clients' CA certificate store
    let mut client_auth_roots = RootCertStore::empty();
    let client_ca_cert = CertificateDer::from_pem_slice(client_ca_cert_pem.as_bytes())
        .context("failed loading the clients'  CA certificate")?;
    client_auth_roots
        .add(client_ca_cert)
        .context("failed to add client CA cert")?;

    // Enable the client certificate verifier
    let client_auth = WebPkiClientVerifier::builder(client_auth_roots.into())
        .build()
        .context("failed to create client auth verifier")?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(server_private_key))
        .context("Invalid server certificate or key")?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(server_config)
}
