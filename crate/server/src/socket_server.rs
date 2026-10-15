use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, RwLock, mpsc},
    thread,
    time::Duration,
};

use cosmian_logger::{debug, error, info, trace, warn};
use openssl::ssl::{SslAcceptor, SslStream, SslVerifyMode};
use tokio::task::JoinHandle;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
    tls_config::{TlsConfig, configure_client_cert_verification, create_base_openssl_acceptor},
};

/// Configuration for the `py_kmip` socket server
#[derive(Clone)]
pub struct SocketServerParams<'a> {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Server certificate and private key (PKCS#12 format) - non-fips
    #[cfg(feature = "non-fips")]
    pub p12: Option<&'a openssl::pkcs12::ParsedPkcs12_2>,
    /// Server certificate and private key (PEM) - FIPS mode
    pub server_cert_pem: &'a [u8],
    pub server_key_pem: &'a [u8],
    pub server_chain_pem: Option<&'a [u8]>,
    /// Client CA certificate (PEM format, X509)
    pub client_ca_cert_pem: &'a [u8],
    /// Configured cipher suites to use for TLS connections (OpenSSL cipher string format)
    pub cipher_suites: Option<&'a String>,
}

impl<'a> TryFrom<&'a ServerParams> for SocketServerParams<'a> {
    type Error = KmsError;

    fn try_from(params: &'a ServerParams) -> Result<Self, Self::Error> {
        let Some(tls_params) = &params.tls_params else {
            return Err(KmsError::NotSupported(
                "The Socket server cannot be started: TLS parameters are not set".to_owned(),
            ));
        };
        let Some(client_ca_cert_pem) = &tls_params.clients_ca_cert_pem else {
            return Err(KmsError::NotSupported(
                "The Socket server cannot be started: Client CA certificate is not set".to_owned(),
            ));
        };
        Ok(Self {
            host: params.socket_server_hostname.clone(),
            port: params.socket_server_port,
            #[cfg(feature = "non-fips")]
            p12: tls_params.p12.as_ref(),
            client_ca_cert_pem,
            cipher_suites: tls_params.cipher_suites.as_ref(),
            server_cert_pem: &tls_params.server_cert_pem,
            server_key_pem: &tls_params.server_key_pem,
            server_chain_pem: tls_params.server_chain_pem.as_deref(),
        })
    }
}

/// Server for handling `py_kmip` requests over TLS socket
pub struct SocketServer {
    host: String,
    port: u16,
    server_config: Arc<SslAcceptor>,
}

impl SocketServer {
    /// Create a new `py_kmip` socket server with the specified configuration
    ///
    /// # Errors
    /// - If the server certificates and key are invalid
    /// - If the client CA certificate is invalid
    /// - If the server fails to bind to the specified host and port
    pub fn instantiate(config: &SocketServerParams) -> KResult<Self> {
        let server_config = Arc::new(create_openssl_acceptor(config)?);
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
    /// # Arguments
    ///
    /// * `request_handler`: A function that handles incoming requests.
    /// * It takes the username and request bytes as input and returns the response bytes.
    /// * The function must be `Send`, `Sync`, and `'static` to be used in a thread.
    ///
    /// # Errors
    /// - If the server fails to bind to the specified host and port
    /// - If an error occurs while handling a client connection
    pub fn start<F>(
        &self,
        kms_server: &Arc<KMS>,
        request_handler: F,
        command_receiver: mpsc::Receiver<KResult<()>>,
    ) -> KResult<()>
    where
        F: Fn(&str, &[u8], Arc<KMS>) -> Vec<u8> + Send + Sync + 'static,
    {
        let addr = format!("{}:{}", self.host, self.port);
        let server_config = self.server_config.clone();
        let handler = Arc::new(request_handler);
        Self::start_listening(
            kms_server,
            &addr,
            &server_config,
            &handler,
            command_receiver,
            None,
            None,
        )?;
        Ok(())
    }

    /// Start the server in a separate thread and listen for incoming connections
    /// The `request_handler` function is called for each incoming request.
    /// The function should take a byte slice as input and return a byte vector as output.
    /// The server runs in a separate thread for each client connection.
    /// The server will continue to run until the process is terminated.
    ///
    /// # Arguments
    ///
    /// * `request_handler`: A function that handles incoming requests.
    /// * It takes the username and request bytes as input and returns the response bytes.
    /// * The function must be `Send`, `Sync`, and `'static` to be used in a thread.
    /// * `pre_bound_listener`: An optional pre-bound `TcpListener` for the socket server's
    ///   `host:port`. When provided, it is used directly instead of re-binding by address,
    ///   eliminating the TOCTOU race that a probe-then-release port allocation would have
    ///   under highly parallel test execution.
    ///
    /// # Errors
    /// - If the server fails to bind to the specified host and port
    /// - If an error occurs while handling a client connection
    pub fn start_threaded<F>(
        &self,
        kms_server: Arc<KMS>,
        request_handler: F,
        command_receiver: mpsc::Receiver<KResult<()>>,
        pre_bound_listener: Option<TcpListener>,
    ) -> KResult<JoinHandle<()>>
    where
        F: Fn(&str, &[u8], Arc<KMS>) -> Vec<u8> + Send + Sync + 'static,
    {
        let addr = format!("{}:{}", self.host, self.port);
        let server_config = self.server_config.clone();
        let handler = Arc::new(request_handler);
        let (tx, rx) = mpsc::channel::<KResult<()>>();

        let thread_handle = tokio::spawn(async move {
            // We swallow the error, if any; the mpsc receiver will receive it
            let _swallowed = Self::start_listening(
                &kms_server,
                &addr,
                &server_config,
                &handler,
                command_receiver,
                Some(tx),
                pre_bound_listener,
            );
        });
        trace!("Waiting for test socket server to start...");
        let state = rx
            .recv_timeout(Duration::from_secs(25))
            .context("Can't get the socket server to start after 25 seconds")?;
        // if the server failed to start, the returned state will be in error
        state?;
        Ok(thread_handle)
    }

    fn start_listening<F>(
        kms_server: &Arc<KMS>,
        addr: &str,
        server_config: &Arc<SslAcceptor>,
        handler: &Arc<F>,
        command_receiver: mpsc::Receiver<KResult<()>>,
        start_notifier: Option<mpsc::Sender<KResult<()>>>,
        pre_bound_listener: Option<TcpListener>,
    ) -> Result<(), KmsError>
    where
        F: Fn(&str, &[u8], Arc<KMS>) -> Vec<u8> + Send + Sync + 'static,
    {
        // Use the pre-bound listener when given (eliminates the TOCTOU race between
        // probing a free port and re-binding it later); otherwise bind fresh by address.
        let bind_result = pre_bound_listener.map_or_else(|| TcpListener::bind(addr), Ok);
        let listener = match bind_result.context(&format!("Failed to bind to {addr}")) {
            Ok(listener) => {
                info!("Socket server listening on {}", addr);
                if let Some(notifier) = start_notifier {
                    notifier
                        .send(Ok(()))
                        .context("Failed to notify the successful socket server start")?;
                }
                listener
            }
            Err(e) => {
                let error_msg = e.to_string(); // keep the message before moving the error
                if let Some(notifier) = start_notifier {
                    notifier
                        .send(Err(e))
                        .context("Failed to notify the error on socket server start")?;
                }
                kms_bail!("Failed to bind to {addr}: {}", error_msg);
            }
        };

        // Setup for handling command receiver if it exists
        let stop_requested = Arc::new(RwLock::new(false));
        let stop_requested_clone = stop_requested.clone();
        // Use a separate thread to listen for stop signals
        let listener_clone = listener
            .try_clone()
            .context("Failed to clone TCP listener")?;
        thread::spawn(move || {
            if let Ok(result) = command_receiver.recv() {
                // If we receive any message, signal to stop
                debug!("Socket server received stop signal: {result:?}",);
                if let Err(e) = result {
                    error!("Socket server stop signal contained error: {}", e);
                }
                if let Ok(mut stop_requested) = stop_requested_clone.try_write().map_err(|e| {
                    error!(
                        "Socket server failed to acquire write lock for stop request: {}",
                        e
                    );
                }) {
                    *stop_requested = true;
                    // Trigger a connection to ourselves to break the `accept` loop
                    if let Ok(local_address) = listener_clone.local_addr() {
                        // On Windows, connecting to an unspecified address (0.0.0.0 or ::) fails (os error 10049).
                        // Prefer loopback when the listener is bound to an unspecified address.
                        let connect_addr = match local_address.ip() {
                            std::net::IpAddr::V4(ipv4) if ipv4.is_unspecified() => {
                                std::net::SocketAddr::new(
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                    local_address.port(),
                                )
                            }
                            std::net::IpAddr::V6(ipv6) if ipv6.is_unspecified() => {
                                std::net::SocketAddr::new(
                                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                                    local_address.port(),
                                )
                            }
                            _ => local_address,
                        };
                        if let Ok(_c) =
                            TcpStream::connect_timeout(&connect_addr, Duration::from_secs(5))
                                .map_err(|e| {
                                    error!("Socket server failed to connect to itself: {}", e);
                                })
                        {
                            info!("Socket server stop signal sent");
                        }
                    } else {
                        error!("Socket server failed to get local address for stop signal");
                    }
                } else {
                    error!("Socket server failed to write stop request");
                }
            }
        });

        // Accept incoming connections
        for stream in listener.incoming() {
            if *stop_requested
                .read()
                .context("Failed to read stop request")?
            {
                info!("Socket server shutting down due to stop request");
                break;
            }

            match stream {
                Ok(mut stream) => {
                    // Check if this is a self-connection to break the loop
                    if *stop_requested
                        .read()
                        .context("Failed to read stop request")?
                    {
                        break;
                    }
                    // Accept incoming connections
                    let server_config = server_config.clone();
                    let handler = handler.clone();
                    // Spawn a new thread to handle the client connection
                    let kms_server = kms_server.clone();
                    thread::spawn(move || {
                        if let Err(e) =
                            handle_client(&kms_server, &server_config, &handler, &mut stream)
                        {
                            error!("Error handling socket client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Socket server: connection failed: {e}");
                }
            }
        }
        Ok(())
    }
}

fn handle_client(
    kms_server: &Arc<KMS>,
    server_config: &Arc<SslAcceptor>,
    handler: &Arc<impl Fn(&str, &[u8], Arc<KMS>) -> Vec<u8> + Send + Sync>,
    stream: &mut TcpStream,
) -> KResult<()> {
    // Accept TLS connection
    let peer_addr = stream
        .peer_addr()
        .map_or_else(|_| "[N/A]".to_owned(), |sa| sa.to_string());
    debug!("socket server: client connected from {}", peer_addr);

    let mut tls_stream = server_config
        .accept(stream)
        .context("socket server: failed to create OpenSSL TLS connection")?;

    loop {
        // Read 8 bytes of the TTLV header
        let mut header = [0_u8; 8];
        match tls_stream.read_exact(&mut header) {
            Ok(()) => {
                let username = client_username(&tls_stream)?;

                // Parse length from header
                let length = usize::try_from(u32::from_be_bytes([
                    header[4], header[5], header[6], header[7],
                ]))
                .context("socket server: failed to parse request length")?;

                // Read the rest of the request directly into a single contiguous buffer
                let mut request = vec![0_u8; 8 + length];
                request
                    .get_mut(..8)
                    .context("socket server: failed to get header slice")?
                    .copy_from_slice(&header);
                let body_slice = request
                    .get_mut(8..)
                    .context("socket server: failed to get body slice")?;
                tls_stream
                    .read_exact(body_slice)
                    .context("socket server: failed to read request body")?;
                debug!("socket server: received request: {}", hex::encode(&request));

                // Process the request
                let response = handler(&username, &request, kms_server.clone());

                // Send the response
                tls_stream
                    .write_all(&response)
                    .context("socket server: failed to send response")?;

                tls_stream
                    .flush()
                    .context("socket server: failed to flush TLS stream")?;

                trace!("Response sent to {}", peer_addr);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client disconnected
                debug!("socket server: client {} disconnected", peer_addr);
                break;
            }
            Err(e) => {
                return Err(e).context("socket server: failed to read request header");
            }
        }
    }

    Ok(())
}

/// Extract the common name from the client certificate which is used as the username
fn client_username(tls_stream: &SslStream<&mut TcpStream>) -> Result<String, KmsError> {
    let client_certificate = tls_stream.ssl().peer_certificate().ok_or_else(|| {
        // unreachable: the acceptor sets FAIL_IF_NO_PEER_CERT (see `create_openssl_acceptor`)
        KmsError::Certificate(
            "socket server: the client did not provide a peer certificate".to_owned(),
        )
    })?;

    // The certificate is already an X509 object with OpenSSL
    let x509 = client_certificate;
    x509.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .ok_or_else(|| {
            KmsError::Certificate("socket server: failed to get common name".to_owned())
        })?
        .data()
        .to_string()
        .map_err(|_e| {
            KmsError::Certificate(
                "socket server: failed to convert common name to UTF-8".to_owned(),
            )
        })
}

// Client Certificate Authentication
// Build an OpenSSL SslAcceptor supporting client cert auth
pub(crate) fn create_openssl_acceptor(server_config: &SocketServerParams) -> KResult<SslAcceptor> {
    trace!("Creating OpenSSL SslAcceptor for socket server");

    // Use the common TLS configuration
    let tls_config = TlsConfig {
        #[cfg(feature = "non-fips")]
        p12: server_config.p12,
        cipher_suites: server_config.cipher_suites.map(std::string::String::as_str),
        server_cert_pem: server_config.server_cert_pem,
        server_key_pem: server_config.server_key_pem,
        server_chain_pem: server_config.server_chain_pem,
        client_ca_cert_pem: Some(server_config.client_ca_cert_pem),
    };

    let mut builder = create_base_openssl_acceptor(&tls_config, "socket server")?;

    // Configure client certificate verification (required for socket server)
    configure_client_cert_verification(
        &mut builder,
        server_config.client_ca_cert_pem,
        "socket server",
    )?;
    // The socket server authenticates exclusively via mTLS: abort the handshake
    // when the client sends no certificate (the shared helper only sets PEER).
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    // OpenSSL requires a session ID context when both client certificate verification
    // and TLS session caching are enabled (the default). Without it, session
    // resumption attempts fail with ssl_get_prev_session:session id context
    // uninitialized (error:0A000115).
    builder
        .set_session_id_context(b"cosmian_kms_socket")
        .context("socket server: failed to set TLS session ID context")?;

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, io, net::TcpListener, thread};

    use openssl::{
        pkey::PKey,
        ssl::{SslConnector, SslConnectorBuilder, SslFiletype, SslMethod, SslVerifyMode},
        x509::X509,
    };

    use super::{SocketServerParams, create_openssl_acceptor};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    const CERTS: &str = "../../test_data/certificates/client_server";

    /// Run one server-side TLS handshake against a client built by `client_setup`
    /// and return whether the *server* accepted the handshake.
    fn server_accepts(
        client_setup: impl FnOnce(&mut SslConnectorBuilder) -> TestResult,
    ) -> TestResult<bool> {
        let cert = fs::read(format!("{CERTS}/server/kmserver.acme.com.crt"))?;
        let key = PKey::private_key_from_pem(&fs::read(format!(
            "{CERTS}/server/kmserver.acme.com.key"
        ))?)?
        .private_key_to_pem_pkcs8()?;
        let ca = fs::read(format!("{CERTS}/ca/ca.crt"))?;
        let params = SocketServerParams {
            host: "127.0.0.1".to_owned(),
            port: 0,
            #[cfg(feature = "non-fips")]
            p12: None,
            server_cert_pem: &cert,
            server_key_pem: &key,
            server_chain_pem: None,
            client_ca_cert_pem: &ca,
            cipher_suites: None,
        };
        let acceptor = create_openssl_acceptor(&params)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<bool> {
            let (stream, _) = listener.accept()?;
            Ok(acceptor.accept(stream).is_ok())
        });

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::NONE);
        client_setup(&mut builder)?;
        let stream = std::net::TcpStream::connect(addr)?;
        // The client may succeed or fail (TLS 1.3 client finishes before the server
        // alert arrives); only the server verdict matters.
        let _client = builder.build().connect("kmserver.acme.com", stream);
        Ok(server.join().map_err(|_e| "server thread panicked")??)
    }

    #[test]
    fn handshake_fails_without_client_certificate() -> TestResult {
        if server_accepts(|_| Ok(()))? {
            return Err("server accepted a handshake without a client certificate".into());
        }
        Ok(())
    }

    #[test]
    fn handshake_succeeds_with_valid_client_certificate() -> TestResult {
        let accepted = server_accepts(|b| {
            let cert =
                X509::from_pem(&fs::read(format!("{CERTS}/user/user.client.acme.com.crt"))?)?;
            b.set_certificate(&cert)?;
            b.set_private_key_file(
                format!("{CERTS}/user/user.client.acme.com.key"),
                SslFiletype::PEM,
            )?;
            Ok(())
        })?;
        if !accepted {
            return Err("server rejected a valid client certificate".into());
        }
        Ok(())
    }
}
