use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
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
    middlewares::user_from_client_certificate,
    middlewares::{UserId, client_cert_username},
    result::{KResult, KResultHelper},
    tls_config::{TlsConfig, configure_client_cert_verification, create_base_openssl_acceptor},
};

/// Timeout for the (unauthenticated) TLS handshake, so pre-auth clients release their slot quickly.
const SOCKET_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle/read/write timeout of an authenticated client socket (same as the HTTP keep-alive).
const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(120);
/// Maximum number of concurrent client connections (one OS thread each).
const MAX_SOCKET_CONNECTIONS: usize = 1024;
/// Maximum TTLV request body size, same as the HTTP payload limit.
const MAX_SOCKET_REQUEST_BODY: usize = 64 * 1024 * 1024;

/// Releases a connection slot when the client thread ends, even on panic.
struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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

        let active_connections = Arc::new(AtomicUsize::new(0));
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
                    // Reserve a slot atomically so the counter never exceeds the limit.
                    if active_connections
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                            (n < MAX_SOCKET_CONNECTIONS).then_some(n + 1)
                        })
                        .is_err()
                    {
                        warn!(
                            "Socket server: {MAX_SOCKET_CONNECTIONS} connections already active, \
                             dropping new connection"
                        );
                        continue;
                    }
                    let slot = ConnectionSlot(active_connections.clone());
                    // Bound the TLS handshake so unauthenticated or slow clients cannot hold a
                    // thread forever; `handle_client` switches to the idle timeout afterwards.
                    if let Err(e) = stream
                        .set_read_timeout(Some(SOCKET_HANDSHAKE_TIMEOUT))
                        .and_then(|()| stream.set_write_timeout(Some(SOCKET_HANDSHAKE_TIMEOUT)))
                    {
                        warn!(
                            "Socket server: cannot set socket timeouts, dropping connection: {e}"
                        );
                        continue;
                    }
                    let server_config = server_config.clone();
                    let handler = handler.clone();
                    // Spawn a new thread to handle the client connection
                    let kms_server = kms_server.clone();
                    thread::spawn(move || {
                        let _slot = slot;
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
    tls_stream
        .get_ref()
        .set_read_timeout(Some(SOCKET_IO_TIMEOUT))
        .and_then(|()| {
            tls_stream
                .get_ref()
                .set_write_timeout(Some(SOCKET_IO_TIMEOUT))
        })
        .context("socket server: failed to set socket timeouts")?;

    while let Some(request) = read_request(&mut tls_stream)? {
        let username = client_username(&tls_stream)?;
        debug!("socket server: received request: {}", hex::encode(&request));

        // Process the request
        let response = handler(username.as_str(), &request, kms_server.clone());

        // Send the response
        tls_stream
            .write_all(&response)
            .context("socket server: failed to send response")?;

        tls_stream
            .flush()
            .context("socket server: failed to flush TLS stream")?;

        trace!("Response sent to {}", peer_addr);
    }
    debug!("socket server: client {} disconnected", peer_addr);

    Ok(())
}

/// Read one TTLV message (8-byte header followed by its body).
///
/// Returns `Ok(None)` when the client closed the connection or stayed idle past
/// [`SOCKET_IO_TIMEOUT`]. The declared length is checked before allocating the body.
fn read_request(stream: &mut impl Read) -> KResult<Option<Vec<u8>>> {
    let mut header = [0_u8; 8];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::TimedOut | ErrorKind::WouldBlock
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e).context("socket server: failed to read request header"),
    }
    let length = usize::try_from(u32::from_be_bytes([
        header[4], header[5], header[6], header[7],
    ]))
    .context("socket server: failed to parse request length")?;
    if length > MAX_SOCKET_REQUEST_BODY {
        kms_bail!(KmsError::InvalidRequest(format!(
            "socket server: request body of {length} bytes exceeds the \
             {MAX_SOCKET_REQUEST_BODY} bytes limit"
        )));
    }

    // Read the rest of the request directly into a single contiguous buffer
    let mut request = vec![0_u8; 8 + length];
    request
        .get_mut(..8)
        .context("socket server: failed to get header slice")?
        .copy_from_slice(&header);
    stream
        .read_exact(
            request
                .get_mut(8..)
                .context("socket server: failed to get body slice")?,
        )
        .context("socket server: failed to read request body")?;
    Ok(Some(request))
}

/// Extract the username from the client certificate, with the same checks as HTTP mTLS.
fn client_username(tls_stream: &SslStream<&mut TcpStream>) -> KResult<UserId> {
    let client_certificate = tls_stream.ssl().peer_certificate().ok_or_else(|| {
        // unreachable: the acceptor sets FAIL_IF_NO_PEER_CERT (see `create_openssl_acceptor`)
        KmsError::Certificate(
            "socket server: the client did not provide a peer certificate".to_owned(),
        )
    })?;
    client_cert_username(&client_certificate)
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
    use std::{
        error::Error,
        fs, io,
        net::{TcpListener, TcpStream},
        thread,
    };

    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        ssl::{
            SslConnector, SslConnectorBuilder, SslFiletype, SslMethod, SslStream, SslVerifyMode,
        },
        x509::{X509, X509NameBuilder, extension::BasicConstraints},
    };

    use super::{
        MAX_SOCKET_REQUEST_BODY, SocketServerParams, client_username, create_openssl_acceptor, read_request,
    };
    use crate::routes::{aws_xks::AWS_XKS_SERVICE_USER, enrollment::ENROLLMENT_SERVICE_USER};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    const CERTS: &str = "../../test_data/certificates/client_server";

    /// Run one server-side TLS handshake against a client built by `client_setup` and return
    /// `on_accept` applied to the accepted server stream (`None` when the server refused it).
    fn serve_one<T: Send + 'static>(
        client_setup: impl FnOnce(&mut SslConnectorBuilder) -> TestResult,
        on_accept: impl FnOnce(&SslStream<&mut TcpStream>) -> T + Send + 'static,
    ) -> TestResult<Option<T>> {
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
        let server = thread::spawn(move || -> io::Result<Option<T>> {
            let (mut stream, _) = listener.accept()?;
            Ok(acceptor.accept(&mut stream).ok().map(|tls| on_accept(&tls)))
        });

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::NONE);
        client_setup(&mut builder)?;
        let stream = TcpStream::connect(addr)?;
        // The client may succeed or fail (TLS 1.3 client finishes before the server
        // alert arrives); only the server verdict matters.
        let _client = builder.build().connect("kmserver.acme.com", stream);
        Ok(server.join().map_err(|_e| "server thread panicked")??)
    }

    /// Run one server-side TLS handshake and return whether the *server* accepted it.
    fn server_accepts(
        client_setup: impl FnOnce(&mut SslConnectorBuilder) -> TestResult,
    ) -> TestResult<bool> {
        Ok(serve_one(client_setup, |_| ())?.is_some())
    }

    /// A client certificate for `cn`, issued by the trusted test client CA.
    fn client_certificate(cn: &str, key: &PKey<Private>) -> TestResult<X509> {
        let ca = X509::from_pem(&fs::read(format!("{CERTS}/ca/ca.crt"))?)?;
        let ca_key = PKey::private_key_from_pem(&fs::read(format!("{CERTS}/ca/ca.key"))?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_nid(Nid::COMMONNAME, cn)?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_serial_number(BigNum::from_u32(1)?.to_asn1_integer()?.as_ref())?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(ca.subject_name())?;
        builder.set_pubkey(key)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        builder.append_extension(BasicConstraints::new().build()?)?;
        builder.sign(&ca_key, MessageDigest::sha256())?;
        Ok(builder.build())
    }

    /// Username the socket server resolves for a client presenting a CA-issued certificate
    /// for `cn`; the outer error means the TLS handshake itself failed.
    fn socket_username(cn: &str, key: &PKey<Private>) -> TestResult<Result<String, String>> {
        let cert = client_certificate(cn, key)?;
        let key = key.clone();
        Ok(serve_one(
            move |b| {
                b.set_certificate(&cert)?;
                b.set_private_key(&key)?;
                Ok(())
            },
            |tls| client_username(tls).map_err(|e| e.to_string()),
        )?
        .ok_or("the TLS handshake must succeed: the certificate is CA-issued")?)
    }

    #[test]
    fn reserved_service_identity_cn_is_rejected() -> TestResult {
        let key = PKey::private_key_from_pem(&fs::read(format!(
            "{CERTS}/user/user.client.acme.com.key"
        ))?)?;
        for cn in [ENROLLMENT_SERVICE_USER, AWS_XKS_SERVICE_USER] {
            if let Ok(user) = socket_username(cn, &key)? {
                return Err(
                    format!("socket server resolved reserved CN {cn} to user {user}").into(),
                );
            }
        }
        // Control: a regular certificate from the same CA resolves to its CN.
        let user = socket_username("alice@example.com", &key)??;
        if user != "alice@example.com" {
            return Err(format!("unexpected username {user}").into());
        }
        Ok(())
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

    fn ttlv_header(length: u32) -> Vec<u8> {
        let mut header = vec![0x42, 0x00, 0x78, 0x01];
        header.extend_from_slice(&length.to_be_bytes());
        header
    }

    /// A declared length above the limit is refused before the body buffer is allocated.
    #[test]
    fn oversized_request_is_rejected_before_allocation() -> TestResult {
        let too_big = u32::try_from(MAX_SOCKET_REQUEST_BODY + 1)?;
        let Err(e) = read_request(&mut io::Cursor::new(ttlv_header(too_big))) else {
            return Err("oversized request accepted".into());
        };
        if !e.to_string().contains("exceeds") {
            return Err(format!("unexpected error: {e}").into());
        }
        Ok(())
    }

    #[test]
    fn request_is_read_whole_and_eof_ends_session() -> TestResult {
        let mut message = ttlv_header(8);
        message.extend_from_slice(&[7; 8]);
        let mut stream = io::Cursor::new(message.clone());
        if read_request(&mut stream)? != Some(message) {
            return Err("request not read back verbatim".into());
        }
        if read_request(&mut stream)?.is_some() {
            return Err("EOF must end the session".into());
        }
        Ok(())
    }
}
