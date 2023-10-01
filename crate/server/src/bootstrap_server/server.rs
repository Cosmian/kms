use std::{
    sync::{mpsc, Arc, RwLock},
    thread::{self},
    time::Duration,
};

use actix_web::{
    dev::ServerHandle,
    middleware::Condition,
    web::{Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use openssl::{
    pkcs12::{ParsedPkcs12_2, Pkcs12},
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tracing::{info, trace};

use super::routes::{
    mysql_config, pkcs12_password, postgresql_config, receive_pkcs12, redis_findex_config,
    sqlite_config, sqlite_enc_config, start_kms_server_config,
};
use crate::{
    bootstrap_server::certificate::generate_self_signed_cert,
    config::{DbParams, HttpParams, ServerParams},
    error::KmsError,
    kms_bail, kms_error,
    kms_server::start_kms_server,
    middlewares::{
        ssl_auth::{extract_peer_certificate, SslAuth},
        JwtAuth, JwtConfig,
    },
    result::KResult,
};

pub enum BootstrapServerMessage {
    /// The PKCS12 to use for the server to start in HTTPS
    Pkcs12(ParsedPkcs12_2),
    /// The DbParams to use for the database
    DbParams(DbParams),
    /// Start the KMS server; pass true to clear the database on start
    StartKmsServer(bool),
}

pub struct BootstrapServer {
    pub server_params: ServerParams,
    pub db_params_supplied: RwLock<bool>,
    pub pkcs12_supplied: RwLock<bool>,
    pub pkcs12_received: RwLock<Option<Pkcs12>>,
    pub pkcs12_password_received: RwLock<Option<String>>,
    pub bs_msg_tx: mpsc::Sender<BootstrapServerMessage>,
}

pub async fn start_kms_server_using_bootstrap_server(
    mut server_params: ServerParams,
    kms_server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // check that the config actually requests a bootstrap server
    if !server_params.bootstrap_server_params.use_bootstrap_server {
        kms_bail!("Start bootstrap server is called but config says to not start one!")
    }

    // Create a channel to send the bootstrap server handle to the main thread
    let (bs_handle_tx, bs_handle_rx) = mpsc::channel::<ServerHandle>();
    // Create a channel to send messages from the bootstrap server to the main thread
    let (bs_msg_tx, bs_msg_rx) = mpsc::channel::<BootstrapServerMessage>();

    let bs_server_params = server_params.clone();
    let tokio_handle = tokio::runtime::Handle::current();
    let bs_thread_handle = thread::spawn(move || {
        tokio_handle
            .block_on(start_https_bootstrap_server(
                bs_server_params,
                bs_handle_tx,
                bs_msg_tx,
            ))
            .map_err(|e| {
                info!("Error starting the bootstrap server: {}", e);
                KmsError::ServerError(e.to_string())
            })
    });

    // Wait for the bootstrap server to start
    trace!("Waiting for the bootstrap server to start...");
    let bs_actix_handle = bs_handle_rx
        .recv_timeout(Duration::from_secs(25))
        .map_err(|e| kms_error!("Can't get bootstrap server handle after 25 seconds: {}", e))?;
    info!("Bootstrap server started !");

    // Now wait for the bootstrap server to send messages
    trace!("Waiting for the bootstrap server to send messages...");
    loop {
        let msg = bs_msg_rx
            .recv()
            .map_err(|e| kms_error!("Can't get a message from bootstrap server: {}", e))?;
        match msg {
            BootstrapServerMessage::Pkcs12(p12) => {
                let subject_name = format!(
                    "{:?}",
                    p12.cert
                        .as_ref()
                        .ok_or_else(|| kms_error!("PKCS12 does not contain a certificate"))?
                        .subject_name()
                );
                // Set the PKCS12 in the config
                server_params.http_params = HttpParams::Https(p12);
                info!(
                    "PKCS12 received and successfully opened with subject name: {}",
                    subject_name
                );
            }
            BootstrapServerMessage::DbParams(db_params) => {
                let db_params_str = format!("{db_params:?}");
                // Set the DbParams in the config
                server_params.db_params = Some(db_params);
                info!("DbParams received: {}", db_params_str);
            }
            BootstrapServerMessage::StartKmsServer(clear_data_base) => {
                // set the clear database flag
                server_params.clear_db_on_start = clear_data_base;
                info!(
                    "Start KMS server requested with clear database flag: {}",
                    clear_data_base
                );
                break
            }
        }
    }
    info!("Shutting down the bootstrap server...");

    // We have a PKCS12 so we can stop the bootstrap server
    bs_actix_handle.stop(true).await;

    // Wait for the bootstrap server to thread to finish
    bs_thread_handle
        .join()
        .map_err(|e| {
            kms_error!(
                "Error starting the bootstrap server (waiting for threads to stop): {:?}",
                e
            )
        })?
        .map_err(|e| kms_error!("Error starting the bootstrap server: {}", e))?;

    info!("Starting KMS server...");

    // Start the KMS server with the updated configuration
    start_kms_server(server_params, kms_server_handle_tx).await
}

pub async fn start_https_bootstrap_server(
    server_params: ServerParams,
    server_handle_transmitter: mpsc::Sender<ServerHandle>,
    bs_msg_tx: mpsc::Sender<BootstrapServerMessage>,
) -> KResult<()> {
    // Log the server configuration
    info!("Bootstrap server configuration: {:#?}", server_params);

    // Was a PKCS#12 supplied on the command line ?
    let pkcs12_supplied = matches!(
        &server_params.http_params,
        crate::config::HttpParams::Https(_)
    );

    // Create the BootstrapServer instance
    let bootstrap_server = Arc::new(BootstrapServer {
        server_params: server_params.clone(),
        db_params_supplied: RwLock::new(server_params.db_params.is_some()),
        pkcs12_supplied: RwLock::new(pkcs12_supplied),
        bs_msg_tx,
        pkcs12_received: RwLock::new(None),
        pkcs12_password_received: RwLock::new(None),
    });

    // Generate a, possibly RA-TLS, certificate
    let (pkey, cert) = generate_self_signed_cert(
        &bootstrap_server
            .server_params
            .bootstrap_server_params
            .bootstrap_server_subject,
        bootstrap_server
            .server_params
            .bootstrap_server_params
            .bootstrap_server_expiration_days,
        bootstrap_server
            .server_params
            .bootstrap_server_params
            .ensure_ra_tls,
    )?;
    // Create and configure an SSL acceptor with the certificate and key
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_private_key(&pkey)?;
    builder.set_certificate(&cert)?;

    if let Some(verify_cert) = &bootstrap_server.server_params.verify_cert {
        // This line sets the mode to verify peer (client) certificates
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(verify_cert.clone())?;
        builder.set_verify_cert_store(store_builder.build())?;
    }

    // Instantiate and prepare the Bootstrap server
    let server = prepare_bootstrap_server(bootstrap_server, builder)?;

    // send the server handle to the caller
    server_handle_transmitter.send(server.handle())?;

    // Run the server and return the result
    server.await.map_err(Into::into)
}

fn prepare_bootstrap_server(
    bootstrap_server: Arc<BootstrapServer>,
    builder: SslAcceptorBuilder,
) -> KResult<actix_web::dev::Server> {
    // Determine if JWT Auth should be used for authentication.
    let (use_jwt_auth, jwt_config) =
        if let Some(jwt_issuer_uri) = &bootstrap_server.server_params.jwt_issuer_uri {
            (
                true,
                Some(JwtConfig {
                    jwt_issuer_uri: jwt_issuer_uri.clone(),
                    jwks: bootstrap_server
                        .server_params
                        .jwks
                        .as_ref()
                        .ok_or_else(|| {
                            kms_error!("The JWKS must be provided when using JWT authentication")
                        })?
                        .clone(),
                    jwt_audience: bootstrap_server.server_params.jwt_audience.clone(),
                }),
            )
        } else {
            (false, None)
        };
    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = bootstrap_server.server_params.verify_cert.is_some();

    // Determine the address to bind the server to.
    let address = format!(
        "{}:{}",
        bootstrap_server.server_params.hostname,
        bootstrap_server
            .server_params
            .bootstrap_server_params
            .bootstrap_server_port
    );

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the routes.

        App::new()
            .wrap(Condition::new(
                use_jwt_auth,
                JwtAuth::new(jwt_config.clone()),
            )) // Use JWT for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use certificates for authentication if necessary.
            .app_data(Data::new(bootstrap_server.clone())) // Set the shared reference to the `BootstrapServer` instance.
            .app_data(PayloadConfig::new(1_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(1_000_000)) // Set the maximum size of the JSON request payload.
            .service(receive_pkcs12)
            .service(pkcs12_password)
            .service(redis_findex_config)
            .service(postgresql_config)
            .service(mysql_config)
            .service(sqlite_config)
            .service(sqlite_enc_config)
            .service(start_kms_server_config)
    })
    .client_request_timeout(std::time::Duration::from_secs(10));

    Ok(if use_cert_auth {
        // Start an HTTPS server with PKCS#12 with client cert auth
        server
            .on_connect(extract_peer_certificate)
            .bind_openssl(address, builder)?
            .run()
    } else {
        // Start an HTTPS server with PKCS#12 but not client cert auth
        server.bind_openssl(address, builder)?.run()
    })
}
