use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};

use actix_cors::Cors;
use actix_web::{
    dev::ServerHandle,
    middleware::Condition,
    rt::{spawn, time::sleep},
    web::{Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use libsgx::utils::is_running_inside_enclave;
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tracing::{debug, error, info};

use crate::{
    config::{self, ServerConfig},
    core::{certbot::Certbot, KMS},
    error::KmsError,
    kms_bail, kms_error,
    middlewares::{
        ssl_auth::{extract_peer_certificate, SslAuth},
        JwtAuth, JwtConfig,
    },
    result::KResult,
    routes, KMSServer,
};

/// Starts the Key Management System (KMS) server based on the provided configuration.
///
/// The server is started using one of three methods:
/// 1. Plain HTTP,
/// 2. HTTPS with PKCS#12,
/// 3. HTTPS with certbot.
///
/// The method used depends on the server settings specified in the `ServerConfig` instance provided.
///
/// # Arguments
///
/// * `server_config` - An instance of `ServerConfig` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function will return an error if any of the server starting methods fails.
pub async fn start_kms_server(
    server_config: ServerConfig,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // Log the server configuration
    info!("KMS Server configuration: {:#?}", server_config);
    if server_config.certbot.is_some() {
        // Start an HTTPS server with certbot
        start_certbot_https_kms_server(server_config, server_handle_transmitter).await
    } else if server_config.server_pkcs_12.is_some() {
        // Start an HTTPS server with PKCS#12
        start_https_kms_server(server_config, server_handle_transmitter).await
    } else {
        // Start a plain HTTP server
        start_plain_http_kms_server(server_config, server_handle_transmitter).await
    }
}

/// Start a plain HTTP KMS server
///
/// This function will instantiate and prepare the KMS server and run it on a plain HTTP connection
///
/// # Arguments
///
/// * `server_config` - An instance of `ServerConfig` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function returns an error if:
/// - The KMS server cannot be instantiated or prepared
/// - The server fails to run
async fn start_plain_http_kms_server(
    server_config: ServerConfig,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate(server_config).await?);

    // Prepare the server
    let server = prepare_kms_server(kms_server, None)?;

    // send the server handle to the caller
    if let Some(tx) = &server_handle_transmitter {
        tx.send(server.handle())?;
    }

    info!("Starting the HTTP KMS server...");
    // Run the server and return the result
    server.await.map_err(Into::into)
}

/// Start an HTTPS KMS server using a PKCS#12 certificate file
///
/// # Arguments
///
/// * `server_config` - An instance of `ServerConfig` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function returns an error if:
/// - The path to the PKCS#12 certificate file is not provided in the config
/// - The file cannot be opened or read
/// - The file is not a valid PKCS#12 format or the password is incorrect
/// - The SSL acceptor cannot be created or configured with the certificate and key
/// - The KMS server cannot be instantiated or prepared
/// - The server fails to run
async fn start_https_kms_server(
    server_config: ServerConfig,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    let p12 = server_config
        .server_pkcs_12
        .as_ref()
        .ok_or_else(|| kms_error!("http/s: a PKCS#12 file must be provided"))?;

    // Create and configure an SSL acceptor with the certificate and key
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    if let Some(pkey) = &p12.pkey {
        builder.set_private_key(pkey)?;
    }
    if let Some(cert) = &p12.cert {
        builder.set_certificate(cert)?;
    }
    if let Some(chain) = &p12.ca {
        for x in chain {
            builder.add_extra_chain_cert(x.to_owned())?;
        }
    }

    if let Some(verify_cert) = &server_config.verify_cert {
        // This line sets the mode to verify peer (client) certificates
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(verify_cert.clone())?;
        builder.set_verify_cert_store(store_builder.build())?;
    }

    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate(server_config).await?);
    let server = prepare_kms_server(kms_server, Some(builder))?;

    // send the server handle to the caller
    if let Some(tx) = &server_handle_transmitter {
        tx.send(server.handle())?;
    }

    info!("Starting the HTTPS KMS server...");

    // Run the server and return the result
    server.await.map_err(Into::into)
}

/// Start and https server with the ability to renew its certificates
async fn start_auto_renew_https(
    server_config: ServerConfig,
    certbot: &Arc<Mutex<Certbot>>,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    let kms_server = Arc::new(KMSServer::instantiate(server_config).await?);

    // The loop is designed to restart the server in case it stops.
    // It stops when we renew the certificates
    loop {
        // Define an HTTPS server
        let (pk, x509) = certbot
            .lock()
            .expect("can't lock certificate mutex")
            .get_cert()?;

        debug!("Building the HTTPS server... ");
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key(&pk)?;
        builder.set_certificate(&x509[0])?;
        for x in x509 {
            builder.add_extra_chain_cert(x)?;
        }

        let server = prepare_kms_server(kms_server.clone(), Some(builder))?;

        // send the server handle to the caller
        if let Some(tx) = &server_handle_transmitter {
            tx.send(server.handle())?;
        }

        let restart = Arc::new(AtomicBool::new(false));
        let restart_me = Arc::clone(&restart);
        let srv = server.handle();
        let cert_copy = Arc::clone(certbot);

        // Define and start the thread renewing the certificate
        spawn(async move {
            let days_before_renew = cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .get_days_before_renew();
            let renew_in = match days_before_renew {
                Ok(x) => x,
                Err(error) => {
                    error!("Error when asking for renewing the certificate {error}");
                    0 // force the renew
                }
            };

            // Wait for the renew date.
            if renew_in > 0 {
                info!("Waiting {renew_in} days before renewing the certificate!");
                sleep(Duration::from_secs(renew_in as u64 * 3600 * 24)).await;
            }

            // It's time to renew!!
            info!("Updating certificate now...");
            let request_cert = cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .request_cert();
            match request_cert {
                Ok(_) => restart_me.store(true, Ordering::Relaxed),
                Err(error) => {
                    error!("Error when renewing the certificate {error}");
                    restart_me.store(false, Ordering::Relaxed);
                }
            }

            info!("Stopping the HTTPS server...");
            // Stop the HTTPS server. We don't need it anymore
            srv.stop(true).await
        });

        // Run server until stopped (either by ctrl-c or stopped by the previous thread)
        info!("Starting the HTTPS KMS server...");
        server.await?;

        // We reach that part of the code when the thread renewing the certificates stops.
        if restart.load(Ordering::Relaxed) {
            restart.store(false, Ordering::Relaxed);
        } else {
            // If we reach that point, we don't want to restart.
            // Contact the administrator
            error!("Can't restart the HTTPS server (no valid certificate)...");
            kms_bail!("Can't restart the HTTPS server (no valid certificate)...")

            // Note: we could decide another behavior such as:
            // Let the server up. Then the web browser or the wget will raise a security error the user can ignore
            // That way, we don't stop our service.
        }
    }
}

async fn start_certbot_https_kms_server(
    server_config: ServerConfig,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // Before starting any servers, check the status of our SSL certificates
    let certbot = server_config.certbot.clone().ok_or_else(|| {
        KmsError::ServerError("trying to start a TLS server but certbot is not used !".to_string())
    })?;

    debug!("Initializing certbot");
    // Recover the previous certificate if exist
    certbot
        .lock()
        .expect("can't lock certificate mutex")
        .init()?;

    debug!("Checking certificates...");
    let mut has_valid_cert = certbot
        .lock()
        .expect("can't lock certificate mutex")
        .check();

    let http_root_path = certbot
        .lock()
        .expect("can't lock certificate mutex")
        .http_root_path
        .clone();

    if !has_valid_cert {
        info!("No valid certificate found!");
        info!("Starting certification process...");

        // Start a HTTP server, to negotiate a certificate
        let server = HttpServer::new(move || {
            App::new().service(actix_files::Files::new("/", &http_root_path).use_hidden_files())
        })
        .workers(1)
        .bind(("0.0.0.0", 80))?
        .run();
        // The server is not started yet here!

        let succeed = Arc::new(AtomicBool::new(false));
        let succeed_me = Arc::clone(&succeed);
        let srv = server.handle();
        let cert_copy = Arc::clone(&certbot);

        spawn(async move {
            // Generate the certificate in another thread
            info!("Requesting acme...");
            let request_cert = cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .request_cert();
            match request_cert {
                Ok(_) => succeed_me.store(true, Ordering::Relaxed),
                Err(error) => {
                    error!("Error when generating the certificate: {error}");
                    succeed_me.store(false, Ordering::Relaxed);
                }
            }

            // Stop the HTTP server. We don't need it anymore
            srv.stop(true).await
        });

        // Run server until stopped (either by ctrl-c or stopped by the previous thread)
        info!("Starting the HTTP KMS server...");
        server.await?;

        // Note: cert_copy is a ref to cert. So `cert.certificates` contains the new certificates
        // Therefore, we do not need to call `cert.init()`. That way, we avoid several acme useless queries
        has_valid_cert = succeed.load(Ordering::Relaxed)
            && certbot
                .lock()
                .expect("can't lock certificate mutex")
                .check();

        info!("Stop the HTTP server");
    }

    if has_valid_cert {
        // Use it and start SSL Server
        info!("Certificate is valid");
        start_auto_renew_https(server_config, &certbot, server_handle_transmitter).await?
    } else {
        error!("Abort program, failed to get a valid certificate");
        kms_bail!("Abort program, failed to get a valid certificate")
    }

    Ok(())
}

/**
 * This function prepares a server for the application. It creates an `HttpServer` instance,
 * configures the routes for the application, and sets the request timeout. The server can be
 * configured to use OpenSSL for SSL encryption by providing an `SslAcceptorBuilder`.
 *
 * # Arguments
 *
 * * `kms_server`: A shared reference to the `KMS` instance to be used by the application.
 * * `builder`: An optional `SslAcceptorBuilder` to configure the SSL encryption for the server.
 *
 * # Returns
 *
 * Returns a `Result` type that contains a `Server` instance if successful, or an error if
 * something went wrong.
 *
 */
pub fn prepare_kms_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> KResult<actix_web::dev::Server> {
    // Determine if JWT Auth should be used for authentication.
    let (use_jwt_auth, jwt_config) = if let Some(jwt_issuer_uri) = &kms_server.config.jwt_issuer_uri
    {
        (
            true,
            Some(JwtConfig {
                jwt_issuer_uri: jwt_issuer_uri.clone(),
                jwks: kms_server
                    .config
                    .jwks
                    .as_ref()
                    .ok_or_else(|| {
                        kms_error!("The JWKS must be provided when using JWT authentication")
                    })?
                    .clone(),
                jwt_audience: kms_server.config.jwt_audience.clone(),
            }),
        )
    } else {
        (false, None)
    };
    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = kms_server.config.verify_cert.is_some();
    // Determine if the application is running inside an enclave.
    let is_running_inside_enclave = is_running_inside_enclave();
    // Determine if the application is using an encrypted SQLite database.
    let is_using_sqlite_enc = matches!(
        kms_server.config.db_params,
        Some(config::DbParams::SqliteEnc(_))
    );

    // Determine the address to bind the server to.
    let address = format!("{}:{}", kms_server.config.hostname, kms_server.config.port);

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the routes.
        let app = App::new()
            .wrap(Condition::new(
                use_jwt_auth,
                JwtAuth::new(jwt_config.clone()),
            )) // Use JWT for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use certificates for authentication if necessary.
            // Enable CORS for the application.
            // Since Actix is running the middlewares in reverse order, it's important that the
            // CORS middleware is the last one so that the auth middlewares do not run on
            // preflight (OPTION) requests.
            .wrap(Cors::permissive())
            .app_data(Data::new(kms_server.clone())) // Set the shared reference to the `KMS` instance.
            .app_data(PayloadConfig::new(10_000_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(10_000_000_000)) // Set the maximum size of the JSON request payload.
            .service(routes::kmip)
            .service(routes::list_owned_objects)
            .service(routes::list_access_rights_obtained)
            .service(routes::list_accesses)
            .service(routes::grant_access)
            .service(routes::revoke_access)
            .service(routes::get_version)
            .service(routes::get_certificate);

        let app = if is_using_sqlite_enc {
            app.service(routes::add_new_database)
        } else {
            app
        };

        if is_running_inside_enclave {
            app.service(routes::get_enclave_quote)
                .service(routes::get_enclave_manifest)
                .service(routes::get_enclave_public_key)
        } else {
            app
        }
    })
    .client_request_timeout(std::time::Duration::from_secs(10));

    Ok(match builder {
        Some(b) => {
            if use_cert_auth {
                // Start an HTTPS server with PKCS#12 with client cert auth
                server
                    .on_connect(extract_peer_certificate)
                    .bind_openssl(address, b)?
                    .run()
            } else {
                // Start an HTTPS server with PKCS#12 but not client cert auth
                server.bind_openssl(address, b)?.run()
            }
        }
        _ => server.bind(address)?.run(),
    })
}
