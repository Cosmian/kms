use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use actix_cors::Cors;
use actix_web::{
    middleware::Condition,
    rt::{spawn, time::sleep},
    web::{Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use config::SharedConfig;
use libsgx::utils::is_running_inside_enclave;
use middlewares::{
    jwt_auth::JwtAuth,
    ssl_auth::{extract_peer_certificate, SslAuth},
};
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use result::KResult;
use tracing::{debug, error, info};

use crate::{
    core::{certbot::Certbot, KMS},
    error::KmsError,
    routes::endpoint,
};

pub mod config;
pub mod core;
pub mod database;
pub mod error;
pub mod log_utils;
pub mod middlewares;
pub mod result;
pub mod routes;
pub use database::KMSServer;

#[cfg(test)]
mod tests;

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
pub fn prepare_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> KResult<actix_web::dev::Server> {
    // Determine if JWT Auth should be used for authentication.
    let use_jwt_auth = SharedConfig::jwt_issuer_uri().is_some();
    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = SharedConfig::verify_cert().is_some();
    // Determine if the application is running inside an enclave.
    let is_running_inside_enclave = is_running_inside_enclave();
    // Determine if the application is using an encrypted SQLite database.
    let is_using_sqlite_enc = matches!(SharedConfig::db_params(), config::DbParams::SqliteEnc(_));

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the routes.
        let app = App::new()
            .wrap(Cors::permissive()) // Enable CORS for the application.
            .wrap(Condition::new(use_jwt_auth, JwtAuth)) // Use Auth0 for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use Auth0 for authentication if necessary.
            .app_data(Data::new(kms_server.clone())) // Set the shared reference to the `KMS` instance.
            .app_data(PayloadConfig::new(10_000_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(10_000_000_000)) // Set the maximum size of the JSON request payload.
            .service(endpoint::kmip)
            .service(endpoint::list_owned_objects)
            .service(endpoint::list_shared_objects)
            .service(endpoint::list_accesses)
            .service(endpoint::insert_access)
            .service(endpoint::delete_access)
            .service(endpoint::get_version)
            .service(endpoint::get_certificate);

        let app = if is_using_sqlite_enc {
            app.service(endpoint::add_new_database)
        } else {
            app
        };

        if is_running_inside_enclave {
            app.service(endpoint::get_enclave_quote)
                .service(endpoint::get_enclave_manifest)
                .service(endpoint::get_enclave_public_key)
        } else {
            app
        }
    })
    .client_request_timeout(std::time::Duration::from_secs(10));

    Ok(match builder {
        Some(b) => {
            // Determine if Client Cert Auth should be used for authentication.
            let use_cert_auth = SharedConfig::verify_cert().is_some();
            if use_cert_auth {
                // Start an HTTPS server with PKCS#12 with client cert auth
                server
                    .on_connect(extract_peer_certificate)
                    .bind_openssl(SharedConfig::hostname_port(), b)?
                    .run()
            } else {
                // Start an HTTPS server with PKCS#12 but not client cert auth
                server.bind_openssl(SharedConfig::hostname_port(), b)?.run()
            }
        }
        _ => server.bind(SharedConfig::hostname_port())?.run(),
    })
}

/// Start the KMS server using the specified configuration
///
/// This function will start either a plain HTTP, an HTTPS with PKCS#12, or an HTTPS with certbot server
/// depending on the config settings.
///
/// # Arguments
///
/// * `conf` - A reference to the Config struct that contains the server settings
///
/// # Errors
///
/// This function returns an error if any of the sub-functions fail to start the server
pub async fn start_kms_server() -> KResult<()> {
    if SharedConfig::certbot().is_some() {
        // Start an HTTPS server with certbot
        start_certbot_https_kms_server().await
    } else if SharedConfig::server_pkcs12().is_some() {
        // Start an HTTPS server with PKCS#12
        start_https_kms_server().await
    } else {
        // Start a plain HTTP server
        start_plain_http_kms_server().await
    }
}

/// Start a plain HTTP KMS server
///
/// This function will instantiate and prepare the KMS server and run it on a plain HTTP connection
///
/// # Arguments
///
/// * `conf` - A reference to the Config struct that contains the server settings
///
/// # Errors
///
/// This function returns an error if:
/// - The KMS server cannot be instantiated or prepared
/// - The server fails to run
async fn start_plain_http_kms_server() -> KResult<()> {
    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate().await?);
    let server = prepare_server(kms_server, None)?;

    // Run the server and return the result
    server.await.map_err(Into::into)
}

/// Start an HTTPS KMS server using a PKCS#12 certificate file
///
/// # Arguments
///
/// * `conf` - A reference to the Config struct that contains the server settings
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
async fn start_https_kms_server() -> KResult<()> {
    let p12 = SharedConfig::server_pkcs12()
        .as_ref()
        .ok_or_else(|| eyre::eyre!("http/s: a PKCS#12 file must be provided"))?;

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

    if let Some(verify_cert) = SharedConfig::verify_cert() {
        // This line sets the mode to verify peer (client) certificates
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(verify_cert.clone()).unwrap();
        builder.set_verify_cert_store(store_builder.build())?;
    }

    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate().await?);
    let server = prepare_server(kms_server, Some(builder))?;

    // Run the server and return the result
    server.await.map_err(Into::into)
}

/// Start and https server with the ability to renew its certificates
async fn start_auto_renew_https(certbot: &Arc<Mutex<Certbot>>) -> KResult<()> {
    let kms_server = Arc::new(KMSServer::instantiate().await?);

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

        let server = prepare_server(kms_server.clone(), Some(builder))?;

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
        info!("Starting the HTTPS server...");
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

async fn start_certbot_https_kms_server() -> KResult<()> {
    // Before starting any servers, check the status of our SSL certificates
    let certbot = SharedConfig::certbot().clone().ok_or_else(|| {
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
        info!("Starting the HTTP server...");
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
        start_auto_renew_https(&certbot).await?
    } else {
        error!("Abort program, failed to get a valid certificate");
        kms_bail!("Abort program, failed to get a valid certificate")
    }

    Ok(())
}
