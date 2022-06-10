pub mod config;
mod core;
mod database;
pub mod error;

#[cfg(feature = "auth")]
mod middlewares;
pub mod result;
mod routes;

use std::sync::Arc;

#[cfg(feature = "auth")]
use middlewares::auth::Auth;
#[cfg(feature = "https")]
use {
    crate::core::certbot::Certbot,
    actix_files as fs,
    actix_web::rt::{spawn, time::sleep},
    config::certbot,
    openssl::ssl::{SslAcceptor, SslMethod},
    std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    std::time::Duration,
    tracing::{debug, error, info},
};

use crate::core::KMS;
pub mod log_utils;

use actix_web::{
    web::{Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use config::kms_url;
use database::KMSServer;
use openssl::ssl::SslAcceptorBuilder;

use crate::routes::endpoint;

/// A factory to configure the server
pub fn prepare_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> eyre::Result<actix_web::dev::Server> {
    let server = HttpServer::new(move || {
        let app = App::new()
            .app_data(Data::new(kms_server.clone()))
            .app_data(PayloadConfig::new(10_000_000_000))
            .app_data(JsonConfig::default().limit(10_000_000_000))
            .service(endpoint::kmip)
            .service(endpoint::list_owned_objects)
            .service(endpoint::list_shared_objects)
            .service(endpoint::list_accesses)
            .service(endpoint::insert_access)
            .service(endpoint::delete_access);

        #[cfg(feature = "auth")]
        let app = app.wrap(Auth);

        #[cfg(feature = "enclave")]
        let app = app.service(endpoint::get_quote);
        #[cfg(feature = "https")]
        let app = app.service(endpoint::get_certificate);
        #[cfg(feature = "enclave")]
        let app = app.service(endpoint::get_manifest);

        app
    });

    Ok(match builder {
        Some(b) => server.bind_openssl(kms_url(), b)?.run(),
        _ => server.bind(kms_url())?.run(),
    })
}

#[cfg(not(feature = "https"))]
// Start the kms server
pub async fn start_kms_server() -> eyre::Result<()> {
    let kms_server = Arc::new(KMSServer::instantiate().await?);
    let server = prepare_server(kms_server, None)?;
    server.await.map_err(Into::into)
}

#[cfg(feature = "https")]
/// Start and https server with the ability to renew its certificates
async fn start_https(cert: &Arc<Mutex<Certbot>>) -> eyre::Result<()> {
    let kms_server = Arc::new(KMSServer::instantiate().await?);

    // The loop is designed to restart the server in case it stops.
    // It stops when we renew the certificates
    loop {
        // Define an HTTPS server
        let (pk, x509) = cert
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
        let cert_copy = Arc::clone(cert);

        // Define and start the thread renewing the certificate
        spawn(async move {
            let renew_in = match cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .get_days_before_renew()
            {
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
            match cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .request_cert()
            {
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
            eyre::bail!("Can't restart the HTTPS server (no valid certificate)...")

            // Note: we could decide another behavior such as:
            // Let the server up. Then the web browser or the wget will raise a security error the user can ignore
            // That way, we don't stop our service.
        }
    }
}

#[cfg(feature = "https")]
pub async fn start_kms_server() -> eyre::Result<()> {
    // Before starting any servers, check the status of our SSL certificates
    let cert = certbot();

    debug!("Initializing certbot");
    // Recover the previous certificate if exist
    cert.lock().expect("can't lock certificate mutex").init()?;

    debug!("Checking certificates...");
    let mut has_valid_cert = cert.lock().expect("can't lock certificate mutex").check();

    let http_root_path = cert
        .lock()
        .expect("can't lock certificate mutex")
        .http_root_path
        .clone();

    if !has_valid_cert {
        info!("No valid certificate found!");
        info!("Starting certification process...");

        // Start a HTTP server, to negociate a certificate
        let server = HttpServer::new(move || {
            App::new().service(fs::Files::new("/", &http_root_path).use_hidden_files())
        })
        .workers(1)
        .bind(("0.0.0.0", 80))?
        .run();
        // The server is not started yet here!

        let succeed = Arc::new(AtomicBool::new(false));
        let succeed_me = Arc::clone(&succeed);
        let srv = server.handle();
        let cert_copy = Arc::clone(cert);

        spawn(async move {
            // Generate the certificate in another thread
            info!("Requesting acme...");
            match cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .request_cert()
            {
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
            && cert.lock().expect("can't lock certificate mutex").check();

        info!("Stop the HTTP server");
    }

    if has_valid_cert {
        // Use it and start SSL Server
        info!("Certificate is valid");
        start_https(cert).await?
    } else {
        error!("Abort program, failed to get a valid certificate");
        eyre::bail!("Abort program, failed to get a valid certificate")
    }

    Ok(())
}
