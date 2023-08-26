use std::{
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

use actix_web::{
    dev::ServerHandle,
    middleware::Condition,
    web::{Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tracing::trace;

use super::certificates::generate_self_signed_cert;
use crate::{
    config::ServerConfig,
    error::KmsError,
    kms_bail, kms_error,
    middlewares::{
        ssl_auth::{extract_peer_certificate, SslAuth},
        JwtAuth, JwtConfig,
    },
    result::KResult,
};

//let is_running_inside_enclave = is_running_inside_enclave();

struct BootstrapServer {
    config: ServerConfig,
}

async fn start_bootstrap_server(
    config: ServerConfig,
) -> Result<(ServerHandle, JoinHandle<Result<(), KmsError>>), KmsError> {
    // check that the config actually requests a bootstrap server
    if !config.bootstrap_server_config.use_bootstrap_server {
        kms_bail!("Start bootstrap server is called but config says to not start one!")
    }

    let (tx, rx) = mpsc::channel::<ServerHandle>();

    //
    let bootstrap_server = Arc::new(BootstrapServer { config });

    let tokio_handle = tokio::runtime::Handle::current();
    let cs_thread_handle = thread::spawn(move || {
        tokio_handle
            .block_on(start_https_bootstrap_server(bootstrap_server, tx))
            .map_err(|e| KmsError::ServerError(e.to_string()))
    });

    trace!("Waiting for server to start...");
    let cs_actix_handle = rx
        .recv_timeout(Duration::from_secs(25))
        .expect("Can't get actix control server handle after 25 seconds");
    trace!("... got handle ...");
    Ok((cs_actix_handle, cs_thread_handle))
}

async fn start_https_bootstrap_server(
    bootstrap_server: Arc<BootstrapServer>,
    server_handle_transmitter: mpsc::Sender<ServerHandle>,
) -> KResult<()> {
    let common_name = &bootstrap_server
        .config
        .bootstrap_server_config
        .bootstrap_server_common_name;

    // Generate a self-signed certificate
    let pkcs12 = generate_self_signed_cert(common_name, "")?;
    let p12 = pkcs12.parse2("")?;
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

    if let Some(verify_cert) = &bootstrap_server.config.verify_cert {
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
        if let Some(jwt_issuer_uri) = &bootstrap_server.config.jwt_issuer_uri {
            (
                true,
                Some(JwtConfig {
                    jwt_issuer_uri: jwt_issuer_uri.clone(),
                    jwks: bootstrap_server
                        .config
                        .jwks
                        .as_ref()
                        .ok_or_else(|| {
                            kms_error!("The JWKS must be provided when using JWT authentication")
                        })?
                        .clone(),
                    jwt_audience: bootstrap_server.config.jwt_audience.clone(),
                }),
            )
        } else {
            (false, None)
        };
    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = bootstrap_server.config.verify_cert.is_some();

    // Determine the address to bind the server to.
    let address = format!(
        "{}:{}",
        bootstrap_server.config.hostname,
        bootstrap_server
            .config
            .bootstrap_server_config
            .bootstrap_server_port
    );

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the routes.
        let app = App::new()
            .wrap(Condition::new(
                use_jwt_auth,
                JwtAuth::new(jwt_config.clone()),
            )) // Use JWT for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use certificates for authentication if necessary.
            .app_data(Data::new(bootstrap_server.clone())) // Set the shared reference to the `BootstrapServer` instance.
            .app_data(PayloadConfig::new(1_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(1_000_000)); // Set the maximum size of the JSON request payload.
        // .service(routes::kmip);

        app
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
