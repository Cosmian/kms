use std::{
    sync::{mpsc, Arc},
    thread::{self},
    time::Duration,
};

use actix_multipart::Multipart;
use actix_web::{
    dev::ServerHandle,
    http::header,
    middleware::Condition,
    post,
    web::{Data, Json, JsonConfig, PayloadConfig},
    App, HttpRequest, HttpServer,
};
use cosmian_kms_utils::access::SuccessResponse;
use futures::StreamExt;
use openssl::{
    pkcs12::{ParsedPkcs12_2, Pkcs12},
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tracing::{info, trace};

use super::certificate::generate_self_signed_cert;
use crate::{
    config::ServerConfig,
    error::KmsError,
    kms_bail, kms_error,
    kms_server::start_kms_server,
    middlewares::{
        ssl_auth::{extract_peer_certificate, SslAuth},
        JwtAuth, JwtConfig,
    },
    result::KResult,
};

//let is_running_inside_enclave = is_running_inside_enclave();

pub struct BootstrapServer {
    config: ServerConfig,
    pkcs12_tx: mpsc::Sender<ParsedPkcs12_2>,
}

pub async fn start_bootstrap_server(mut config: ServerConfig) -> Result<ServerHandle, KmsError> {
    // check that the config actually requests a bootstrap server
    if !config.bootstrap_server_config.use_bootstrap_server {
        kms_bail!("Start bootstrap server is called but config says to not start one!")
    }

    // Create a channel to send the bootstrap server handle to the main thread
    let (bs_handle_tx, bs_handle_rx) = mpsc::channel::<ServerHandle>();
    // Create a channel to send the PKCS12 ro the main thread
    let (pkcs12_tx, pkcs12_rx) = mpsc::channel::<ParsedPkcs12_2>();

    // Create the BootstrapServer instance
    let bootstrap_server = Arc::new(BootstrapServer {
        config: config.clone(),
        pkcs12_tx,
    });

    let tokio_handle = tokio::runtime::Handle::current();
    let bs_thread_handle = thread::spawn(move || {
        tokio_handle
            .block_on(start_https_bootstrap_server(bootstrap_server, bs_handle_tx))
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

    // Now wait for the bootstrap server to send a PKCS12
    trace!("Waiting for the bootstrap server to send a PKCS12...");
    let pkcs12 = pkcs12_rx
        .recv()
        .map_err(|e| kms_error!("Can't get PKCS12 from bootstrap server: {}", e))?;
    info!("Received PKCS12 from the bootstrap server. Shutting it down...");

    // We have a PKCS12 so we can stop the bootstrap server
    bs_actix_handle.stop(true).await;

    // Wait for the bootstrap server to thread to finish
    bs_thread_handle
        .join()
        .map_err(|e| kms_error!("Error starting the bootstrap server: {:?}", e))?
        .map_err(|e| kms_error!("Error starting the bootstrap server: {}", e))?;

    // Set the PKCS12 in the config
    config.server_pkcs_12 = Some(pkcs12);

    info!("Bootstrap server shut down. Starting KMS server...");

    // Start the KMS server with the PKCS12
    start_kms_server(config, None).await?;

    Ok(bs_actix_handle)
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

#[post("/pkcs12")]
pub async fn receive_pkcs12(
    req: HttpRequest,
    mut payload: Multipart,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    // print the request content-type
    match req.headers().get(header::CONTENT_TYPE) {
        Some(content_type) => {
            // match the content_type to multipart/form-data
            if content_type.as_bytes().starts_with(b"multipart/form-data") {
                println!("content-type: multipart/form-data");
            } else {
                println!("another content-type: {:#?}", content_type);
            }
        }
        None => println!("content-type: None"),
    };

    // Extract the bytes from a multipart/form-data payload
    // and return them as a `Vec<u8>`.
    let mut bytes = Vec::new();
    while let Some(field) = payload.next().await {
        let mut field =
            field.map_err(|e| kms_error!("Failed reading multipart/form-data field: {e}"))?;
        // we want to read the field/part which has a content-type of application/octet-stream
        if let Some(content_type) = field.content_type() {
            if *content_type == mime::APPLICATION_OCTET_STREAM {
                while let Some(chunk) = field.next().await {
                    let data = chunk.map_err(|e| {
                        kms_error!("Failed reading the bytes form the multipart/form-data: {e}")
                    })?;
                    bytes.extend_from_slice(&data);
                }
            }
        }
    }

    // Parse the PKCS#12
    let pkcs12 = Pkcs12::from_der(&bytes)
        .map_err(|e| kms_error!("Error reading PKCS#12 from DER: {}", e))?;
    // Verify the PKCS 12 by extracting the certificate, private key and chain
    let p12 = pkcs12
        .parse2("")
        .map_err(|e| kms_error!("Error parsing PKCS#12: {}", e))?;
    let cert = p12
        .cert
        .as_ref()
        .ok_or_else(|| kms_error!("Missing certificate"))?;
    let subject_name = cert.subject_name().to_owned()?;
    let _pkey = p12
        .pkey
        .as_ref()
        .ok_or_else(|| kms_error!("Missing private key"))?;
    // let _chain = p12.ca.ok_or_else(|| kms_error!("Missing chain"))?;

    // Send the parsed PKCS12 to the main thread on the tx channel
    bootstrap_server
        .pkcs12_tx
        .send(p12)
        .map_err(|e| kms_error!("failed sending the PKCS12 to the main thread: {e}"))?;

    let response = SuccessResponse {
        success: format!(
            "PKCS#12 of {} bytes with CN:{:#?}, received",
            bytes.len(),
            subject_name.as_ref()
        ),
    };
    Ok(Json(response))
}
