use std::{
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

use actix_web::{
    dev::ServerHandle,
    web::{Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use tracing::trace;

use super::certificates::generate_self_signed_cert;
use crate::{error::KmsError, result::KResult};

//let is_running_inside_enclave = is_running_inside_enclave();

struct BootstrapServer {
    common_name: String,
    hostname: String,
    port: usize,
}

async fn start_bootstrap_server(
    common_name: &str,
    hostname: &str,
    port: usize,
) -> Result<(ServerHandle, JoinHandle<Result<(), KmsError>>), KmsError> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    //
    let bootstrap_server = Arc::new(BootstrapServer {
        common_name: common_name.to_owned(),
        hostname: hostname.to_owned(),
        port,
    });

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
    // Generate a self-signed certificate
    let pkcs12 = generate_self_signed_cert(&bootstrap_server.common_name, "")?;
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

    // if let Some(verify_cert) = &shared_config.verify_cert {
    //     // This line sets the mode to verify peer (client) certificates
    //     builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    //     let mut store_builder = X509StoreBuilder::new()?;
    //     store_builder.add_cert(verify_cert.clone())?;
    //     builder.set_verify_cert_store(store_builder.build())?;
    // }

    // Instantiate and prepare the Bootstrap server
    let server = prepare_bootstrap_server(bootstrap_server, builder)?;

    // send the server handle to the caller
    server_handle_transmitter.send(server.handle())?;

    // Run the server and return the result
    server.await.map_err(Into::into)
}

pub fn prepare_bootstrap_server(
    bootstrap_server: Arc<BootstrapServer>,
    builder: SslAcceptorBuilder,
) -> KResult<actix_web::dev::Server> {
    let host_port = format!("{}:{}", bootstrap_server.hostname, bootstrap_server.port);

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the routes.
        let app = App::new()
            .app_data(Data::new(bootstrap_server.clone())) // Set the shared reference to the `BootstrapServer` instance.
            .app_data(PayloadConfig::new(1_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(1_000_000)) // Set the maximum size of the JSON request payload.
            .service(routes::kmip);

        app
    })
    .client_request_timeout(std::time::Duration::from_secs(10));

    // Start an HTTPS server with PKCS#12 but not client cert auth
    Ok(server.bind_openssl(host_port, builder)?.run())
}
