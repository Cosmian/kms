use std::sync::{mpsc, Arc};

use actix_cors::Cors;
use actix_files::Files;
use actix_identity::IdentityMiddleware;
use actix_session::{SessionMiddleware, config::PersistentSession, storage::CookieSessionStore};
use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer,
    cookie::{Key, time::Duration},
    dev::ServerHandle,
    middleware::Condition,
    web::{self, Data, JsonConfig, PayloadConfig},
};
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tokio::{runtime::Handle, task::JoinHandle};
use tracing::{debug, info, trace};

use crate::{
    config::{JwtAuthConfig, ServerParams},
    core::KMS,
    error::KmsError,
    kms_bail,
    middlewares::{AuthTransformer, JwksManager, JwtConfig, SslAuth, extract_peer_certificate},
    middlewares::{extract_peer_certificate, AuthTransformer, JwksManager, JwtConfig, SslAuth},
    result::{KResult, KResultHelper},
    routes::{
        access, get_version,
        google_cse::{self, GoogleCseConfig},
        kmip::handle_ttlv_bytes,
        kmip, ms_dke,
        ui_auth::configure_auth_routes,
    },
    socket_server::{SocketServer, SocketServerParams},
};

/// Starts the Key Management System (KMS) server based on the provided configuration.
///
/// The server is started using one of three methods:
/// 1. Plain HTTP,
/// 2. HTTPS with PKCS#12,
///
/// The method used depends on the server settings specified in the `ServerParams` instance provided.
///
/// # Arguments
///
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function will return an error if any of the server starting methods fails.
pub async fn start_kms_server(
    server_params: Arc<ServerParams>,
    kms_server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // OpenSSL is loaded now, so that tests can use the correct provider(s)

    // For an explanation of openssl providers, see
    //  https://docs.openssl.org/3.1/man7/crypto/#openssl-providers

    // In FIPS mode, we only load the fips provider
    #[cfg(feature = "fips")]
    let _provider = openssl::provider::Provider::load(None, "fips")?;

    // Not in FIPS mode and version > 3.0: load the default provider and the legacy provider
    // so that we can use the legacy algorithms,
    // particularly those used for old PKCS#12 formats
    #[cfg(not(feature = "fips"))]
    let _provider = if openssl::version::number() >= 0x3000_0000 {
        debug!("OpenSSL: loading the legacy provider");
        openssl::provider::Provider::try_load(None, "legacy", true)
            .context("OpenSSL: unable to load the openssl legacy provider")?
    } else {
        debug!("OpenSSL: loading the default provider");
        // In version < 3.0, we only load the default provider
        openssl::provider::Provider::load(None, "default")?
    };

    let kms_server = Arc::new(
        KMS::instantiate(server_params.clone())
            .await
            .context("start KMS server: failed instantiating the server")?,
    );

    let socket_server_handle: Option<JoinHandle<()>> = if server_params.start_socket_server {
        // Start the socket server
        Some(start_socket_server(kms_server.clone())?)
    } else {
        None
    };

    // Log the server configuration
    info!("KMS Server configuration: {:#?}", server_params);
    let res = start_http_kms_server(kms_server.clone(), kms_server_handle_tx).await;
    if let Some(ss_handle) = socket_server_handle {
        ss_handle.await.context("socket server failed")?;
    }
    res
}

/// Start a socket server that will handle TTLV bytes
///
/// # Arguments
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
///
/// # Errors
/// This function returns an error if:
/// - The socket server cannot be instantiated or started
/// - The server fails to run
///
/// # Returns
/// * a `JoinHandle<()>` that represents the socket server thread.
///
fn start_socket_server(kms_server: Arc<KMS>) -> KResult<JoinHandle<()>> {
    // Start the socket server
    let socket_server =
        SocketServer::instantiate(&SocketServerParams::try_from(kms_server.params.as_ref())?)?;
    let tokio_handle = Handle::current();
    let socket_server_handle =
        socket_server.start_threaded(kms_server, move |username, request, kms_server| {
            trace!("request: {username} {}", hex::encode(request));
            // Handle the TTLV bytes received from the socket server
            // tokio: run async code in the current thread
            tokio_handle.block_on(async {
                // Handle the TTLV bytes
                handle_ttlv_bytes(username, request, &kms_server).await
            })
        })?;
    Ok(socket_server_handle)
}

/// Start an HTTP(S) KMS server
///
/// # Arguments
///
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
/// This function returns an error if:
/// - The server cannot be instantiated or started
/// - The server fails to run
async fn start_http_kms_server(
    kms_server: Arc<KMS>,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    let server_params = &kms_server.params;
    let ssl_acceptor_builder = if let Some(tls_params) = &server_params.tls_params {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        if let Some(pkey) = &tls_params.p12.pkey {
            builder.set_private_key(pkey)?;
        }
        if let Some(cert) = &tls_params.p12.cert {
            builder.set_certificate(cert)?;
        }
        if let Some(chain) = &tls_params.p12.ca {
            for x in chain {
                builder.add_extra_chain_cert(x.to_owned())?;
            }
        }

        if let Some(verify_cert) = &tls_params.client_ca_cert_pem {
            // This line sets the mode to verify peer (client) certificates
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            let x509_cert = openssl::x509::X509::from_pem(verify_cert)
                .context("Failed to parse the client CA certificate")?;
            let mut store_builder = X509StoreBuilder::new()?;
            store_builder.add_cert(x509_cert)?;
            builder.set_verify_cert_store(store_builder.build())?;
        }
        Some(builder)
    } else {
        None
    };

    // Instantiate and prepare the KMS server
    let server = prepare_kms_server(kms_server, ssl_acceptor_builder).await?;

    // send the server handle to the caller
    if let Some(tx) = &server_handle_transmitter {
        tx.send(server.handle())?;
    }

    info!("Starting the HTTPS KMS server...");

    // Run the server and return the result
    server.await.map_err(Into::into)
}

/// This function handles a request to an inner path of the static UI and redirect
/// it to the index.html file, so that the routing renders the appropriate component
fn spa_index_handler(req: &HttpRequest, ui_index_html_folder: &PathBuf) -> actix_web::HttpResponse {
    let index_html_path = PathBuf::from(ui_index_html_folder).join("index.html");
    info!("Serving index.html from {}", index_html_path.display());
    match actix_files::NamedFile::open(index_html_path) {
        Ok(file) => file.into_response(req),
        Err(e) => {
            log::error!("Failed to open index.html: {e:?}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Prepare server for the application.
///
/// Creates an `HttpServer` instance,
/// configures the routes for the application, and sets the request timeout. The server can be
/// configured to use OpenSSL for SSL encryption by providing an `SslAcceptorBuilder`.
///
/// # Arguments
/// `kms_server`: A shared reference to the `KMS` instance to be used by the application.
/// `builder`: An optional `SslAcceptorBuilder` to configure the SSL encryption for the server.
///
/// # Returns
/// Returns a `Result` type that contains a `Server` instance if successful, or an error if
/// something went wrong.
///
/// # Errors
/// This function can return the following errors:
/// - `KmsError::ServerError` - If there is an error in the server configuration or preparation.
pub async fn prepare_kms_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> KResult<actix_web::dev::Server> {
    // Check if this auth server is enabled for Google Client-Side Encryption
    let enable_google_cse_authentication = kms_server.params.google_cse_kacls_url.is_some()
        && !kms_server.params.google_cse_disable_tokens_validation;

    // Prepare the JWT configurations and the JWKS manager if the server is using JWT for authentication.
    let (jwt_configurations, jwks_manager) = if let Some(identity_provider_configurations) =
        &kms_server.params.identity_provider_configurations
    {
        // Prepare all the needed URIs from all the configured Identity Providers
        let mut all_jwks_uris: Vec<_> = identity_provider_configurations
            .iter()
            .map(|idp_config| {
                JwtAuthConfig::uri(&idp_config.jwt_issuer_uri, idp_config.jwks_uri.as_deref())
            })
            .collect();
        // Add the one from google if cse is enabled
        if enable_google_cse_authentication {
            all_jwks_uris.extend(google_cse::list_jwks_uri());
        }

        let jwks_manager = Arc::new(JwksManager::new(all_jwks_uris).await?);

        let built_jwt_configurations = identity_provider_configurations
            .iter()
            .map(|idp_config| JwtConfig {
                jwt_issuer_uri: idp_config.jwt_issuer_uri.clone(),
                jwks: jwks_manager.clone(),
                jwt_audience: idp_config.jwt_audience.clone(),
            })
            .collect::<Vec<_>>();

        (Some(Arc::new(built_jwt_configurations)), Some(jwks_manager))
    } else {
        (None, None)
    };

    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = kms_server
        .params
        .tls_params
        .as_ref()
        .map_or(false, |tls_params| tls_params.client_ca_cert_pem.is_some());

    // Determine the address to bind the server to.
    let address = format!(
        "{}:{}",
        kms_server.params.http_hostname, kms_server.params.http_port
    );

    // Get the Google Client-Side Encryption JWT authorization config
    debug!("Enable Google CSE JWT Authorization: {enable_google_cse_authentication}");
    let google_cse_jwt_config = if enable_google_cse_authentication {
        let Some(jwks_manager) = jwks_manager else {
            return Err(KmsError::ServerError(
                "No JWKS manager to handle Google CSE JWT authorization".to_owned(),
            ));
        };
        let google_cse_config = GoogleCseConfig {
            authentication: jwt_configurations.clone().context(
                "When using Google client-side encryption, an identity provider used to \
                 authenticate Google Workspace users must be configured.",
            )?,
            authorization: google_cse::jwt_authorization_config(&jwks_manager),
        };
        trace!("Google CSE JWT Config: {:#?}", google_cse_config);
        Some(google_cse_config)
    } else {
        None
    };

    // Should we enable the MS DKE Service ?
    let enable_ms_dke = kms_server.params.ms_dke_service_url.is_some();

    let privileged_users: Option<Vec<String>> = kms_server.params.privileged_users.clone();

    // Generate key for actix session cookie encryption and elements for UI exposure
    let secret_key: Key = Key::generate();

    let kms_public_url = kms_server.params.kms_public_url.clone().map_or_else(
        || {
            format!(
                "http{}://{}:{}",
                if builder.is_some() { "s" } else { "" },
                &kms_server.params.hostname,
                &kms_server.params.port
            )
        },
        |url| url,
    );

    // Create the `HttpServer` instance.
    let server = HttpServer::new({
        move || {
            // Create an `App` instance and configure the passed data and the various scopes
            let mut app = App::new()
                .wrap(IdentityMiddleware::default())
                .wrap(
                    SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                        .cookie_path("/".to_owned())
                        .cookie_http_only(false)
                        .cookie_name("auth_session".to_owned())
                        .cookie_same_site(actix_web::cookie::SameSite::None)
                        .cookie_secure(true)
                        .session_lifecycle(
                            PersistentSession::default().session_ttl(Duration::hours(24)),
                        )
                        .build(),
                )
                .app_data(Data::new(kms_server.clone())) // Set the shared reference to the `KMS` instance.
                .app_data(PayloadConfig::new(10_000_000_000)) // Set the maximum size of the request payload.
                .app_data(JsonConfig::default().limit(10_000_000_000)); // Set the maximum size of the JSON request payload.

            if kms_server.params.google_cse_kacls_url.is_some() {
                // The scope for the Google Client-Side Encryption endpoints served from /google_cse
                let google_cse_scope = web::scope("/google_cse")
                    .app_data(Data::new(google_cse_jwt_config.clone()))
                    .wrap(Cors::permissive())
                    .service(google_cse::digest)
                    .service(google_cse::private_key_sign)
                    .service(google_cse::private_key_decrypt)
                    .service(google_cse::privileged_private_key_decrypt)
                    .service(google_cse::privileged_unwrap)
                    .service(google_cse::privileged_wrap)
                    .service(google_cse::rewrap)
                    .service(google_cse::get_status)
                    .service(google_cse::unwrap)
                    .service(google_cse::wrap)
                    .service(google_cse::wrapprivatekey);
                app = app.service(google_cse_scope);
            }

            if enable_ms_dke {
                // The scope for the Microsoft Double Key Encryption endpoints served from /ms_dke
                let ms_dke_scope = web::scope("/ms_dke")
                    .wrap(Cors::permissive())
                    .service(ms_dke::version)
                    .service(ms_dke::get_key)
                    .service(ms_dke::decrypt);
                app = app.service(ms_dke_scope);
            }

            let ui_index_folder = kms_server.params.ui_index_html_folder.clone();
            if ui_index_folder.join("index.html").exists() {
                info!("Serving UI from {}", ui_index_folder.display());
                let oidc_config = kms_server.params.ui_oidc_auth.clone();

                let auth_type: Option<String> = if jwt_configurations.is_some() {
                    Some("JWT".to_owned())
                } else if use_cert_auth {
                    Some("CERT".to_owned())
                } else {
                    None
                };

                let spa_routes = [
                    "/login",
                    "/locate",
                    "/sym{_:.*}",
                    "/rsa{_:.*}",
                    "/ec{_:.*}",
                    "/cc{_:.*}",
                    "/certificates{_:.*}",
                    "/attributes{_:.*}",
                    "/access-rights{_:.*}",
                ];
                let mut auth_routes = web::scope("/ui")
                    .app_data(web::Data::new(oidc_config))
                    .app_data(web::Data::new(kms_public_url.clone()))
                    .app_data(web::Data::new(ui_index_folder.clone()))
                    .app_data(web::Data::new(auth_type))
                    .wrap(Cors::permissive())
                    .configure(configure_auth_routes);
                // Add all SPA routes
                for route in spa_routes {
                    auth_routes = auth_routes.route(
                    route,
                    web::get().to(
                        move |req: HttpRequest, ui_index_folder: web::Data<PathBuf>| async move {
                            spa_index_handler(&req, &ui_index_folder)
                        },
                    ),
                );
                }
                // Add static files service
                auth_routes = auth_routes.service(
                    Files::new("/", ui_index_folder)
                        .index_file("index.html")
                        .use_last_modified(true)
                        .use_etag(true)
                        .prefer_utf8(true),
                );
                // Add the auth_routes to the main app
                app = app.service(auth_routes);
            } else {
                trace!(
                    "No UI folder containing index.html found at {}",
                    ui_index_folder.display()
                );
            }

        // The default scope serves from the root / the KMIP, permissions, and tee endpoints
        let default_scope = web::scope("")
            .wrap(AuthTransformer::new(
                kms_server.clone(),
                jwt_configurations.clone(),
            )) // Use JWT for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use certificates for authentication if necessary.
            // Enable CORS for the application.
            // Since Actix is running the middlewares in reverse order, it's important that the
            // CORS middleware is the last one so that the auth middlewares do not run on
            // preflight (OPTION) requests.
            .wrap(Cors::permissive())
            .service(kmip::kmip_2_1_json)
            .service(kmip::kmip)
            .service(access::list_owned_objects)
            .service(access::list_access_rights_obtained)
            .service(access::list_accesses)
            .service(access::grant_access)
            .service(access::revoke_access)
            .service(access::get_create_access)
            .service(access::get_privileged_access)
            .service(get_version);

        app.service(default_scope)
    })
    .client_disconnect_timeout(std::time::Duration::from_secs(30)) // default: 5s
    .tls_handshake_timeout(std::time::Duration::from_secs(18)) // default: 3s
    .keep_alive(std::time::Duration::from_secs(90)) // default: 5s
    .client_request_timeout(std::time::Duration::from_secs(90)) // default: 5s
    .shutdown_timeout(180); // default: 30s

    Ok(match builder {
        Some(cert_auth_builder) => {
            if use_cert_auth {
                // Start an HTTPS server with PKCS#12 with client cert auth
                server
                    .on_connect(extract_peer_certificate)
                    .bind_openssl(address, cert_auth_builder)?
                    .run()
            } else {
                // Start an HTTPS server with PKCS#12 but not client cert auth
                server.bind_openssl(address, cert_auth_builder)?.run()
            }
        }
        _ => server.bind(address)?.run(),
    })
}
