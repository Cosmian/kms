use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
};

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
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::KeyWrapType,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
            kmip_operations::Get,
            kmip_types::{KeyFormatType, LinkType, LinkedObjectIdentifier, UniqueIdentifier},
            requests::{create_rsa_key_pair_request, import_object_request},
        },
    },
    cosmian_kms_crypto::openssl::kmip_private_key_to_openssl,
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
    middlewares::{
        ApiTokenAuth, EnsureAuth, JwksManager, JwtAuth, JwtConfig, LogAllRequests, SslAuth,
        extract_peer_certificate,
    },
    result::{KResult, KResultHelper},
    routes::{
        access, get_version,
        google_cse::{self, GoogleCseConfig},
        kmip::{self, handle_ttlv_bytes},
        ms_dke,
        ui_auth::configure_auth_routes,
    },
    socket_server::{SocketServer, SocketServerParams},
    start_kms_server::google_cse::operations::GOOGLE_CSE_ID,
};

/// Handles the initialization or import of the Google CSE RSA keypair in the KMS.
///
/// This function performs the following logic:
/// 1. Attempts to retrieve the RSA keypair for Google CSE from the KMS.
/// 2. If the keypair exists and is valid, the function returns successfully.
/// 3. If the keypair is not found and a migration PEM key is provided in the `ServerParams`,
///    the key is imported along with its derived public key.
/// 4. If no key exists and no migration key is available, a new RSA keypair is created and stored.
///
/// This ensures that the KMS either reuses an existing RSA keypair, imports one for migration purposes,
/// or generates a new one, depending on availability and configuration.
///
/// # Arguments
///
/// * `kms_server` - A reference-counted pointer to the KMS instance, used to interact with the key management backend.
/// * `server_params` - A reference-counted pointer to the server configuration, which may contain a migration key.
///
/// # Errors
///
/// Returns a `KmsError` if:
/// * The RSA keypair fetch, import, or creation fails.
/// * The migration PEM key is malformed or cannot be parsed.
/// * Conversion between KMIP and OpenSSL formats fails.
pub async fn handle_google_cse_rsa_keypair(
    kms_server: &Arc<KMS>,
    server_params: &Arc<ServerParams>,
) -> KResult<()> {
    let uid_sk = format!("{GOOGLE_CSE_ID}_rsa");
    let uid_pk = format!("{GOOGLE_CSE_ID}_rsa_pk");

    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid_sk.clone())),
        key_format_type: Some(KeyFormatType::PKCS1),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };

    match kms_server
        .get(get_request, &server_params.default_username, None)
        .await
    {
        Ok(resp) => match resp.object_type {
            ObjectType::PrivateKey => {
                info!("RSA Keypair for Google CSE already exists.");
                return Ok(());
            }
            _ => {
                return Err(KmsError::CryptographicError(format!(
                    "Unexpected object type for Google CSE RSA keypair: {:?}",
                    resp.object_type
                )));
            }
        },
        Err(_) => {
            info!("RSA Keypair for Google CSE not found from existing DB.");
        }
    }

    if let Some(migration_key_pem) = &server_params.google_cse.google_cse_migration_key {
        info!("Found Google CSE migration key, importing it.");

        let key_bytes = pem::parse(migration_key_pem)
            .map_err(|e| {
                KmsError::CryptographicError(format!(
                    "Error parsing google_cse_migration PEM key: {e}"
                ))
            })?
            .contents()
            .to_vec();

        // Build PrivateKey object
        let object_sk = Object::PrivateKey(PrivateKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::PKCS8,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(key_bytes.into()),
                    attributes: Some(Attributes::default()),
                }),
                cryptographic_algorithm: None,
                cryptographic_length: None,
                key_wrapping_data: None,
            },
        });

        let mut import_attributes_sk = object_sk.attributes().cloned().unwrap_or_default();
        import_attributes_sk.set_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString(uid_pk.clone()),
        );

        // Generate matching public key
        let openssl_sk = kmip_private_key_to_openssl(&object_sk)?;
        let openssl_pk_bytes = openssl_sk.public_key_to_der()?;

        let object_pk = Object::PublicKey(PublicKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::PKCS8,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(openssl_pk_bytes.into()),
                    attributes: Some(Attributes::default()),
                }),
                cryptographic_algorithm: None,
                cryptographic_length: None,
                key_wrapping_data: None,
            },
        });

        let mut import_attributes_pk = object_pk.attributes().cloned().unwrap_or_default();
        import_attributes_pk.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(uid_sk.clone()),
        );

        // Import PrivateKey
        let import_request_sk = import_object_request::<Vec<String>>(
            Some(uid_sk.clone()),
            object_sk,
            Some(import_attributes_sk),
            false,
            false,
            vec![],
        );
        let imported_sk = kms_server
            .import(
                import_request_sk,
                &server_params.default_username,
                None,
                None,
            )
            .await?;

        // Import PublicKey
        let import_request_pk = import_object_request::<Vec<String>>(
            Some(uid_pk.clone()),
            object_pk,
            Some(import_attributes_pk),
            false,
            false,
            vec![],
        );
        let imported_pk = kms_server
            .import(
                import_request_pk,
                &server_params.default_username,
                None,
                None,
            )
            .await?;

        debug!("Imported RSA keypair with UID: {imported_sk:?} -- {imported_pk:?}");
    } else {
        info!("No migration key found, creating new RSA keypair.");

        let create_request = create_rsa_key_pair_request::<Vec<String>>(
            Some(UniqueIdentifier::TextString(uid_sk)),
            Vec::new(),
            4096,
            false,
            None,
        )?;

        let uid = kms_server
            .create_key_pair(create_request, &server_params.default_username, None, None)
            .await?;

        debug!("Created new RSA keypair with UID: {uid:?}");
    }

    Ok(())
}

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
/// * `server_params` - An instance of `ServerParams` containing the server's settings.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function will return an error if any server starting methods fail.
pub async fn start_kms_server(
    server_params: Arc<ServerParams>,
    kms_server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // OpenSSL is loaded now, so that tests can use the correct provider(s)

    // For an explanation of OpenSSL providers, see
    //  https://docs.openssl.org/3.1/man7/crypto/#openssl-providers

    // In FIPS mode, we only load the FIPS provider
    #[cfg(not(feature = "non-fips"))]
    let _provider = openssl::provider::Provider::load(None, "fips")?;

    // Not in FIPS mode and version > 3.0: load the default provider and the legacy provider
    // so that we can use the legacy algorithms,
    // particularly those used for old PKCS#12 formats
    #[cfg(feature = "non-fips")]
    let _provider = if openssl::version::number() >= 0x3000_0000 {
        debug!("OpenSSL: loading the legacy provider");
        openssl::provider::Provider::try_load(None, "legacy", true)
            .context("OpenSSL: unable to load the openssl legacy provider")?
    } else {
        debug!("OpenSSL: loading the default provider");
        // In version < 3.0, we only load the default provider
        openssl::provider::Provider::load(None, "default")?
    };

    // Instantiate KMS
    let kms_server = Arc::new(
        KMS::instantiate(server_params.clone())
            .await
            .context("start KMS server: failed instantiating the server")?,
    );

    // Handle Google RSA Keypair for CSE Kacls migration
    if server_params.google_cse.google_cse_enable {
        handle_google_cse_rsa_keypair(&kms_server, &server_params)
            .await
            .context("start KMS server: failed managing Google CSE RSA Keypair")?;
    }

    // Handle sockets
    let (ss_command_tx, _socket_server_handle) = if server_params.start_socket_server {
        let (tx, rx) = mpsc::channel::<KResult<()>>();
        // Start the socket server
        let socket_server_handle = start_socket_server(kms_server.clone(), rx)?;
        (Some(tx), Some(socket_server_handle))
    } else {
        (None, None)
    };

    // Log the server configuration
    info!("KMS Server configuration: {:#?}", server_params);
    let res = start_http_kms_server(kms_server.clone(), kms_server_handle_tx).await;
    if let Some(ss_command_tx) = ss_command_tx {
        // Send a shutdown command to the socket server
        ss_command_tx
            .send(Ok(()))
            .context("start KMS server: failed sending shutdown command to socket server")?;
    }
    res
}

/// Start a socket server that will handle TTLV bytes
///
/// # Arguments
/// * `server_params` - An instance of `ServerParams` containing the server's settings.
///
/// # Errors
/// This function returns an error if:
/// - The socket server cannot be instantiated or started
/// - The server fails to run
///
/// # Returns
/// * a `JoinHandle<()>` that represents the socket server thread.
///
fn start_socket_server(
    kms_server: Arc<KMS>,
    command_receiver: mpsc::Receiver<KResult<()>>,
) -> KResult<JoinHandle<()>> {
    // Start the socket server
    let socket_server =
        SocketServer::instantiate(&SocketServerParams::try_from(kms_server.params.as_ref())?)?;
    let tokio_handle = Handle::current();
    let socket_server_handle = socket_server.start_threaded(
        kms_server,
        move |username, request, kms_server| {
            trace!("request: {username} {}", hex::encode(request));
            // Handle the TTLV bytes received from the socket server
            // tokio: run async code in the current thread
            tokio_handle.block_on(async {
                // Handle the TTLV bytes
                handle_ttlv_bytes(username, request, &kms_server).await
            })
        },
        command_receiver,
    )?;
    Ok(socket_server_handle)
}

/// Start an HTTP(S) KMS server
///
/// # Arguments
///
/// * `server_params` - An instance of `ServerParams` containing the server's settings.
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
            // sending the client cert is optional so that
            // we can handle multiple authentication modes at the same time (WT token, API token)
            builder.set_verify(SslVerifyMode::PEER);
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

/// This function handles a request to an inner path of the static UI and redirects
/// it to the index.html file, so that the routing renders the appropriate component
fn spa_index_handler(req: &HttpRequest, ui_index_html_folder: &PathBuf) -> HttpResponse {
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

/// Prepare the server for the application.
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
/// Returns a `Result` type that contains a `Server` instance if successful, or an error if something went wrong.
///
/// # Errors
/// This function can return the following errors:
/// - `KmsError::ServerError` - If there is an error in the server configuration or preparation.
pub async fn prepare_kms_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> KResult<actix_web::dev::Server> {
    // Check if this auth server is enabled for Google Client-Side Encryption
    let enable_google_cse_authentication = kms_server.params.google_cse.google_cse_enable
        && !kms_server
            .params
            .google_cse
            .google_cse_disable_tokens_validation
        && kms_server.params.kms_public_url.is_some();

    // Prepare the JWT configurations and the JWKS manager if the server uses JWT for authentication.
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
        // Add the one from Google if CSE is enabled.
        if enable_google_cse_authentication {
            all_jwks_uris.extend(google_cse::list_jwks_uri(
                kms_server
                    .params
                    .google_cse
                    .google_cse_incoming_url_whitelist
                    .clone(),
            ));
        }

        let jwks_manager = Arc::new(
            JwksManager::new(all_jwks_uris, kms_server.params.proxy_params.as_ref()).await?,
        );

        let mut built_jwt_configurations = identity_provider_configurations
            .iter()
            .map(|idp_config| JwtConfig {
                jwt_issuer_uri: idp_config.jwt_issuer_uri.clone(),
                jwks: jwks_manager.clone(),
                jwt_audience: idp_config.jwt_audience.clone(),
            })
            .collect::<Vec<_>>();

        // Add the one from Google if CSE is enabled and some external urls are whitelisted
        if enable_google_cse_authentication {
            if let Some(white_list) = &kms_server
                .params
                .google_cse
                .google_cse_incoming_url_whitelist
            {
                built_jwt_configurations.extend(google_cse::list_jwt_configurations(
                    white_list,
                    &jwks_manager,
                ));
            }
        }
        (Arc::new(built_jwt_configurations), Some(jwks_manager))
    } else {
        (Arc::new(Vec::new()), None)
    };

    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = kms_server
        .params
        .tls_params
        .as_ref()
        .is_some_and(|tls_params| tls_params.client_ca_cert_pem.is_some());
    // Determine if API Token Auth should be used for authentication.
    let use_jwt_auth = !jwt_configurations.is_empty();
    // Determine if API Token Auth should be used for authentication.
    let use_api_token_auth = kms_server.params.api_token_id.is_some();

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
        if jwt_configurations.is_empty() {
            return Err(KmsError::ServerError(
                "Google CSE JWT authorization requires configuring at least one identity provider."
                    .to_owned(),
            ));
        }
        let google_cse_config = GoogleCseConfig {
            authentication: jwt_configurations.clone(),
            authorization: google_cse::jwt_authorization_config(&jwks_manager),
        };
        trace!("Google CSE JWT Config: {:#?}", google_cse_config);
        Some(google_cse_config)
    } else {
        None
    };

    // Should we enable the MS DKE Service?
    let enable_ms_dke = kms_server.params.ms_dke_service_url.is_some();

    let privileged_users: Option<Vec<String>> = kms_server.params.privileged_users.clone();

    // Generate key for actix session cookie encryption and elements for UI exposure
    let secret_key: Key = Key::generate();

    let kms_public_url = kms_server.params.kms_public_url.clone().map_or_else(
        || {
            format!(
                "http{}://{}:{}",
                if builder.is_some() { "s" } else { "" },
                &kms_server.params.http_hostname,
                &kms_server.params.http_port
            )
        },
        |url| url,
    );

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the passed data and the various scopes
        let mut app = App::new()
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_path("/".to_owned())
                    .cookie_http_only(true)
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

        if kms_server.params.kms_public_url.is_some()
            && kms_server.params.google_cse.google_cse_enable
        {
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
                .service(google_cse::certs)
                .service(google_cse::delegate);
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

            let auth_type: Option<String> = if use_jwt_auth {
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
                .app_data(Data::new(oidc_config))
                .app_data(Data::new(kms_public_url.clone()))
                .app_data(Data::new(ui_index_folder.clone()))
                .app_data(Data::new(auth_type))
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

        // The default scope serves from the root / the KMIP, permissions, and TEE endpoints
        let default_scope = web::scope("")
            .app_data(Data::new(privileged_users.clone()))
            .wrap(EnsureAuth::new(
                kms_server.clone(),
                use_jwt_auth || use_cert_auth || use_api_token_auth,
            ))
            .wrap(Condition::new(
                use_api_token_auth,
                ApiTokenAuth::new(kms_server.clone()),
            ))
            .wrap(Condition::new(
                use_jwt_auth,
                JwtAuth::new(jwt_configurations.clone()),
            )) // Use JWT for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use certificates for authentication if necessary.
            .wrap(LogAllRequests)
            // Enable CORS for the application.
            // Since Actix is running the middlewares in reverse order, it's important that the
            // CORS middleware is the last one, so that the auth middlewares do not run on
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
    // .client_disconnect_timeout(std::time::Duration::from_secs(30)) // default: 5s
    // .tls_handshake_timeout(std::time::Duration::from_secs(18)) // default: 3s
    // .keep_alive(std::time::Duration::from_secs(90)) // default: 5s
    // .client_request_timeout(std::time::Duration::from_secs(90)) // default: 5s
    // .shutdown_timeout(180); // default: 30s
;
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
