use std::sync::{mpsc, Arc};

use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_web::{
    dev::ServerHandle,
    middleware::Condition,
    web::{self, Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tracing::{debug, info, trace};

use crate::{
    config::{self, JwtAuthConfig, ServerParams},
    core::KMS,
    error::KmsError,
    kms_bail,
    middlewares::{extract_peer_certificate, AuthTransformer, JwksManager, JwtConfig, SslAuth},
    result::{KResult, KResultHelper},
    routes::{
        access, add_new_database, get_version,
        google_cse::{self, GoogleCseConfig},
        kmip, ms_dke,
    },
    KMSServer,
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
    server_params: ServerParams,
    kms_server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // OpenSSL is loaded now, so that tests can use the correct provider(s)

    // For an explanation of openssl providers, see
    //  https://docs.openssl.org/3.1/man7/crypto/#openssl-providers

    // In FIPS mode, we only load the fips provider
    #[cfg(feature = "fips")]
    let _provider = openssl::provider::Provider::load(None, "fips")?;

    // Not in FIPS mode and version > 3.0: load the default provider and the legacy provider
    // so that we can use the legacy algorithms
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

    // Log the server configuration
    info!("KMS Server configuration: {:#?}", server_params);
    match &server_params.http_params {
        config::HttpParams::Https(_) => {
            start_https_kms_server(server_params, kms_server_handle_tx).await
        }
        config::HttpParams::Http => {
            start_plain_http_kms_server(server_params, kms_server_handle_tx).await
        }
    }
}

/// Start a plain HTTP KMS server
///
/// This function will instantiate and prepare the KMS server and run it on a plain HTTP connection
///
/// # Arguments
///
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function returns an error if:
/// - The KMS server cannot be instantiated or prepared
/// - The server fails to run
async fn start_plain_http_kms_server(
    server_params: ServerParams,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate(server_params).await?);

    // Prepare the server
    let server = prepare_kms_server(kms_server, None).await?;

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
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
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
    server_params: ServerParams,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    let config::HttpParams::Https(p12) = &server_params.http_params else {
        kms_bail!("http/s: a PKCS#12 file must be provided")
    };

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

    if let Some(verify_cert) = &server_params.authority_cert_file {
        // This line sets the mode to verify peer (client) certificates
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(verify_cert.clone())?;
        builder.set_verify_cert_store(store_builder.build())?;
    }

    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate(server_params).await?);
    let server = prepare_kms_server(kms_server, Some(builder)).await?;

    // send the server handle to the caller
    if let Some(tx) = &server_handle_transmitter {
        tx.send(server.handle())?;
    }

    info!("Starting the HTTPS KMS server...");

    // Run the server and return the result
    server.await.map_err(Into::into)
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
 * # Errors
 *
 * This function can return the following errors:
 * - `KmsError::ServerError` - If there is an error in the server configuration or preparation.
 */
pub async fn prepare_kms_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> KResult<actix_web::dev::Server> {
    // Check if this auth server is enabled for Google Client-Side Encryption
    let enable_google_cse = kms_server.params.google_cse_kacls_url.is_some();

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
        if enable_google_cse {
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
    let use_cert_auth = kms_server.params.authority_cert_file.is_some();

    // Determine if the application is using an encrypted SQLite database.
    let is_using_sqlite_enc = matches!(
        kms_server.params.db_params,
        Some(config::DbParams::SqliteEnc(_))
    );

    // Determine the address to bind the server to.
    let address = format!("{}:{}", kms_server.params.hostname, kms_server.params.port);

    // Get the Google Client-Side Encryption JWT authorization config
    debug!("Enable Google CSE JWT Authorization: {enable_google_cse}");
    let google_cse_jwt_config = if enable_google_cse {
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
            kacls_url: kms_server.params.google_cse_kacls_url.clone().context(
                "The Google Workspace Client Side Encryption KACLS URL must be provided",
            )?,
        };
        trace!("Google CSE JWT Config: {:#?}", google_cse_config);
        Some(google_cse_config)
    } else {
        None
    };

    // Should we enable the MS DKE Service ?
    let enable_ms_dke = kms_server.params.ms_dke_service_url.is_some();

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the passed data and the various scopes
        let mut app = App::new()
            .wrap(IdentityMiddleware::default())
            .app_data(Data::new(kms_server.clone())) // Set the shared reference to the `KMS` instance.
            .app_data(PayloadConfig::new(10_000_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(10_000_000_000)); // Set the maximum size of the JSON request payload.

        if enable_google_cse {
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
            .service(kmip::kmip)
            .service(access::list_owned_objects)
            .service(access::list_access_rights_obtained)
            .service(access::list_accesses)
            .service(access::grant_access)
            .service(access::revoke_access)
            .service(get_version);

        // The default scope is extended with the /new_database endpoint if the application is using an encrypted SQLite database.
        let default_scope = if is_using_sqlite_enc {
            default_scope.service(add_new_database)
        } else {
            default_scope
        };

        app.service(default_scope)
    })
    .client_disconnect_timeout(std::time::Duration::from_secs(30)) // default: 5s
    .tls_handshake_timeout(std::time::Duration::from_secs(18)) // default: 3s
    .keep_alive(std::time::Duration::from_secs(30)) // default: 5s
    .client_request_timeout(std::time::Duration::from_secs(30)) // default: 5s
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
