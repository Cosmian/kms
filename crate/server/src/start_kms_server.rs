//! KMS server module responsible for starting and configuring the KMS server instance.
//!
//! This module provides functionality for:
//! - Starting HTTP/HTTPS KMS server
//! - Managing Google CSE RSA keypairs
//! - Handling socket server connections
//! - Configuring server authentication and TLS
//! - Setting up routes and middleware

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
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_operations::GetAttributes,
        kmip_types::{KeyFormatType, LinkType, LinkedObjectIdentifier, UniqueIdentifier},
        requests::{create_rsa_key_pair_request, import_object_request},
    },
    cosmian_kms_crypto::{
        crypto::password_derivation::{derive_key_from_password, FIPS_MIN_SALT_SIZE},
        openssl::kmip_private_key_to_openssl,
    },
};
use cosmian_logger::{debug, error, info, trace};
use openssl::{hash::{Hasher, MessageDigest}, ssl::SslAcceptorBuilder};
use tokio::{runtime::Handle, task::JoinHandle, try_join};

use crate::{
    config::{IdpAuthConfig, ServerParams, TlsParams},
    core::KMS,
    cron,
    error::KmsError,
    middlewares::{
        ApiTokenAuth, EnsureAuth, JwksManager, JwtAuth, JwtConfig, SslAuth,
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
    tls_config::{TlsConfig, configure_client_cert_verification, create_base_openssl_acceptor},
};

/// Handles the creation or import of RSA keypair used for Google Client-Side Encryption (CSE).
///
/// This function ensures that the required RSA keypair exists in the KMS for Google CSE operations.
/// It either:
/// 1. Creates a new 4096-bit RSA keypair if no migration key is provided
/// 2. Imports an existing migration key if provided via configuration
///
/// The keypair is stored with the following identifiers:
/// - Private key: `{GOOGLE_CSE_ID}_rsa`
/// - Public key: `{GOOGLE_CSE_ID}_rsa_pk`
///
/// # Arguments
///
/// * `kms_server` - Reference to the KMS server instance
/// * `server_params` - Server configuration parameters including Google CSE settings
///
/// # Returns
///
/// Returns `Ok(())` if the keypair exists or was successfully created/imported.
/// Returns `Err(KmsError)` if any operation fails.
///
/// # Errors
///
///  * `KmsError::ServerError` if the keypair cannot be created/imported
///
/// # Note
///
/// This function is idempotent - if the keypair already exists, it will not create a new one.
pub async fn handle_google_cse_rsa_keypair(
    kms_server: &Arc<KMS>,
    server_params: &Arc<ServerParams>,
) -> KResult<()> {
    let uid_sk = format!("{GOOGLE_CSE_ID}_rsa");
    let uid_pk = format!("{GOOGLE_CSE_ID}_rsa_pk");

    // Fast path: if the private key already exists, we're done.
    if let Ok(resp) = kms_server
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(uid_sk.clone())),
                attribute_reference: None,
            },
            &server_params.default_username,
            None,
        )
        .await
    {
        if resp.attributes.object_type == Some(ObjectType::PrivateKey) {
            info!("RSA Keypair for Google CSE already exists (pre-check).");
            return Ok(());
        }
    }

    let response =
        if let Some(migration_key_pem) = &server_params.google_cse.google_cse_migration_key {
            info!("Found Google CSE migration key, importing it.");
            import_cse_migration_key(
                kms_server,
                server_params,
                &uid_sk,
                &uid_pk,
                migration_key_pem,
            )
            .await
        } else {
            info!("No migration key found, creating new RSA keypair.");
            let create_request = create_rsa_key_pair_request::<Vec<String>>(
                Some(UniqueIdentifier::TextString(uid_sk.clone())),
                Vec::new(),
                4096,
                false,
                None,
            )?;
            kms_server
                .create_key_pair(create_request, &server_params.default_username, None, None)
                .await
                .map(|cr| {
                    (
                        cr.private_key_unique_identifier,
                        cr.public_key_unique_identifier,
                    )
                })
        };

    if let Err(e) = response {
        // If the error is due to a UNIQUE constraint, treat it as success (idempotent behavior).
        let err_str = format!("{e:?}");
        if err_str.contains("UNIQUE constraint failed") {
            info!(
                "RSA Keypair for Google CSE already exists (detected by UNIQUE constraint). Continuing without error."
            );
            return Ok(());
        }
        // We got an error (likely due to a duplicate). Treat existence as success by checking attributes.
        return match kms_server
            .get_attributes(
                GetAttributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(uid_sk)),
                    attribute_reference: None,
                },
                &server_params.default_username,
                None,
            )
            .await
        {
            Ok(resp) => {
                if resp.attributes.object_type == Some(ObjectType::PrivateKey) {
                    info!("RSA Keypair for Google CSE already exists.");
                    Ok(())
                } else {
                    Err(KmsError::CryptographicError(format!(
                        "Unexpected object type for Google CSE RSA keypair: {:?}",
                        resp.attributes.object_type
                    )))
                }
            }
            Err(eg) => {
                let msg = format!(
                    "RSA Keypair for Google CSE not found from existing DB ({eg:#?}), and there \
                     was an error trying to create it: {e:#?}"
                );
                error!("{}", &msg);
                Err(KmsError::ServerError(msg))
            }
        };
    }

    info!("RSA Keypair for Google CSE created.");

    Ok(())
}

/// Imports an existing Google CSE migration key pair into the KMS.
///
/// This function handles the import of an existing RSA private key in PEM format
/// and generates its corresponding public key. Both keys are then imported into
/// the KMS with proper linkage between them.
///
/// # Arguments
///
/// * `kms_server` - A reference-counted pointer to the KMS instance that will store the keys
/// * `server_params` - A reference-counted pointer to server configuration parameters
/// * `uid_sk` - The unique identifier string to assign to the private key
/// * `uid_pk` - The unique identifier string to assign to the public key
/// * `migration_key_pem` - The PEM-encoded private key string to import
///
/// # Returns
///
/// Returns a tuple of `(UniqueIdentifier, UniqueIdentifier)` containing the unique
/// identifiers for the imported private and public keys respectively.
///
/// # Errors
///
/// Returns a `KmsError` if:
/// * The PEM key cannot be parsed
/// * Key conversion between formats fails
/// * Key import operations fail
/// * Key linkage operations fail
async fn import_cse_migration_key(
    kms_server: &Arc<KMS>,
    server_params: &Arc<ServerParams>,
    uid_sk: &str,
    uid_pk: &str,
    migration_key_pem: &str,
) -> Result<(UniqueIdentifier, UniqueIdentifier), KmsError> {
    let key_bytes = pem::parse(migration_key_pem)
        .map_err(|e| {
            KmsError::CryptographicError(format!("Error parsing google_cse_migration PEM key: {e}"))
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
        LinkedObjectIdentifier::TextString(uid_pk.to_owned()),
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
        LinkedObjectIdentifier::TextString(uid_sk.to_owned()),
    );

    // Import PrivateKey
    let import_sk_fut = {
        let import_request_sk = import_object_request::<Vec<String>>(
            Some(uid_sk.to_owned()),
            object_sk,
            Some(import_attributes_sk),
            false,
            false,
            vec![],
        )?;
        kms_server.import(
            import_request_sk,
            &server_params.default_username,
            None,
            None,
        )
    };
    let import_pk_fut = {
        // Import PublicKey
        let import_request_pk = import_object_request::<Vec<String>>(
            Some(uid_pk.to_owned()),
            object_pk,
            Some(import_attributes_pk),
            false,
            false,
            vec![],
        )?;
        kms_server.import(
            import_request_pk,
            &server_params.default_username,
            None,
            None,
        )
    };

    try_join!(import_sk_fut, import_pk_fut)
        .map(|(resp_sk, resp_pk)| (resp_sk.unique_identifier, resp_pk.unique_identifier))
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

    // Spawn background metrics cron thread and retain shutdown signal
    let metrics_shutdown_tx = if kms_server.metrics.is_some() {
        Some(cron::spawn_metrics_cron(kms_server.clone()))
    } else {
        None
    };

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
    info!("KMS Server configuration: {server_params:#?}");
    let res = start_http_kms_server(kms_server.clone(), kms_server_handle_tx).await;
    // Signal the metrics cron thread to stop
    if let Some(tx) = metrics_shutdown_tx {
        let _ = tx.send(());
    }
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
    // Instantiate and prepare the KMS server
    let server = prepare_kms_server(kms_server).await?;

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
            error!("Failed to open index.html: {e:?}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Derive a session cookie encryption key from the public URL and a user-provided salt.
///
/// This function creates a deterministic key from the public URL and salt to ensure that
/// multiple server instances in a load-balanced setup can decrypt session cookies
/// created by any instance.
///
/// The key derivation uses:
/// - In FIPS mode: PBKDF2 with SHA-512
/// - In non-FIPS mode: Argon2
///
/// # Security Considerations
///
/// The salt MUST be:
/// 1. A secret value configured by the user
/// 2. Identical across all KMS instances behind the same load balancer
/// 3. Kept confidential to prevent key derivation attacks
///
/// # Versioning
///
/// The version string (v1) allows for future algorithm changes. If the derivation
/// algorithm needs to change, increment the version to ensure backward compatibility
/// during rolling upgrades.
///
/// # Arguments
///
/// * `public_url` - The public URL of the KMS server
/// * `user_salt` - A user-provided secret salt (must not be empty)
///
/// # Returns
///
/// Returns a 64-byte `Key` suitable for actix-web session cookie encryption.
///
/// # Errors
///
/// Returns `KmsError` if key derivation fails.
fn derive_session_key_from_url(public_url: &str, user_salt: &str) -> KResult<Key> {
    // Version prefix allows for future algorithm changes
    const VERSION: &str = "v1";
    
    // Create a URL-specific salt by combining salt seed, version, and URL
    // This ensures different URLs get different salts while maintaining determinism
    let salt_input = format!("{user_salt}{VERSION}{public_url}");
    
    // Hash the salt input to get a fixed-size salt
    // Using SHA-256 to get 32 bytes, then taking first FIPS_MIN_SALT_SIZE (16) bytes
    let mut hasher = Hasher::new(MessageDigest::sha256())
        .map_err(|e| KmsError::ServerError(format!("Failed to create hasher: {e}")))?;
    hasher.update(salt_input.as_bytes())
        .map_err(|e| KmsError::ServerError(format!("Failed to hash salt input: {e}")))?;
    let hash = hasher.finish()
        .map_err(|e| KmsError::ServerError(format!("Failed to finish hash: {e}")))?;
    
    // Extract first FIPS_MIN_SALT_SIZE bytes as salt
    // SHA-256 produces 32 bytes and FIPS_MIN_SALT_SIZE is 16, so this is always safe
    let mut salt = [0_u8; FIPS_MIN_SALT_SIZE];
    // This indexing is safe because SHA-256 always produces 32 bytes >= FIPS_MIN_SALT_SIZE (16)
    #[allow(clippy::indexing_slicing)]
    {
        salt.copy_from_slice(&hash[..FIPS_MIN_SALT_SIZE]);
    }
    
    // Derive a 64-byte key from the public URL
    let derived_key = derive_key_from_password::<64>(&salt, public_url.as_bytes())
        .map_err(|e| KmsError::ServerError(format!("Failed to derive session key: {e}")))?;
    
    // Convert the derived key to an actix-web Key
    Ok(Key::from(derived_key.as_ref()))
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
pub async fn prepare_kms_server(kms_server: Arc<KMS>) -> KResult<actix_web::dev::Server> {
    let tls_config = if let Some(tls_params) = &kms_server.params.tls_params {
        Some(create_openssl_acceptor(tls_params)?)
    } else {
        None
    };

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
                IdpAuthConfig::uri(&idp_config.jwt_issuer_uri, idp_config.jwks_uri.as_deref())
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
        .is_some_and(|tls_params| tls_params.clients_ca_cert_pem.is_some());
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
        // Only log google_cse_config on error - removed trace statement
        Some(google_cse_config)
    } else {
        None
    };

    // Should we enable the MS DKE Service?
    let enable_ms_dke = kms_server.params.ms_dke_service_url.is_some();

    let privileged_users: Option<Vec<String>> = kms_server.params.privileged_users.clone();

    // Compute the public URL first so we can use it to derive the session key
    let kms_public_url = kms_server.params.kms_public_url.clone().unwrap_or_else(|| {
        format!(
            "http{}://{}:{}",
            if tls_config.is_some() { "s" } else { "" },
            &kms_server.params.http_hostname,
            &kms_server.params.http_port
        )
    });

    // Derive key for actix session cookie encryption from the public URL
    // This ensures all instances in a load-balanced setup generate the same key
    let secret_key: Key = derive_session_key_from_url(
        &kms_public_url,
        &kms_server.params.session_salt,
    )?;

    // Clone kms_server for HttpServer closure
    let kms_server_for_http = kms_server.clone();

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
            .app_data(Data::new(kms_server_for_http.clone())) // Set the shared reference to the `KMS` instance.
            .app_data(PayloadConfig::new(10_000_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(10_000_000_000)); // Set the maximum size of the JSON request payload.

        if kms_server_for_http.params.kms_public_url.is_some()
            && kms_server_for_http.params.google_cse.google_cse_enable
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

        let ui_index_folder = kms_server_for_http.params.ui_index_html_folder.clone();
        if ui_index_folder.join("index.html").exists() {
            info!("Serving UI from {}", ui_index_folder.display());
            let oidc_config = kms_server_for_http.params.ui_oidc_auth.clone();

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
                "/secret-data{_:.*}",
                "/certificates{_:.*}",
                "/attributes{_:.*}",
                "/access-rights{_:.*}",
                "/google-cse",
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
                kms_server_for_http.clone(),
                use_jwt_auth || use_cert_auth || use_api_token_auth,
            ))
            .wrap(Condition::new(
                use_api_token_auth,
                ApiTokenAuth::new(kms_server_for_http.clone()),
            ))
            .wrap(Condition::new(
                use_jwt_auth,
                JwtAuth::new(jwt_configurations.clone()),
            )) // Use JWT for authentication if necessary.
            // Prefer checking API token before JWT to avoid header handling quirks
            .wrap(Condition::new(
                use_api_token_auth,
                ApiTokenAuth::new(kms_server.clone()),
            ))
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use certificates for authentication if necessary.
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
    .keep_alive(actix_web::http::KeepAlive::Timeout(
        std::time::Duration::from_secs(120),
    ))
    .client_request_timeout(std::time::Duration::from_secs(10)); // keep 10 seconds timeout for KMIP test vectors
    // The KMIP XML vector test harness keeps a single HTTP connection open across
    // many serialized requests with potentially long gaps (several seconds) while
    // preparing the next request. Actix-web's default keep-alive (~5s) was closing
    // the idle connection, leading to sporadic "connection reset by peer" errors
    // surfaced in the client test (reqwest) when it attempted to reuse the pooled
    // socket. Extending the keep-alive timeout prevents these false negatives and
    // lets us observe true protocol-level failures instead of transport resets.
    // Additionally, actix-web has a default client_request_timeout of 5 seconds which
    // was causing "408 Request Timeout" errors during long-running test operations.

    // Start and return the main KMS server
    Ok(match tls_config {
        Some(ssl_acceptor) => {
            if use_cert_auth {
                trace!("Using Client Certificate Authentication with OpenSSL");
                // Start an HTTPS server with PKCS#12 with client cert auth
                server
                    .on_connect(extract_peer_certificate)
                    .bind_openssl(address, ssl_acceptor)?
                    .run()
            } else {
                trace!("Not using Client Certificate Authentication with OpenSSL");
                // Start an HTTPS server with PKCS#12 but not client cert auth
                server.bind_openssl(address, ssl_acceptor)?.run()
            }
        }
        _ => server.bind(address)?.run(),
    })
}

// Client Certificate Authentication
// Build an OpenSSL SslAcceptorBuilder supporting client cert auth
pub(crate) fn create_openssl_acceptor(server_config: &TlsParams) -> KResult<SslAcceptorBuilder> {
    trace!("Creating OpenSSL SslAcceptorBuilder with TLS parameters");

    // Use the common TLS configuration
    let tls_config = {
        #[cfg(feature = "non-fips")]
        {
            TlsConfig {
                cipher_suites: server_config.cipher_suites.as_deref(),
                p12: &server_config.p12,
                client_ca_cert_pem: server_config.clients_ca_cert_pem.as_deref(),
            }
        }
        #[cfg(not(feature = "non-fips"))]
        {
            TlsConfig {
                cipher_suites: server_config.cipher_suites.as_deref(),
                server_cert_pem: &server_config.server_cert_pem,
                server_key_pem: &server_config.server_key_pem,
                server_chain_pem: server_config.server_chain_pem.as_deref(),
                client_ca_cert_pem: server_config.clients_ca_cert_pem.as_deref(),
            }
        }
    };

    let mut builder = create_base_openssl_acceptor(&tls_config, "http server")?;

    // Configure client certificate verification if specified
    if let Some(ca_cert_pem) = &server_config.clients_ca_cert_pem {
        configure_client_cert_verification(&mut builder, ca_cert_pem, "http server")?;
    }

    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::unwrap_used)]
    fn test_derive_session_key_deterministic() {
        // Load the appropriate provider if available
        #[cfg(not(feature = "non-fips"))]
        {
            let _ = openssl::provider::Provider::load(None, "fips");
        }

        let url1 = "https://kms.example.com:9998";
        let url2 = "https://kms.example.com:9998";
        let url3 = "https://kms.different.com:9998";
        let salt = "test_secret_salt";

        // Same URL and salt should generate the same key
        let key1 = derive_session_key_from_url(url1, salt).expect("Failed to derive key 1");
        let key2 = derive_session_key_from_url(url2, salt).expect("Failed to derive key 2");
        
        // Extract the key bytes for comparison
        let key1_bytes = key1.master();
        let key2_bytes = key2.master();
        
        assert_eq!(
            key1_bytes, key2_bytes,
            "Same URL and salt should generate identical keys"
        );

        // Different URL should generate different key
        let key3 = derive_session_key_from_url(url3, salt).expect("Failed to derive key 3");
        let key3_bytes = key3.master();
        
        assert_ne!(
            key1_bytes, key3_bytes,
            "Different URLs should generate different keys"
        );

        // Different salt should generate different key
        let key4 = derive_session_key_from_url(url1, "different_salt").expect("Failed to derive key 4");
        let key4_bytes = key4.master();
        
        assert_ne!(
            key1_bytes, key4_bytes,
            "Different salts should generate different keys"
        );

        // Verify key length is 64 bytes
        assert_eq!(key1_bytes.len(), 64, "Key should be 64 bytes");
    }

    #[test]
    #[expect(clippy::unwrap_used)]
    fn test_derive_session_key_from_empty_url() {
        // Load the appropriate provider if available
        #[cfg(not(feature = "non-fips"))]
        {
            let _ = openssl::provider::Provider::load(None, "fips");
        }

        // Even an empty URL should successfully derive a key
        let key = derive_session_key_from_url("", "test_salt").expect("Failed to derive key from empty URL");
        assert_eq!(key.master().len(), 64, "Key should be 64 bytes");
    }

    #[test]
    #[expect(clippy::unwrap_used)]
    fn test_derive_session_key_determinism() {
        // Load the appropriate provider if available
        #[cfg(not(feature = "non-fips"))]
        {
            let _ = openssl::provider::Provider::load(None, "fips");
        }

        let url = "https://kms.example.com:9998";
        let salt = "my_secret_salt";
        
        // Same URL and salt should always produce the same key
        let key1 = derive_session_key_from_url(url, salt).expect("Failed to derive key 1");
        let key2 = derive_session_key_from_url(url, salt).expect("Failed to derive key 2");
        
        // Should be deterministic
        assert_eq!(
            key1.master(),
            key2.master(),
            "Keys with same URL and salt should be identical"
        );
    }
}
