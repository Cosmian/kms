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
    middleware::{Condition, DefaultHeaders, from_fn},
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
        crypto::password_derivation::{FIPS_MIN_SALT_SIZE, derive_key_from_password},
        openssl::kmip_private_key_to_openssl,
    },
};
use cosmian_logger::{debug, error, info, trace, warn};
use openssl::{
    hash::{Hasher, MessageDigest},
    ssl::SslAcceptorBuilder,
};
use tokio::{runtime::Handle, task::JoinHandle, try_join};
use url::Url;

#[cfg(feature = "non-fips")]
use crate::routes::tokenize;
use crate::{
    config::{
        AuthVerifierConfig, AuthVerifierRuntimeConfig, IdpAuthConfig, OidcRuntimeConfig,
        ProxyParams, ServerParams, TlsParams,
    },
    core::KMS,
    cron,
    error::KmsError,
    middlewares::{
        AuditMiddleware, AuthVerifier, JwksManager, JwtConfig, SessionAuth, SpireTokenCache,
        api_token_middleware, ensure_auth_middleware, extract_peer_certificate,
        jwt_auth_middleware, otel_http_metrics_middleware, spire_token_middleware, tls_auth_fn,
        vault_token_optional_middleware,
    },
    result::{KResult, KResultHelper},
    routes::{
        access,
        aws_xks::{self},
        azure_ekm, cli_archive_download, cli_archive_exists, get_hsm_status, get_server_info,
        get_version,
        google_cse::{self, GoogleCseConfig},
        health, jose, jwks,
        kmip::{self, handle_ttlv_bytes},
        ms_dke, root_redirect,
        spire::{
            auth_proxy::proxy_auth_request,
            pki::sign_intermediate,
            transit::{
                configure_transit_key, create_transit_key, create_transit_key_put,
                delete_transit_key, get_transit_key, list_transit_keys, sign_with_transit_key,
                sign_with_transit_key_put,
            },
        },
        swagger,
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
                server_params.vendor_identification.as_str(),
                Some(UniqueIdentifier::TextString(uid_sk.clone())),
                Vec::new(),
                4096,
                false,
                None,
            )?;
            kms_server
                .create_key_pair(create_request, &server_params.default_username)
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
            server_params.vendor_identification.as_str(),
            Some(uid_sk.to_owned()),
            object_sk,
            Some(import_attributes_sk),
            false,
            false,
            vec![],
        )?;
        kms_server.import(import_request_sk, &server_params.default_username)
    };
    let import_pk_fut = {
        // Import PublicKey
        let import_request_pk = import_object_request::<Vec<String>>(
            server_params.vendor_identification.as_str(),
            Some(uid_pk.to_owned()),
            object_pk,
            Some(import_attributes_pk),
            false,
            false,
            vec![],
        )?;
        kms_server.import(import_request_pk, &server_params.default_username)
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

    // Load the appropriate OpenSSL provider based on FIPS mode and OpenSSL version
    crate::openssl_providers::init_openssl_providers()
        .context("OpenSSL: unable to load the required provider")?;

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

    // Spawn background auto-rotation cron thread and retain shutdown signal
    let auto_rotation_shutdown_tx = if kms_server.params.auto_rotation_check_interval_secs > 0 {
        Some(cron::spawn_auto_rotation_cron(kms_server.clone()))
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
    // Signal the auto-rotation cron thread to stop
    if let Some(tx) = auto_rotation_shutdown_tx {
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
    hasher
        .update(salt_input.as_bytes())
        .map_err(|e| KmsError::ServerError(format!("Failed to hash salt input: {e}")))?;
    let hash = hasher
        .finish()
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

/// Fetch the OIDC discovery document and build an `OidcRuntimeConfig`.
///
/// Called once at server startup. The discovered `authorization_endpoint` and
/// `token_endpoint` are **cached for the lifetime of the server process**. The
/// `jwks_uri` is fetched once here to seed the `JwksManager`, but signing keys
/// are refreshed on demand afterward (refresh-on-miss on an unknown `kid` in
/// `crate::routes::ui_auth::callback`) — key rotation at the `IdP` does not
/// require a restart.
///
/// WARNING: `authorization_endpoint`/`token_endpoint` are cached at startup.
/// Changes to the `IdP` configuration (issuer URL, endpoint URLs) require a
/// **server restart** to take effect.
async fn build_oidc_runtime_config(
    oidc_config: crate::config::OidcConfig,
    proxy_params: Option<&ProxyParams>,
) -> OidcRuntimeConfig {
    use crate::config::OidcDiscoveredEndpoints;

    let Some(ref issuer) = oidc_config.ui_oidc_issuer_url else {
        return OidcRuntimeConfig {
            config: oidc_config,
            discovered: None,
        };
    };

    let base = issuer.trim_end_matches('/');
    let discovery_url = format!("{base}/.well-known/openid-configuration");

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("OIDC: failed to build HTTP client for discovery: {e}");
            return OidcRuntimeConfig {
                config: oidc_config,
                discovered: None,
            };
        }
    };

    let discovery: serde_json::Value = match client.get(&discovery_url).send().await {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("OIDC: failed to parse discovery document from {discovery_url}: {e}");
                return OidcRuntimeConfig {
                    config: oidc_config,
                    discovered: None,
                };
            }
        },
        Err(e) => {
            warn!("OIDC: failed to fetch discovery document from {discovery_url}: {e}");
            return OidcRuntimeConfig {
                config: oidc_config,
                discovered: None,
            };
        }
    };

    let get_str = |key: &str| {
        discovery
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };

    let (Some(authorization_endpoint), Some(token_endpoint), Some(jwks_uri)) = (
        get_str("authorization_endpoint"),
        get_str("token_endpoint"),
        get_str("jwks_uri"),
    ) else {
        warn!("OIDC: discovery document at {discovery_url} is missing required fields");
        return OidcRuntimeConfig {
            config: oidc_config,
            discovered: None,
        };
    };

    info!("OIDC: discovered endpoints from {discovery_url}");
    debug!("OIDC: authorization_endpoint={authorization_endpoint}");
    debug!("OIDC: token_endpoint={token_endpoint}");
    debug!("OIDC: jwks_uri={jwks_uri}");

    let jwks_manager = match JwksManager::new(vec![jwks_uri], proxy_params).await {
        Ok(mgr) => Arc::new(mgr),
        Err(e) => {
            warn!("OIDC: failed to build JwksManager for UI OIDC: {e}");
            return OidcRuntimeConfig {
                config: oidc_config,
                discovered: None,
            };
        }
    };

    OidcRuntimeConfig {
        config: oidc_config,
        discovered: Some(OidcDiscoveredEndpoints {
            authorization_endpoint,
            token_endpoint,
            jwks_manager,
        }),
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
///
/// # Panics
/// Panics if the static fallback URL `"http://localhost"` fails to parse, which
/// cannot occur in practice since the URL is syntactically valid. This URL is only
/// constructed when `vault_api_enabled = false` or `vault_auth_verifier_url` is
/// absent, and is never invoked (guarded by `Condition::new(false, …)`).
pub async fn prepare_kms_server(kms_server: Arc<KMS>) -> KResult<actix_web::dev::Server> {
    // ── Startup security guards ──────────────────────────────────────────────

    // F-001: Warn loudly if the `insecure` feature flag is compiled in.
    #[cfg(feature = "insecure")]
    {
        cosmian_logger::error!(
            "SECURITY: KMS compiled with 'insecure' feature — ALL JWT and Auth Verifier signature \
             validation is DISABLED. Any syntactically valid token is accepted without signature \
             verification. This binary MUST NOT be used in production."
        );
    }

    // F-002: Warn if accept_invalid_certs is enabled for auth-verifier or vault connections.
    if kms_server
        .params
        .auth_verifier_config
        .as_ref()
        .is_some_and(|c| c.auth_verifier_accept_invalid_certs)
    {
        cosmian_logger::warn!(
            "SECURITY: auth_verifier_accept_invalid_certs is TRUE — TLS certificate verification \
             is DISABLED for Auth Verifier JWKS fetches. Only use in dev/test environments."
        );
    }
    if kms_server.params.vault_auth_verifier_accept_invalid_certs {
        cosmian_logger::warn!(
            "SECURITY: vault_auth_verifier_accept_invalid_certs is TRUE — TLS certificate \
             verification is DISABLED for Vault auth-verifier connections. Only use in dev/test."
        );
    }

    // F-003: Warn when Vault API is enabled but rate limiting is disabled.
    // The auth proxy at /v1/auth/* is unauthenticated and can be used to flood
    // the auth-verifier. The global rate limiter (if configured) mitigates this.
    if kms_server.params.vault_api_enabled && kms_server.params.rate_limit_per_second.is_none() {
        cosmian_logger::warn!(
            "SECURITY: vault_api_enabled is true but rate_limit_per_second is not set. The \
             unauthenticated auth proxy at /v1/auth/* can be used as a DoS amplifier. Set \
             rate_limit_per_second in the server config for production deployments."
        );
    }

    // F-008: Validate session salt entropy when UI is enabled.
    if kms_server.params.ui_enable {
        if let Some(ref salt) = kms_server.params.ui_session_salt {
            if salt.len() < 32 {
                return Err(KmsError::ServerError(format!(
                    "ui_session_salt is too short ({} bytes). Minimum 32 bytes required for \
                     adequate entropy. Generate one with: openssl rand -hex 32",
                    salt.len()
                )));
            }
            // Reject known-weak default values
            let weak_salts = [
                "test", "dev", "debug", "changeme", "password", "secret", "0000",
            ];
            if weak_salts.contains(&salt.to_ascii_lowercase().as_str()) {
                return Err(KmsError::ServerError(format!(
                    "ui_session_salt uses a weak/known-default value '{salt}'. Generate a random \
                     one with: openssl rand -hex 32"
                )));
            }
        } else {
            cosmian_logger::warn!(
                "UI is enabled but ui_session_salt is not set. A random salt will be generated \
                 per process, which invalidates existing sessions on restart. Set a persistent \
                 salt for production use."
            );
        }
    }

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

        // Security guard: all JWKS URIs must use HTTPS to prevent credential exposure and
        // MITM attacks on the public-key material used to verify bearer tokens.
        // In `insecure` builds (dev / integration tests with a local HTTP JWKS mock) this
        // check is compiled out to allow http:// URIs.
        #[cfg(not(feature = "insecure"))]
        validate_jwks_uris_are_https(&all_jwks_uris)?;

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
    // Determine if JWT Auth should be used for authentication.
    let use_jwt_auth = !jwt_configurations.is_empty();
    // Determine if API Token Auth should be used for authentication.
    let use_api_token_auth = kms_server.params.api_token_id.is_some();
    // Determine if Auth Verifier should be used for authentication.
    let (use_auth_verifier, auth_verifier_jwks_manager) =
        if let Some(ref auth_verifier_cfg) = kms_server.params.auth_verifier_config {
            let jwks_uri = auth_verifier_cfg.jwks_uri().ok_or_else(|| {
                KmsError::ServerError(
                    "Auth Verifier is enabled but no server URL is configured".to_owned(),
                )
            })?;
            // Security guard: the Auth Verifier JWKS URI must use HTTPS to prevent credential
            // exposure and MITM attacks on the public-key material used to verify bearer
            // tokens, same as for the other JWT identity providers above.
            // When `accept_invalid_certs` is set (dev/test only) the operator explicitly
            // acknowledges insecure transport, so the scheme check is also skipped.
            #[cfg(not(feature = "insecure"))]
            if !auth_verifier_cfg.auth_verifier_accept_invalid_certs {
                validate_jwks_uris_are_https(std::slice::from_ref(&jwks_uri))?;
            }

            let proxy_params = kms_server.params.proxy_params.clone();
            let mgr = Arc::new(
                JwksManager::new_with_options(
                    vec![jwks_uri],
                    proxy_params.as_ref(),
                    auth_verifier_cfg.auth_verifier_accept_invalid_certs,
                )
                .await
                .map_err(|e| {
                    KmsError::ServerError(format!(
                        "Failed to initialise Auth Verifier JWKS manager: {e}"
                    ))
                })?,
            );
            (true, Some(mgr))
        } else {
            (false, None)
        };

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

    // Should we enable the MS DKE Service ?
    let enable_ms_dke = kms_server.params.ms_dke_service_url.is_some();

    // Should we enable the AWS XKS Service?
    let enable_aws_xks = kms_server.params.aws_xks_params.is_some();

    // Should we enable the Azure EKM API ?
    let enable_azure_ekm = kms_server.params.azure_ekm.azure_ekm_enable;
    if enable_azure_ekm {
        // Validate path prefix if provided
        if let Some(prefix) = &kms_server.params.azure_ekm.azure_ekm_path_prefix {
            // Check length (max 64 characters)
            if prefix.len() > 64 {
                return Err(KmsError::ServerError(format!(
                    "Azure EKM path prefix is too long ({} chars). Maximum allowed is 64 characters.",
                    prefix.len()
                )));
            }

            if !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '-')
            {
                return Err(KmsError::ServerError(format!(
                    "Azure EKM path prefix contains illegal characters: '{prefix}'. Only a-z, A-Z, 0-9, '/', and '-' are allowed."
                )));
            }

            // Check for leading or trailing slashes
            if prefix.starts_with('/') || prefix.ends_with('/') {
                return Err(KmsError::ServerError(
                    "Azure EKM path prefix cannot start or end with '/'".to_owned(),
                ));
            }
        }

        if !kms_server.params.azure_ekm.azure_ekm_disable_client_auth && !use_cert_auth {
            return Err(KmsError::ServerError(
                "Azure EKM requires mTLS authentication but the KMS server is not configured with client certificate authentication.".to_owned()
            ));
        }
    }

    // Compute the public URL first so we can use it to derive the session key
    let kms_public_url = kms_server.params.kms_public_url.clone().unwrap_or_else(|| {
        format!(
            "http{}://{}:{}",
            if tls_config.is_some() { "s" } else { "" },
            kms_server.params.http_hostname,
            kms_server.params.http_port
        )
    });

    // Set the `Secure` flag on the session cookie only when the server is reachable
    // via HTTPS.  Over plain HTTP the browser never sends a Secure-flagged cookie
    // back, which breaks the post-login session for auth-verifier and OIDC flows.
    // The flag is enabled when the public URL uses `https://` or when TLS is
    // configured (so the auto-generated URL will also be `https://`).
    let session_cookie_secure = kms_public_url.starts_with("https://") || tls_config.is_some();

    // Derive the session cookie encryption key.
    // - If ui_session_salt is set: derive a stable key tied to the public URL using PBKDF2.
    //   This is deterministic across restarts and identical across load-balanced instances.
    // - Otherwise: generate a random ephemeral key (secure but lost on restart).
    //   Operators who need persistent sessions or load-balanced deployments MUST set
    //   `ui_session_salt` (or KMS_UI_SESSION_SALT).
    let secret_key: Key = if let Some(salt) = kms_server.params.ui_session_salt.as_deref() {
        derive_session_key_from_url(&kms_public_url, salt)?
    } else {
        // No secret configured: generate a cryptographically random ephemeral key.
        // This is secure, but sessions will be invalidated on every server restart
        // and are not portable across load-balanced instances.
        warn!(
            "ui_session_salt is not configured — using a randomly generated ephemeral \
             session key. Sessions will be invalidated on server restart and are not \
             portable across instances. For persistent sessions and load-balanced \
             deployments, set `ui_session_salt` (or KMS_UI_SESSION_SALT) to a strong \
             random secret value."
        );
        Key::generate()
    };

    // Clone kms_server for HttpServer closure
    let kms_server_for_http = kms_server.clone();

    // Pre-build the reqwest client for auth-verifier token validation.
    // Must be done here (outside the HttpServer closure) so that `?` propagates properly.
    let vault_http_client: Arc<reqwest::Client> =
        {
            let mut builder = reqwest::Client::builder();
            if kms_server.params.vault_auth_verifier_accept_invalid_certs {
                builder = builder.danger_accept_invalid_certs(true);
            } else if let Some(ca_cert_path) = &kms_server.params.vault_auth_verifier_ca_cert {
                let cert_pem = std::fs::read(ca_cert_path).map_err(|e| {
                    KmsError::ServerError(format!(
                        "cannot read vault_auth_verifier_ca_cert '{}': {e}",
                        ca_cert_path.display()
                    ))
                })?;
                let cert = reqwest::Certificate::from_pem(&cert_pem).map_err(|e| {
                    KmsError::ServerError(format!(
                        "invalid vault_auth_verifier_ca_cert '{}': {e}",
                        ca_cert_path.display()
                    ))
                })?;
                builder = builder.add_root_certificate(cert);
            }
            Arc::new(builder.build().map_err(|e| {
                KmsError::ServerError(format!("cannot build vault HTTP client: {e}"))
            })?)
        };

    // Pre-compute the vault token authentication context so it can be shared across all
    // route scopes (KMIP, transit/PKI, crypto, MS-DKE, tokenize) without re-creating the
    // cache per scope.  The `SpireTokenCache` is wrapped in `Arc` and shared across all
    // Actix workers for this server instance (`DashMap` provides safe concurrent access).
    //
    // When `vault_api_enabled = false` or `vault_auth_verifier_url` is absent, a dummy
    // context is created but never invoked: `Condition::new(false, …)` is a no-op.
    let use_vault_token_auth =
        kms_server.params.vault_api_enabled && kms_server.params.vault_auth_verifier_url.is_some();
    let spire_cache = SpireTokenCache::new(kms_server.params.vault_token_cache_ttl_secs);
    // When vault_api_enabled = false, this URL is never used; the literal is always valid.
    let spire_auth_verifier_url: Url = kms_server
        .params
        .vault_auth_verifier_url
        .clone()
        .unwrap_or_else(|| {
            // SAFETY: this fallback URL is only constructed when use_vault_token_auth = false,
            // where Condition::new(false, …) never invokes the middleware.
            #[allow(clippy::unwrap_used)]
            Url::parse("http://localhost").unwrap()
        });
    let spire_default_username: Arc<str> = kms_server.params.default_username.as_str().into();

    // Extract http_workers before the closure moves kms_server
    let http_workers = kms_server.params.http_workers;

    // Pre-compute OIDC runtime config (async, with discovery fetch) before the
    // synchronous HttpServer closure. Only built when the UI is enabled.
    let ui_oidc_runtime_config = {
        let ui_enable = kms_server.params.ui_enable;
        let ui_index_folder = kms_server.params.ui_index_html_folder.clone();
        if ui_enable && ui_index_folder.join("index.html").exists() {
            let oidc_config = kms_server.params.ui_oidc_auth.clone();
            let proxy_params = kms_server.params.proxy_params.clone();
            Some(Arc::new(
                build_oidc_runtime_config(oidc_config, proxy_params.as_ref()).await,
            ))
        } else {
            None
        }
    };

    // Rate limiting: keyed by peer IP.  Controlled by `ServerParams::rate_limit_per_second`.
    // The test-server helper leaves that field at `None` so parallel unit tests are never
    // throttled by the rate limiter. Production configs set it to 100 (req/s, burst 300).
    let rate_limit_enabled = kms_server.params.rate_limit_per_second.is_some();
    // When rate limiting is disabled the Condition wrapper short-circuits, so we
    // provide a permissive fallback config that is never actually invoked.
    let rate_limiter_config = crate::middlewares::RateLimiterConfig::new(
        u64::from(kms_server.params.rate_limit_per_second.unwrap_or(u32::MAX)),
        kms_server
            .params
            .rate_limit_per_second
            .map_or(u32::MAX, |rps| rps.saturating_mul(3)),
    );

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the passed data and the various scopes
        let mut app = App::new()
            .wrap(otel_http_metrics_middleware(kms_server_for_http.metrics.clone()))
            .wrap(Condition::new(
                rate_limit_enabled,
                crate::middlewares::RateLimiterMiddleware::new(&rate_limiter_config),
            ))
            .wrap(
                DefaultHeaders::new()
                    // Prevent the UI from being embedded in a foreign frame (clickjacking)
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Content-Security-Policy", "frame-ancestors 'none'")),
            )
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_path("/".to_owned())
                    .cookie_http_only(true)
                    .cookie_name("auth_session".to_owned())
                    .cookie_same_site(actix_web::cookie::SameSite::Lax)
                    .cookie_secure(session_cookie_secure)
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(Duration::hours(24)),
                    )
                    .build(),
            )
            .app_data(Data::new(kms_server_for_http.clone())) // Set the shared reference to the `KMS` instance.
            // 64 MB — realistic maximum for KMIP payloads including wrapped keys and certificates.
            // The previous 10 GB limit allowed unauthenticated clients to exhaust server RAM (DoS).
            .app_data(PayloadConfig::new(64 * 1024 * 1024))
            .app_data(
                JsonConfig::default()
                    .limit(64 * 1024 * 1024)
                    .error_handler(|err, _req| {
                        let message = format!("{err}");
                        actix_web::error::InternalError::from_response(
                            err,
                            HttpResponse::BadRequest()
                                .content_type("text/plain")
                                .body(message),
                        )
                        .into()
                    }),
            );

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
                .service(google_cse::wrapprivatekey)
                .service(google_cse::certs)
                .service(google_cse::delegate);
            app = app.service(google_cse_scope);
        }

        if enable_ms_dke {
            // The scope for the Microsoft Double Key Encryption endpoints served from /ms_dke
            // SECURITY: DKE endpoints MUST be authenticated to prevent unauthenticated
            // decryption oracles. Microsoft's DKE protocol uses Azure AD tokens;
            // we enforce the same auth stack as the main KMIP scope.
            let ms_dke_scope = web::scope("/ms_dke")
                .wrap(ensure_auth_middleware(
                    kms_server_for_http.clone(),
                    use_vault_token_auth || use_jwt_auth || use_cert_auth || use_api_token_auth || use_auth_verifier,
                ))
                .wrap(Condition::new(
                    use_api_token_auth,
                    api_token_middleware(kms_server_for_http.clone()),
                ))
                .wrap(Condition::new(
                    use_jwt_auth,
                    jwt_auth_middleware(jwt_configurations.clone()),
                ))
                .wrap(Condition::new(use_cert_auth, from_fn(tls_auth_fn)))
                // Optional vault-token auth: accepts `X-Vault-Token` in lieu of native auth
                // when vault_api_enabled = true. Runs before native auth (LIFO wrap order).
                .wrap(Condition::new(
                    use_vault_token_auth,
                    vault_token_optional_middleware(
                        spire_cache.clone(),
                        spire_auth_verifier_url.clone(),
                        vault_http_client.clone(),
                        spire_default_username.clone(),
                    ),
                ))
                .wrap(Cors::permissive())
                .service(ms_dke::version)
                .service(ms_dke::get_key)
                .service(ms_dke::decrypt);
            app = app.service(ms_dke_scope);
        }

        if enable_aws_xks {
            // The scope for the AWS XKS (External Key Store) endpoints served from /aws
            let aws_xks_scope = web::scope("/aws")
                .app_data(web::JsonConfig::default().error_handler(aws_xks::xks_json_error_handler))
                .wrap(Cors::permissive())
                .wrap(aws_xks::Sigv4MWare::new(kms_server.clone()))
                .service(aws_xks::get_health_status)
                .service(aws_xks::get_key_metadata)
                .service(aws_xks::encrypt)
                .service(aws_xks::decrypt)
                .default_service(web::to(aws_xks::xks_path_not_found_handler));

            app = app.service(aws_xks_scope);
        }

        if enable_azure_ekm {
            if kms_server.params.azure_ekm.azure_ekm_disable_client_auth {
                warn!(
                    "Azure EKM client authentication is disabled, this should only be done in tests, and won't work for production environments."
                );
            }

            let base_path = kms_server
                .params
                .azure_ekm
                .azure_ekm_path_prefix
                .as_ref()
                .map_or_else(
                    // for unknown reasons, an "azure-ekm" base path will get compiled to "azure_ekm" in the binary, but underscores go against the path specs.
                    || "/azureekm".to_owned(),
                    |prefix| format!("/azureekm/{prefix}"),
                );

            info!("azure EKM API enabled at {}", base_path);

            let azure_ekm_scope = web::scope(&base_path)
                .app_data(azure_ekm::ekm_json_config())
                .wrap(Condition::new(
                    !kms_server.params.azure_ekm.azure_ekm_disable_client_auth,
                    ensure_auth_middleware(kms_server_for_http.clone(), use_cert_auth),
                ))
                .wrap(Condition::new(
                    !kms_server.params.azure_ekm.azure_ekm_disable_client_auth && use_cert_auth,
                    from_fn(tls_auth_fn),
                ))
                .wrap(
                    // EKM is a server-to-server mTLS API: deny all browser cross-origin requests.
                    Cors::default(),
                )
                .service(azure_ekm::get_proxy_info)
                .service(azure_ekm::get_key_metadata)
                .service(azure_ekm::wrap_key)
                .service(azure_ekm::unwrap_key);

            app = app.service(azure_ekm_scope);
        }

        #[cfg(feature = "non-fips")]
        {
            // Middleware registration order: LAST registered = runs FIRST.
            // Cors must run first to handle OPTIONS preflight before auth checks.
            // Auth extractors (TlsAuth, JwtAuth, ApiTokenAuth) must inject
            // AuthenticatedUser before EnsureAuth verifies it.
            //
            // vault_token_optional_middleware is intentionally *optional*: it enriches the
            // request identity when `X-Vault-Token` is present but does NOT mandate that a
            // vault token be supplied. Only "hard" auth methods (JWT, cert, API token) make
            // the endpoint actually require authentication.
            let use_any_auth = use_jwt_auth || use_cert_auth || use_api_token_auth || use_auth_verifier;
            let tokenize_scope = web::scope("/tokenize")
                .app_data(web::JsonConfig::default().limit(65_536))
                .wrap(Condition::new(
                    use_any_auth,
                    ensure_auth_middleware(kms_server_for_http.clone(), use_any_auth),
                ))
                .wrap(SessionAuth)
                .wrap(Condition::new(
                    use_api_token_auth,
                    api_token_middleware(kms_server_for_http.clone()),
                ))
                .wrap(Condition::new(
                    use_auth_verifier,
                    AuthVerifier::new(auth_verifier_jwks_manager.clone()),
                ))
                .wrap(Condition::new(
                    use_jwt_auth,
                    jwt_auth_middleware(jwt_configurations.clone()),
                ))
                .wrap(Condition::new(use_cert_auth, from_fn(tls_auth_fn)))
                // Optional vault-token auth: accepts `X-Vault-Token` in lieu of native auth
                // when vault_api_enabled = true. Runs before native auth (LIFO wrap order).
                .wrap(Condition::new(
                    use_vault_token_auth,
                    vault_token_optional_middleware(
                        spire_cache.clone(),
                        spire_auth_verifier_url.clone(),
                        vault_http_client.clone(),
                        spire_default_username.clone(),
                    ),
                ))
                .wrap(Cors::permissive())
                .service(tokenize::hash)
                .service(tokenize::noise)
                .service(tokenize::word_mask)
                .service(tokenize::word_tokenize)
                .service(tokenize::word_pattern_mask)
                .service(tokenize::aggregate_number)
                .service(tokenize::aggregate_date)
                .service(tokenize::scale_number);
            app = app.service(tokenize_scope);
        }

        // ── Vault-compatible API (Transit + PKI) ──────────────────────────────
        // Enabled only when `vault_api_enabled = true` in server config.
        // Authentication: `X-Vault-Token` header validated by `spire_token_middleware`
        // which calls `GET <vault_auth_verifier_url>/v1/auth/token/lookup-self`.
        if kms_server_for_http.params.vault_api_enabled {
            if use_vault_token_auth {
                let transit_mount = kms_server_for_http.params.vault_transit_mount.clone();
                let transit_scope_path = format!("/v1/{transit_mount}");
                let transit_scope = web::scope(&transit_scope_path)
                    // SPIRE's `vault` KeyManager plugin (SPIRE >= 1.15.0) does
                    // not always set a `Content-Type: application/json` header on its
                    // `PUT` key-creation request; accept the JSON body regardless.
                    .app_data(JsonConfig::default().content_type_required(false))
                    .wrap(spire_token_middleware(
                        spire_cache.clone(),
                        spire_auth_verifier_url.clone(),
                        vault_http_client.clone(),
                        spire_default_username.clone(),
                    ))
                    .wrap(Cors::default())
                    .service(create_transit_key)
                    .service(create_transit_key_put)
                    .service(configure_transit_key)
                    .service(get_transit_key)
                    .service(list_transit_keys)
                    .service(delete_transit_key)
                    .service(sign_with_transit_key)
                    .service(sign_with_transit_key_put);
                app = app.service(transit_scope);

                let pki_mount = kms_server_for_http.params.vault_pki_mount.clone();
                let pki_scope_path = format!("/v1/{pki_mount}");
                let pki_scope = web::scope(&pki_scope_path)
                    .wrap(spire_token_middleware(
                        spire_cache.clone(),
                        spire_auth_verifier_url.clone(),
                        vault_http_client.clone(),
                        spire_default_username.clone(),
                    ))
                    .wrap(Cors::default())
                    .service(sign_intermediate);
                app = app.service(pki_scope);

                // Auth proxy scope: forward /v1/auth/* to the auth-verifier.
                // SPIRE authenticates via AppRole login at vault_addr/v1/auth/approle/login,
                // which is forwarded here to the auth-verifier unchanged.
                // The KMS token-validation middleware still calls auth-verifier directly
                // (server-to-server) — transit/PKI hot-path requests are never proxied.
                //
                // NOTE: In Actix-web 4, a Scope with *only* default_service and no
                // explicit .service() registrations is silently dropped from the router.
                // We must register at least one resource; the wildcard `/{tail:.*}` catches
                // all sub-paths for all HTTP methods, which is exactly what the proxy needs.
                let auth_scope = web::scope("/v1/auth")
                    .app_data(web::Data::new(vault_http_client.clone()))
                    .app_data(web::Data::new(spire_auth_verifier_url.clone()))
                    .wrap(Cors::default())
                    .service(
                        web::resource("/{tail:.*}")
                            .route(web::route().to(proxy_auth_request)),
                    );
                app = app.service(auth_scope);

                info!(
                    "Vault-compatible API enabled: transit at {transit_scope_path}, PKI at {pki_scope_path}, auth proxy at /v1/auth"
                );
            } else {
                warn!(
                    "vault_api_enabled = true but vault_auth_verifier_url is not set — \
                     Vault-compatible API will NOT be registered. \
                     Set vault_auth_verifier_url in the server config."
                );
            }
        }

        let ui_index_folder = kms_server_for_http.params.ui_index_html_folder.clone();
        if kms_server_for_http.params.ui_enable && ui_index_folder.join("index.html").exists() {
            info!("Serving UI from {}", ui_index_folder.display());
            // OIDC runtime config was pre-computed before HttpServer::new (async discovery).
            let oidc_runtime_config: OidcRuntimeConfig = ui_oidc_runtime_config
                .as_ref()
                .map_or_else(
                    || OidcRuntimeConfig {
                        config: kms_server_for_http.params.ui_oidc_auth.clone(),
                        discovered: None,
                    },
                    |arc| arc.as_ref().clone(),
                );

            // Ordered list of UI login methods, highest priority first. The Web UI
            // renders the first entry as the primary login action and the rest as
            // secondary actions (a button when a single alternative exists, a
            // dropdown when several do). Priority is JWT > AUTH_VERIFIER > CERT:
            // the interactive, per-user methods come before the ambient client
            // certificate probe. AUTH_VERIFIER is only offered when its UI login is
            // enabled. The singular `auth_method` served by `get_auth_method` is
            // derived as the first entry for backward compatibility.
            let mut auth_methods: Vec<String> = Vec::new();
            if use_jwt_auth {
                auth_methods.push("JWT".to_owned());
            }
            if use_auth_verifier
                && kms_server_for_http
                    .params
                    .auth_verifier_config
                    .as_ref()
                    .is_some_and(AuthVerifierConfig::ui_login_enabled)
            {
                auth_methods.push("AUTH_VERIFIER".to_owned());
            }
            if use_cert_auth {
                auth_methods.push("CERT".to_owned());
            }

            // BFF runtime config for the Auth Verifier server Web UI login
            // (`/ui/login_as`). Reuses the JWKS manager already built above for the
            // bearer-token `AuthVerifier` middleware — no second JWKS fetch.
            let auth_verifier_runtime_config = AuthVerifierRuntimeConfig {
                config: kms_server_for_http
                    .params
                    .auth_verifier_config
                    .clone()
                    .unwrap_or_default(),
                jwks_manager: auth_verifier_jwks_manager.clone(),
            };

            // These paths mirror the React application's client-side routes
            // (declared with react-router-dom).  Actix-Web must forward every
            // deep-link request to the SPA's `index.html` so the browser can
            // perform client-side navigation; without these registrations the
            // server would return 404 when a page is loaded directly (e.g. on
            // a browser refresh or when following a bookmark).
            let spa_routes = [
                "/login",
                "/locate",
                "/sym{_:.*}",
                "/rsa{_:.*}",
                "/ec{_:.*}",
                "/pqc{_:.*}",
                "/mac{_:.*}",
                "/cc{_:.*}",
                "/secret-data{_:.*}",
                "/opaque-object{_:.*}",
                "/certificates{_:.*}",
                "/attributes{_:.*}",
                "/access-rights{_:.*}",
                "/derive-key{_:.*}",
                "/azure{_:.*}",
                "/aws{_:.*}",
                "/google-cse{_:.*}",
                "/tokenize{_:.*}",
                "/rotation-policy{_:.*}",
            ];
            let mut auth_routes = web::scope("/ui")
                .app_data(Data::new(oidc_runtime_config))
                .app_data(Data::new(auth_verifier_runtime_config))
                .app_data(Data::new(kms_public_url.clone()))
                .app_data(Data::new(ui_index_folder.clone()))
                .app_data(Data::new(auth_methods))
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

        // Public endpoints (no authentication) — health/version for connectivity checks.
        // Swagger UI and OpenAPI schema are also public so they remain reachable when
        // the server requires TLS client certificates or other auth methods that a
        // browser cannot satisfy for static assets.
        app = app
            .service(root_redirect::root_redirect_to_ui)
            .service(health::get_health)
            .service(get_version)
            .service(swagger::get_openapi_yaml)
            .service(swagger::get_swagger_ui)
            .service(swagger::get_swagger_ui_js)
            .service(swagger::get_swagger_ui_css);

        // JWKS endpoint: public, unauthenticated, CORS-open (partially).
        // The scope prefix `/.well-known` is explicit so this scope does not conflict
        // with the empty-prefix default_scope and its restrictive CORS configuration.
        if kms_server_for_http.params.jwks_endpoint.jwks_endpoint_enabled {
            warn!(
                "JWKS endpoint enabled — all active public keys with the \"jwks\" tag will be publicly exposed (unauthenticated) at \
                 `{kms_public_url}/.well-known/jwks.json`. Up to {} keys will be served. \
                 Ensure this is intentional. Configure via the `[jwks_endpoint]` section in the server configuration file.",
                kms_server_for_http.params.jwks_endpoint.jwks_endpoint_max_keys
            );
            app = app.service(
                web::scope("/.well-known")
                    .wrap(
                        Cors::default()
                            .allow_any_origin()
                            // HEAD is included so that CDN healthchecks and HTTP
                            // clients that probe with HEAD before GET work correctly.
                            .allowed_methods(vec!["GET", "HEAD"])
                    )
                    .service(jwks::get_jwks),
            );
        }

        // REST Native Crypto API — /v1/crypto/*
        let crypto_scope = web::scope("/v1/crypto")
            .app_data(
                web::JsonConfig::default()
                    .error_handler(jose::crypto_json_error_handler),
            )
            .wrap(ensure_auth_middleware(
                kms_server_for_http.clone(),
                use_jwt_auth || use_cert_auth || use_api_token_auth || use_auth_verifier,
            ))
            .wrap(SessionAuth)
            .wrap(Condition::new(
                use_api_token_auth,
                api_token_middleware(kms_server_for_http.clone()),
            ))
            .wrap(Condition::new(
                use_auth_verifier,
                AuthVerifier::new(auth_verifier_jwks_manager.clone()),
            ))
            .wrap(Condition::new(
                use_jwt_auth,
                jwt_auth_middleware(jwt_configurations.clone()),
            ))
            .wrap(Condition::new(use_cert_auth, from_fn(tls_auth_fn)))
            // Optional vault-token auth: accepts `X-Vault-Token` in lieu of native auth
            // when vault_api_enabled = true. Runs before native auth (LIFO wrap order).
            .wrap(Condition::new(
                use_vault_token_auth,
                vault_token_optional_middleware(
                    spire_cache.clone(),
                    spire_auth_verifier_url.clone(),
                    vault_http_client.clone(),
                    spire_default_username.clone(),
                ),
            ))
            .wrap(Cors::permissive())
            .service(jose::encrypt_handler)
            .service(jose::decrypt_handler)
            .service(jose::sign_handler)
            .service(jose::verify_handler)
            .service(jose::mac_handler)
            .service(jose::create_key_handler)
            .service(jose::delete_key_handler)
            .service(jose::unwrap_key_handler)
            .service(jose::add_tags_handler)
            .service(jose::remove_tags_handler)
            .service(jose::list_tags_handler);
        app = app.service(crypto_scope);

        // The default scope serves from the root / the KMIP, permissions, and TEE endpoints
        let default_scope = web::scope("")
            .wrap(ensure_auth_middleware(
                kms_server_for_http.clone(),
                use_jwt_auth || use_cert_auth || use_api_token_auth || use_auth_verifier,
            ))
            .wrap(SessionAuth)
            .wrap(Condition::new(
                use_api_token_auth,
                api_token_middleware(kms_server_for_http.clone()),
            ))
            .wrap(Condition::new(
                use_auth_verifier,
                AuthVerifier::new(auth_verifier_jwks_manager.clone()),
            ))
            .wrap(Condition::new(
                use_jwt_auth,
                jwt_auth_middleware(jwt_configurations.clone()),
            )) // Use JWT for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, from_fn(tls_auth_fn))) // Use certificates for authentication if necessary.
            // Optional vault-token auth: accepts `X-Vault-Token` in lieu of native auth
            // when vault_api_enabled = true. Runs before native auth (LIFO wrap order).
            .wrap(Condition::new(
                use_vault_token_auth,
                vault_token_optional_middleware(
                    spire_cache.clone(),
                    spire_auth_verifier_url.clone(),
                    vault_http_client.clone(),
                    spire_default_username.clone(),
                ),
            ))
            // Tamper-evident audit logging: wraps every auth method above so both
            // successful and failed authentication attempts are recorded (LIFO wrap order).
            .wrap(AuditMiddleware::new(
                kms_server_for_http.audit_store.clone(),
                kms_server_for_http.params.audit_trusted_proxy_cidrs.clone(),
            ))
            // CORS: KMIP is a server-to-server protocol; restrict to same-origin by default.
            // Additional origins (e.g. a Vite dev server in E2E tests) can be allowed via
            // `cors_allowed_origins` / `KMS_CORS_ALLOWED_ORIGINS`. Enterprise-integration scopes
            // (Google CSE, MS DKE, AWS XKS) have their own permissive CORS configuration.
            // When origins are configured, allow any method and header for those origins so that
            // browser WASM clients (which use POST with Content-Type: application/octet-stream) can
            // pass the CORS preflight check and carry session cookies (`credentials: "include"`).
            // When no origins are configured, Cors::default() with no allowed origins effectively
            // blocks all cross-origin requests (same-origin only).
            .wrap({
                let mut cors = Cors::default()
                    .allow_any_method()
                    .allow_any_header()
                    .supports_credentials();
                for origin in &kms_server_for_http.params.cors_allowed_origins {
                    cors = cors.allowed_origin(origin.as_str());
                }
                cors
            })
            .service(kmip::kmip_2_1_json)
            .service(kmip::kmip)
            .service(get_server_info)
            .service(get_hsm_status)
            .service(access::get_current_user)
            .service(access::list_owned_objects)
            .service(access::list_access_rights_obtained)
            .service(access::list_accesses)
            .service(access::grant_access)
            .service(access::revoke_access)
            .service(access::get_create_access)
            .service(access::get_privileged_access)
            .service(
                web::resource("/download-cli")
                    .route(web::get().to(cli_archive_download))
                    .route(web::head().to(cli_archive_exists)),
            );

        app.service(default_scope)
    })
    .keep_alive(actix_web::http::KeepAlive::Timeout(
        std::time::Duration::from_secs(120),
    ))
    .client_request_timeout(std::time::Duration::from_secs(10)); // keep 10 seconds timeout for KMIP test vectors

    // Apply worker count if configured; otherwise default to available_parallelism
    // (total logical cores). HTTP workers are I/O-bound (connection handling), so
    // using total core count (including efficiency cores on hybrid architectures)
    // is appropriate here, unlike CPU-bound thread pools (tokio, SQLite) which
    // use P-core count.
    let http_workers = http_workers.unwrap_or_else(|| {
        let total = std::thread::available_parallelism().map_or(1, usize::from);
        info!("http_workers not configured; defaulting to total core count ({total})");
        total
    });
    if http_workers == 0 {
        return Err(KmsError::InvalidRequest(
            "http_workers must be greater than 0; actix-web panics on 0 workers".to_owned(),
        ));
    }
    info!("KMS HTTP server configured with {http_workers} worker thread(s)");
    let server = server.workers(http_workers);

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
    let tls_config = TlsConfig {
        #[cfg(feature = "non-fips")]
        p12: server_config.p12.as_ref(),
        cipher_suites: server_config.cipher_suites.as_deref(),
        server_cert_pem: &server_config.server_cert_pem,
        server_key_pem: &server_config.server_key_pem,
        server_chain_pem: server_config.server_chain_pem.as_deref(),
        client_ca_cert_pem: server_config.clients_ca_cert_pem.as_deref(),
    };

    let mut builder = create_base_openssl_acceptor(&tls_config, "http server")?;

    // Configure client certificate verification if specified
    if let Some(ca_cert_pem) = &server_config.clients_ca_cert_pem {
        configure_client_cert_verification(&mut builder, ca_cert_pem, "http server")?;
    }

    Ok(builder)
}

/// Validate that every JWKS URI in `uris` uses the `https` scheme.
///
/// Prevents the KMS from starting with an HTTP JWKS endpoint, which would expose
/// JWT public-key material to interception and allow MITM-based algorithm confusion.
///
/// This check is compiled out by the `insecure` feature flag so that integration
/// tests can point the server at a local HTTP mock JWKS server.
#[cfg(not(feature = "insecure"))]
fn validate_jwks_uris_are_https(uris: &[String]) -> KResult<()> {
    for uri in uris {
        let scheme = url::Url::parse(uri)
            .map(|u| u.scheme().to_owned())
            .unwrap_or_default();
        if scheme != "https" {
            return Err(KmsError::ServerError(format!(
                "JWKS URI must use HTTPS scheme to protect JWT public-key material, \
                 got: {uri:?}. Use the `insecure` feature flag to bypass this check \
                 in non-production environments."
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::expect_used)]
#[allow(clippy::assertions_on_result_states)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_key_deterministic() {
        // Load the appropriate provider if available
        #[cfg(not(feature = "non-fips"))]
        {
            drop(openssl::provider::Provider::load(None, "fips"));
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
        let key4 =
            derive_session_key_from_url(url1, "different_salt").expect("Failed to derive key 4");
        let key4_bytes = key4.master();

        assert_ne!(
            key1_bytes, key4_bytes,
            "Different salts should generate different keys"
        );

        // Verify key length is 64 bytes
        assert_eq!(key1_bytes.len(), 64, "Key should be 64 bytes");
    }

    #[test]
    fn test_derive_session_key_determinism() {
        // Load the appropriate provider if available
        #[cfg(not(feature = "non-fips"))]
        {
            drop(openssl::provider::Provider::load(None, "fips"));
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

    // ── J1–J4: JWKS HTTPS URI validation (compiled out in `insecure` builds) ─
    #[cfg(not(feature = "insecure"))]
    mod jwks_https_guard {
        use super::*;

        /// J1: A plain HTTP JWKS URI must be rejected at startup.
        #[test]
        fn j01_http_uri_is_rejected() {
            let uris = vec!["http://idp.example.com/.well-known/jwks.json".to_owned()];
            let result = validate_jwks_uris_are_https(&uris);
            assert!(result.is_err(), "HTTP JWKS URI must be rejected");
            let msg = result
                .expect_err("HTTP JWKS URI must be rejected")
                .to_string();
            assert!(
                msg.contains("HTTPS") || msg.contains("https"),
                "Error message must mention HTTPS, got: {msg}"
            );
        }

        /// J2: A valid HTTPS JWKS URI must be accepted.
        #[test]
        fn j02_https_uri_is_accepted() {
            let uris = vec!["https://idp.example.com/.well-known/jwks.json".to_owned()];
            assert!(
                validate_jwks_uris_are_https(&uris).is_ok(),
                "HTTPS JWKS URI must be accepted"
            );
        }

        /// J3: Empty URI list is always valid (no JWT auth configured).
        #[test]
        fn j03_empty_list_is_ok() {
            assert!(
                validate_jwks_uris_are_https(&[]).is_ok(),
                "Empty URI list must be accepted"
            );
        }

        /// J4: A mixed list (one HTTPS, one HTTP) must be rejected and the bad URI named.
        #[test]
        fn j04_mixed_list_rejects_http_uri() {
            let uris = vec![
                "https://good.example.com/jwks".to_owned(),
                "http://bad.example.com/jwks".to_owned(),
            ];
            let result = validate_jwks_uris_are_https(&uris);
            assert!(
                result.is_err(),
                "List containing an HTTP URI must be rejected"
            );
            let msg = result
                .expect_err("List containing an HTTP URI must be rejected")
                .to_string();
            assert!(
                msg.contains("bad.example.com"),
                "Error message must identify the offending URI, got: {msg}"
            );
        }
    }
}
