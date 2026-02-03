use std::{collections::HashMap, fmt, path::PathBuf, str::FromStr, time::Duration};

use cosmian_kms_server_database::{
    MainDbParams, reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType,
};
use cosmian_logger::{debug, warn};

use super::{KmipPolicyParams, TlsParams};
use crate::{
    config::{
        AzureEkmConfig,ClapConfig, GoogleCseConfig, IdpConfig, OidcConfig,
        params::{
            OpenTelemetryConfig, kmip_policy_params::KmipAllowlistsParams,
            proxy_params::ProxyParams,
        },
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// This structure is the context used by the server
/// while it is running. There is a singleton instance
/// shared between all threads.
#[derive(Default)]
pub struct ServerParams {
    /// The JWT Config if Auth is enabled
    pub identity_provider_configurations: Option<Vec<IdpConfig>>,

    /// The UI distribution folder
    pub ui_index_html_folder: PathBuf,

    /// A secret salt used to derive the session cookie encryption key.
    /// This MUST be identical across all KMS instances behind the same load balancer.
    /// This is mandatory only if the UI is configured.
    pub ui_session_salt: Option<String>,

    /// The OIDC config used to handle login from the UI
    pub ui_oidc_auth: OidcConfig,

    /// The Google CSE config
    pub google_cse: GoogleCseConfig,

    /// The username to use if no authentication method is provided
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    pub force_default_username: bool,

    /// The DB parameters may be supplied on the command line
    pub main_db_params: Option<MainDbParams>,

    /// Whether to clear the database on start
    pub clear_db_on_start: bool,

    /// The maximum age of unwrapped objects in the cache
    pub unwrapped_cache_max_age: Duration,

    /// Whether the socket server should be started
    pub start_socket_server: bool,

    /// The socket server hostname
    pub socket_server_hostname: String,

    /// The socket server port
    pub socket_server_port: u16,

    /// The TLS parameters of the server
    pub tls_params: Option<TlsParams>,

    /// The (forward) proxy parameters, if any
    pub proxy_params: Option<ProxyParams>,

    /// The exposed URL of the KMS - this is required if Google CSE configuration is activated.
    /// If this server is running on the domain `cse.my_domain.com` with this public URL,
    /// The configured URL from Google admin  should be something like <https://cse.my_domain.com/google_cse>
    pub kms_public_url: Option<String>,

    /// The hostname of the HTTP server
    pub http_hostname: String,

    /// The port of the HTTP server
    pub http_port: u16,

    /// The API authentication token is used on both the server and client sides
    pub api_token_id: Option<String>,

    /// This setting enables the Microsoft Double Key Encryption service feature of this server.
    ///
    /// It should contain the external URL of this server as configured in
    /// App Registrations of Azure as the DKE Service.
    /// Check this link: <https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store>
    ///
    /// The URL should be something like <https://cse.my_domain.com/ms_dke>
    pub ms_dke_service_url: Option<String>,

    /// The username of the HSM admin.
    /// The HSM admin can create objects on the HSM.
    pub hsm_admin: String,

    /// The HSM model, if any
    pub hsm_model: Option<String>,

    /// HSM slot passwords number
    pub slot_passwords: HashMap<usize, Option<String>>,

    /// The Key Wrapping Key, if any
    pub key_wrapping_key: Option<String>,

    /// Specifies which KMIP object types should be automatically unwrapped when retrieved
    ///
    /// Each entry must be a KMIP `ObjectType`, for example:
    /// `[ObjectType::SecretData, ObjectType::SymmetricKey]`.
    ///
    /// If `None`, no automatic unwrapping will be performed.
    pub default_unwrap_types: Option<Vec<ObjectType>>,

    /// Open Telemetry configuration
    pub otel_params: Option<OpenTelemetryConfig>,

    /// The non-revocable key ID used for demo purposes
    pub non_revocable_key_id: Option<Vec<String>>,

    /// Users who have initial rights to create and grant access rights for Create Kmip Operation
    /// If None, all users can create and grant create access rights.
    pub privileged_users: Option<Vec<String>>,

    /// KMIP algorithm policy.
    pub kmip_policy: KmipPolicyParams,

    pub azure_ekm: AzureEkmConfig,
}

/// Represents the server parameters.
impl ServerParams {
    /// Tries to create a `ServerParams` instance from `ClapConfig`.
    ///
    /// # Arguments
    ///
    /// * `conf` - The `ClapConfig` object containing the configuration parameters.
    ///
    /// # Returns
    ///
    /// Returns a `KResult` containing the `ServerParams` instance if successful, or an error if the conversion fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion from `ClapConfig` to `ServerParams` fails.
    pub fn try_from(conf: ClapConfig) -> KResult<Self> {
        debug!("{conf:#?}");

        #[cfg(target_os = "windows")]
        let mut ui_index_html_folder: PathBuf = conf.ui_config.get_ui_index_html_folder().into();
        #[cfg(not(target_os = "windows"))]
        let ui_index_html_folder: PathBuf = conf.ui_config.get_ui_index_html_folder().into();
        debug!("{ui_index_html_folder:#?}");

        // On Windows, some configs may still carry the Linux default path. Fallback to LOCALAPPDATA default.
        #[cfg(target_os = "windows")]
        {
            use crate::config::get_default_ui_dist_path;
            if ui_index_html_folder.to_string_lossy() == "/usr/local/cosmian/ui/dist/"
                || !ui_index_html_folder.join("index.html").exists()
            {
                let fallback = PathBuf::from(get_default_ui_dist_path());
                if fallback.join("index.html").exists() {
                    warn!(
                        "UI folder invalid or Linux default detected, falling back to: {fallback:#?}"
                    );
                    ui_index_html_folder = fallback;
                }
            }
        }

        if ui_index_html_folder.join("index.html").exists() {
            debug!("{ui_index_html_folder:#?}");
        } else {
            warn!(
                "The UI index HTML folder does not contain an index.html file: \
                 {ui_index_html_folder:#?}"
            );
        }

        // Validate session_salt: it should only be provided when ui_index_html_folder is explicitly defined
        if conf.ui_config.ui_session_salt.is_some() && conf.ui_config.ui_index_html_folder.is_none()
        {
            return Err(KmsError::ServerError(
                "ui_session_salt should only be provided when ui_index_html_folder is configured. \
                 Please either provide --ui-index-html-folder or remove --session-salt."
                    .to_owned(),
            ));
        }

        let tls_params = TlsParams::try_from(&conf.tls).context("failed to create TLS params")?;

        let slot_passwords: HashMap<usize, Option<String>> = conf
            .hsm
            .hsm_slot
            .iter()
            .zip(&conf.hsm.hsm_password)
            .map(|(s, p)| {
                let password = if p == "<NO_LOGIN>" {
                    None
                } else {
                    Some(p.clone())
                };
                (*s, password)
            })
            .collect();

        let kmip_policy_id: Option<String> = conf
            .kmip_policy
            .policy_id
            .as_deref()
            .map(|raw| {
                let normalized = raw.trim().to_ascii_uppercase();
                if normalized == "DEFAULT" || normalized == "CUSTOM" {
                    Ok(normalized)
                } else {
                    Err(KmsError::ServerError(format!(
                        "Invalid kmip.policy_id: '{raw}'. Valid values are: DEFAULT, CUSTOM",
                    )))
                }
            })
            .transpose()?;

        // Invalid values are rejected above when building `kmip_policy_id`.
        let kmip_allowlists = if kmip_policy_id.as_deref() == Some("DEFAULT") {
            crate::config::KmipAllowlistsConfig::default()
        } else {
            conf.kmip_policy.allowlists
        };

        let res = Self {
            identity_provider_configurations: {
                // Try the new IdpAuthConfig first, then fall back to the deprecated JwtAuthConfig
                conf.idp_auth
                    .extract_idp_configs()
                    .context("failed initializing IdPs from idp_auth")?
            },
            ui_index_html_folder,
            ui_oidc_auth: conf.ui_config.ui_oidc_auth,
            main_db_params: Some(
                conf.db
                    .init(&conf.workspace.init().context("failed to init workspace")?)
                    .context("failed to init DB")?,
            ),
            clear_db_on_start: conf.db.clear_database,
            unwrapped_cache_max_age: if conf.db.unwrapped_cache_max_age == 0 {
                return Err(KmsError::NotSupported(
                    "unwrapped_cache_max_age must be greater than 0".to_owned(),
                ));
            } else {
                Duration::from_secs(conf.db.unwrapped_cache_max_age * 60)
            },
            start_socket_server: conf.socket_server.socket_server_start,
            socket_server_hostname: conf.socket_server.socket_server_hostname,
            socket_server_port: conf.socket_server.socket_server_port,
            http_hostname: conf.http.hostname,
            http_port: conf.http.port,
            tls_params,
            kms_public_url: conf.kms_public_url,
            default_username: conf.default_username,
            force_default_username: conf.force_default_username,
            api_token_id: conf.http.api_token_id,
            google_cse: conf.google_cse_config,
            ms_dke_service_url: conf.ms_dke_service_url,
            hsm_admin: conf.hsm.hsm_admin,
            hsm_model: if slot_passwords.is_empty() {
                None
            } else {
                Some(conf.hsm.hsm_model)
            },
            slot_passwords,
            key_wrapping_key: conf.key_encryption_key,
            default_unwrap_types: conf
                .default_unwrap_type
                .map(|types| {
                    // Check if "All" is specified
                    if types.iter().any(|s| s.eq_ignore_ascii_case("All")) {
                        Ok(vec![
                            ObjectType::Certificate,
                            ObjectType::CertificateRequest,
                            ObjectType::OpaqueObject,
                            ObjectType::PGPKey,
                            ObjectType::PrivateKey,
                            ObjectType::PublicKey,
                            ObjectType::SecretData,
                            ObjectType::SplitKey,
                            ObjectType::SymmetricKey,
                        ])
                    } else {
                        types
                            .into_iter()
                            .map(|s| {
                                ObjectType::from_str(&s).map_err(|e| {
                                    KmsError::ServerError(format!(
                                        "Invalid ObjectType: '{s}'. Valid values are: All, \
                                         Certificate, CertificateRequest, OpaqueObject, PGPKey, \
                                         PrivateKey, PublicKey, SecretData, SplitKey, \
                                         SymmetricKey. Error: {e}"
                                    ))
                                })
                            })
                            .collect::<Result<Vec<ObjectType>, KmsError>>()
                    }
                })
                .transpose()?,
            otel_params: if conf.logging.otlp.is_some()
                || conf.logging.enable_metering
                || conf.logging.environment.is_some()
            {
                Some(OpenTelemetryConfig {
                    otlp_url: conf.logging.otlp,
                    enable_metering: conf.logging.enable_metering,
                    environment: conf.logging.environment,
                })
            } else {
                None
            },
            non_revocable_key_id: conf.non_revocable_key_id,
            privileged_users: conf.privileged_users,
            ui_session_salt: conf.ui_config.ui_session_salt,
            proxy_params: ProxyParams::try_from(&conf.proxy)
                .context("failed to create ProxyParams")?,
            kmip_policy: KmipPolicyParams {
                policy_id: kmip_policy_id,
                allowlists: KmipAllowlistsParams {
                    algorithms: kmip_allowlists.algorithms,
                    hashes: kmip_allowlists.hashes,
                    signature_algorithms: kmip_allowlists.signature_algorithms,
                    curves: kmip_allowlists.curves,
                    block_cipher_modes: kmip_allowlists.block_cipher_modes,
                    padding_methods: kmip_allowlists.padding_methods,
                    mgf_hashes: kmip_allowlists.mgf_hashes,
                    mask_generators: kmip_allowlists.mask_generators,
                    rsa_key_sizes: kmip_allowlists.rsa_key_sizes,
                    aes_key_sizes: kmip_allowlists.aes_key_sizes,
                },
            },
            azure_ekm: conf.azure_ekm_config,
        };
        debug!("{res:#?}");

        Ok(res)
    }
}
impl fmt::Debug for ServerParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("ServerParams");

        // Add optional fields only if they are Some
        if let Some(ref idp_configs) = self.identity_provider_configurations {
            debug_struct.field("identity_provider_configurations", idp_configs);
        }

        // Always show these non-optional fields
        debug_struct
            .field("default_username", &self.default_username)
            .field("force_default_username", &self.force_default_username);

        if let Some(ref db_params) = self.main_db_params {
            debug_struct.field("main_db_params", db_params);
        }

        debug_struct
            .field("clear_db_on_start", &self.clear_db_on_start)
            .field("unwrapped_cache_max_age", &self.unwrapped_cache_max_age);

        if let Some(ref otel_params) = self.otel_params {
            debug_struct.field("otel_params", otel_params);
        }

        if let Some(ref key_id) = self.non_revocable_key_id {
            debug_struct.field("non_revocable_key_id", key_id);
        }

        if let Some(ref unwrap_types) = self.default_unwrap_types {
            debug_struct.field("default_unwrap_types", unwrap_types);
        }

        debug_struct.field("kmip_policy_id", &self.kmip_policy.policy_id);
        if let Some(ref wl) = self.kmip_policy.allowlists.algorithms {
            debug_struct.field("kmip_allowed_algorithms", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.hashes {
            debug_struct.field("kmip_allowed_hashes", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.signature_algorithms {
            debug_struct.field("kmip_allowed_signature_algorithms", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.curves {
            debug_struct.field("kmip_allowed_curves", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.block_cipher_modes {
            debug_struct.field("kmip_allowed_block_cipher_modes", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.padding_methods {
            debug_struct.field("kmip_allowed_padding_methods", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.mgf_hashes {
            debug_struct.field("kmip_allowed_mgf_hashes", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.rsa_key_sizes {
            debug_struct.field("kmip_allowed_rsa_key_sizes", wl);
        }
        if let Some(ref wl) = self.kmip_policy.allowlists.aes_key_sizes {
            debug_struct.field("kmip_allowed_aes_key_sizes", wl);
        }

        if self.start_socket_server {
            debug_struct
                .field("socket_server_hostname", &self.socket_server_hostname)
                .field("socket_server_port", &self.socket_server_port);
        } else {
            debug_struct.field("socket_server", &"disabled");
        }

        if let Some(ref tls) = self.tls_params {
            debug_struct.field("tls_params", tls);
        }

        if let Some(ref token) = self.api_token_id {
            debug_struct.field("api_token_id", token);
        }

        if let Some(ref dke_url) = self.ms_dke_service_url {
            debug_struct.field("ms_dke_service_url", dke_url);
        }

        if self.google_cse.google_cse_enable {
            debug_struct
                .field("google_cse_enable", &self.google_cse.google_cse_enable)
                .field(
                    "google_cse_disable_tokens_validation",
                    &self.google_cse.google_cse_disable_tokens_validation,
                )
                .field(
                    "google_cse_incoming_url_whitelist",
                    &self.google_cse.google_cse_incoming_url_whitelist,
                )
                .field(
                    "google_cse_migration_key",
                    &self.google_cse.google_cse_migration_key,
                );
        } else {
            debug_struct.field("google_cse_enable", &self.google_cse.google_cse_enable);
        }

        // Azure EKM configuration
        if self.azure_ekm.azure_ekm_enable {
            debug_struct
                .field("azure_ekm_enable", &self.azure_ekm.azure_ekm_enable)
                .field(
                    "azure_ekm_path_prefix",
                    &self.azure_ekm.azure_ekm_path_prefix,
                )
                .field(
                    "azure_ekm_disable_client_auth",
                    &self.azure_ekm.azure_ekm_disable_client_auth,
                )
                .field(
                    "azure_ekm_proxy_vendor",
                    &self.azure_ekm.azure_ekm_proxy_vendor,
                )
                .field("azure_ekm_proxy_name", &self.azure_ekm.azure_ekm_proxy_name)
                .field("azure_ekm_ekm_vendor", &self.azure_ekm.azure_ekm_ekm_vendor)
                .field(
                    "azure_ekm_ekm_product",
                    &self.azure_ekm.azure_ekm_ekm_product,
                );
        } else {
            debug_struct.field("azure_ekm_enable", &self.azure_ekm.azure_ekm_enable);
        }

        if self.hsm_model.is_some() {
            debug_struct
                .field("hsm_admin", &self.hsm_admin)
                .field("hsm_model", &self.hsm_model);
            // Display slot passwords: mask actual passwords, show slot index
            for (slot, password) in &self.slot_passwords {
                let masked = if password.is_some() {
                    "***"
                } else {
                    "<NO_LOGIN>"
                };
                debug_struct.field(&format!("hsm_slot_{slot}"), &masked);
            }
        } else {
            debug_struct.field("hsm_model", &"no HSM configured");
        }

        if let Some(ref key) = self.key_wrapping_key {
            debug_struct.field("key_wrapping_key", key);
        }

        if let Some(ref proxy) = self.proxy_params {
            debug_struct.field("proxy_params", proxy);
        }

        if let Some(ref public_url) = self.kms_public_url {
            debug_struct.field("kms_public_url", public_url);
        }

        debug_struct.field(
            "kms_url",
            &format!(
                "http{}://{}:{}",
                if self.tls_params.is_some() { "s" } else { "" },
                &self.http_hostname,
                &self.http_port
            ),
        );

        if let Some(ref users) = self.privileged_users {
            debug_struct.field("privileged_users", users);
        }

        // Mask the session salt for security (it's a secret)
        if self.ui_session_salt.is_some() {
            debug_struct.field("ui_session_salt", &"***");
        }

        // if one of these UI fields is some, add debug information
        if self.ui_oidc_auth.ui_oidc_client_id.is_some()
            || self.ui_oidc_auth.ui_oidc_client_secret.is_some()
            || self.ui_oidc_auth.ui_oidc_issuer_url.is_some()
            || self.ui_oidc_auth.ui_oidc_logout_url.is_some()
        {
            debug_struct.field("ui_oidc_auth", &self.ui_oidc_auth);
        }

        debug_struct.field("ui_index_html_folder", &self.ui_index_html_folder);

        debug_struct.finish()
    }
}
