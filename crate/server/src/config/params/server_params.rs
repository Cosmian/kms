use std::{collections::HashMap, fmt, path::PathBuf, str::FromStr, time::Duration};

use cosmian_kms_server_database::{
    MainDbParams, reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType,
};
use cosmian_logger::{debug, warn};

use super::{KmipPolicyParams, TlsParams};
use crate::{
    config::{
        AzureEkmConfig, ClapConfig, GoogleCseConfig, IdpConfig, JwksEndpointConfig, OidcConfig,
        params::{
            OpenTelemetryConfig, kmip_policy_params::KmipAllowlistsParams,
            proxy_params::ProxyParams,
        },
    },
    error::KmsError,
    result::{KResult, KResultHelper},
    routes::aws_xks::AwsXksParams,
};

/// Resolved parameters for a single HSM instance, derived from either
/// the CLI `--hsm-*` flags (single instance) or a TOML `[[hsm]]` entry.
#[derive(Clone, Debug)]
pub struct HsmInstanceParams {
    /// HSM model string (e.g. `"softhsm2"`, `"utimaco"`).
    pub model: String,
    /// KMS usernames with admin access to this HSM instance.
    pub admin: Vec<String>,
    /// Slot-number → optional PIN mapping passed to `BaseHsm::instantiate`.
    pub slot_passwords: HashMap<usize, Option<String>>,
    /// Routing prefix for object UIDs managed by this instance.
    /// Format: `"hsm::<model>"` (e.g. `"hsm::softhsm2"`, `"hsm::utimaco"`).
    pub prefix: String,
}

/// This structure is the context used by the server
/// while it is running. There is a singleton instance
/// shared between all threads.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerParams {
    /// The JWT Config if Auth is enabled
    pub identity_provider_configurations: Option<Vec<IdpConfig>>,

    /// The UI distribution folder
    pub ui_index_html_folder: PathBuf,

    /// Whether the embedded web UI is enabled
    pub ui_enable: bool,

    /// A secret salt used to derive the session cookie encryption key.
    /// This MUST be identical across all KMS instances behind the same load balancer.
    /// This is mandatory only if the UI is configured.
    pub ui_session_salt: Option<String>,

    /// The OIDC config used to handle login from the UI
    pub ui_oidc_auth: OidcConfig,

    /// The Google CSE config
    pub google_cse: GoogleCseConfig,

    /// The vendor identification string reported in KMIP `QueryServerInformation` responses
    pub vendor_identification: String,

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

    /// The maximum number of entries in the unwrapped key cache
    pub unwrapped_cache_max_size: usize,

    /// Absolute time-to-live for unwrapped cache entries (`None` = no ceiling)
    pub unwrapped_cache_max_ttl: Option<Duration>,

    /// When `true`, the unwrapped cache is bypassed: every unwrap is performed live
    pub disable_unwrapped_cache: bool,

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

    /// Configured HSM instances (zero, one, or many).
    /// Index 0 uses prefix `"hsm"`, index N uses prefix `"hsmN"` (N ≥ 1).
    pub hsm_instances: Vec<HsmInstanceParams>,

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

    /// AWS XKS parameters, if any
    pub aws_xks_params: Option<AwsXksParams>,

    /// KMIP algorithm policy.
    pub kmip_policy: KmipPolicyParams,

    pub azure_ekm: AzureEkmConfig,

    /// Steady-state requests per second allowed per source IP address.
    /// Burst is set to 3× this value. `None` disables rate limiting (default for tests and
    /// embedded deployments; production should set this to a positive value such as 100).
    pub rate_limit_per_second: Option<u32>,

    /// Number of actix-web HTTP worker threads. `None` means actix-web default
    /// (uses `std::thread::available_parallelism`).
    pub http_workers: Option<usize>,

    /// Extra origins allowed to make cross-origin requests to the KMIP API.
    /// Empty in production (same-origin only). Set to `["http://127.0.0.1:5173"]` in
    /// UI E2E tests where the Vite dev server runs on a different port.
    pub cors_allowed_origins: Vec<String>,

    /// Maximum number of objects returned by a single Locate operation.
    /// Client-supplied `MaximumItems` is clamped to this value; when absent the cap is
    /// applied automatically. Prevents unbounded DB queries and large response payloads.
    pub max_locate_items: u32,

    /// Interval in seconds between background auto-rotation checks.
    /// 0 means disabled.
    pub auto_rotation_check_interval_secs: u64,

    /// Depth at which a successful keyset chain decryption triggers a warning.
    /// Keyset chain traversal is unbounded (stopped only by cycle detection); this
    /// threshold lets operators know when a ciphertext required walking many
    /// generations to decrypt — a hint that re-encryption with the latest key may
    /// be beneficial.
    pub keyset_warn_depth: u32,

    /// Configuration for the `GET /.well-known/jwks.json` public-key-discovery endpoint.
    pub jwks_endpoint: JwksEndpointConfig,

    // ── Vault-compatible API ──────────────────────────────────────────────────
    /// When `true`, the Vault-compatible `/v1/transit/` and `/v1/<pki_mount>/` scopes
    /// are registered at startup.  Defaults to `false`.
    pub vault_api_enabled: bool,

    /// Base URL of the auth-verifier server used for token validation.
    ///
    /// Required when `vault_api_enabled = true`.
    /// Example: `"https://auth.example.com"`
    pub vault_auth_verifier_url: Option<url::Url>,

    /// Path to a PEM-encoded CA certificate for verifying the auth-verifier's TLS cert.
    ///
    /// When set, the reqwest client used by `vault_token_middleware` will trust this CA.
    pub vault_auth_verifier_ca_cert: Option<std::path::PathBuf>,

    /// When `true`, TLS certificate verification is disabled for auth-verifier connections.
    ///
    /// **Security warning**: only use in test/dev environments.
    pub vault_auth_verifier_accept_invalid_certs: bool,

    /// Vault transit mount name.  Defaults to `"transit"`.
    /// Transit keys are served at `/v1/<vault_transit_mount>/keys/<name>`.
    pub vault_transit_mount: String,

    /// Vault PKI mount name.  Defaults to `"pki"`.
    /// PKI sign-intermediate is served at `/v1/<vault_pki_mount>/root/sign-intermediate`.
    pub vault_pki_mount: String,

    /// KMIP Label of the KMS key to use as the intermediate CA signing key.
    /// The key must already exist in the KMS (create it with `ckms ec create` or similar).
    pub vault_pki_ca_key_label: String,

    /// Lifetime of vault token validation cache entries in seconds.
    /// The KMS caches successful `lookup-self` responses for this duration
    /// to avoid a round-trip to auth-verifier on every transit/PKI request.
    /// Defaults to `30`.
    pub vault_token_cache_ttl_secs: u64,
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

        let hsm_instances = build_hsm_instances(&conf);

        let (kmip_policy_id, kmip_allowlists) = parse_kmip_policy(&conf)?;

        let cors_scheme = if conf.tls.is_tls_enabled() {
            "https"
        } else {
            "http"
        };

        let res = Self {
            identity_provider_configurations: {
                // Try the new IdpAuthConfig first, then fall back to the deprecated JwtAuthConfig
                conf.idp_auth
                    .extract_idp_configs()
                    .context("failed initializing IdPs from idp_auth")?
            },
            ui_index_html_folder,
            ui_enable: conf.ui_config.enable,
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
            unwrapped_cache_max_size: if conf.db.unwrapped_cache_max_size == 0 {
                return Err(KmsError::NotSupported(
                    "unwrapped_cache_max_size must be greater than 0".to_owned(),
                ));
            } else {
                conf.db.unwrapped_cache_max_size
            },
            unwrapped_cache_max_ttl: match conf.db.unwrapped_cache_max_ttl {
                None => None,
                Some(0) => {
                    return Err(KmsError::NotSupported(
                        "unwrapped_cache_max_ttl must be greater than 0 when set".to_owned(),
                    ));
                }
                Some(ttl_min) => {
                    let ttl = Duration::from_secs(ttl_min * 60);
                    let tti = Duration::from_secs(conf.db.unwrapped_cache_max_age * 60);
                    if ttl < tti {
                        return Err(KmsError::NotSupported(
                            "unwrapped_cache_max_ttl must be >= unwrapped_cache_max_age".to_owned(),
                        ));
                    }
                    Some(ttl)
                }
            },
            disable_unwrapped_cache: conf.db.disable_unwrapped_cache,
            start_socket_server: conf.socket_server.socket_server_start,
            socket_server_hostname: conf.socket_server.socket_server_hostname,
            socket_server_port: conf.socket_server.socket_server_port,
            http_hostname: conf.http.hostname,
            http_port: conf.http.port,
            tls_params,
            kms_public_url: conf.kms_public_url,
            vendor_identification: conf.vendor_identification,
            default_username: conf.default_username,
            force_default_username: conf.force_default_username,
            api_token_id: conf.http.api_token_id,
            google_cse: conf.google_cse_config,
            ms_dke_service_url: conf.ms_dke_service_url,
            hsm_instances,
            key_wrapping_key: conf.key_encryption_key,
            default_unwrap_types: parse_default_unwrap_types(conf.default_unwrap_type)?,
            otel_params: if conf.logging.otlp.is_some()
                || conf.logging.enable_metering
                || conf.logging.environment.is_some()
            {
                Some(OpenTelemetryConfig {
                    otlp_url: conf.logging.otlp,
                    otlp_allow_insecure: conf.logging.otlp_allow_insecure,
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
            aws_xks_params: if conf.aws_xks_config.aws_xks_enable {
                Some(conf.aws_xks_config.try_into()?)
            } else {
                None
            },
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
            // Use the value from the HTTP config; None means rate limiting is disabled.
            // Set KMS_RATE_LIMIT_PER_SECOND or `rate_limit_per_second` in the config file
            // to enable rate limiting in production deployments.
            rate_limit_per_second: conf.http.rate_limit_per_second,
            http_workers: conf.http.http_workers,
            cors_allowed_origins: conf.http.cors_allowed_origins.unwrap_or_else(|| {
                crate::config::default_cors_origins(cors_scheme, conf.http.port)
            }),
            max_locate_items: 1000,
            auto_rotation_check_interval_secs: {
                let v = conf.auto_rotation_check_interval_secs;
                // 0 means disabled; any non-zero value must be at least 60 seconds to avoid
                // hammering the database with high-frequency key-rotation scans.
                if v > 0 && v < 60 {
                    return Err(KmsError::ServerError(format!(
                        "auto_rotation_check_interval_secs must be 0 (disabled) or at least 60 \
                         seconds; {v} is too small and would cause excessive database churn"
                    )));
                }
                v
            },
            keyset_warn_depth: conf.keyset_warn_depth,
            jwks_endpoint: conf.jwks_endpoint,
            // Vault-compatible API — opt-in via config file or CLI flags.
            vault_api_enabled: conf.vault.vault_api_enabled,
            vault_auth_verifier_url: conf
                .vault
                .vault_auth_verifier_url
                .as_deref()
                .map(url::Url::parse)
                .transpose()
                .map_err(|e| {
                    KmsError::InvalidRequest(format!("invalid vault_auth_verifier_url: {e}"))
                })?,
            vault_auth_verifier_ca_cert: conf
                .vault
                .vault_auth_verifier_ca_cert
                .map(std::path::PathBuf::from),
            vault_auth_verifier_accept_invalid_certs: conf
                .vault
                .vault_auth_verifier_accept_invalid_certs,
            vault_transit_mount: conf.vault.vault_transit_mount,
            vault_pki_mount: conf.vault.vault_pki_mount,
            vault_pki_ca_key_label: conf.vault.vault_pki_ca_key_label,
            vault_token_cache_ttl_secs: conf.vault.vault_token_cache_ttl_secs,
        };

        debug!("{res:#?}");

        Ok(res)
    }
}

/// Build the list of `HsmInstanceParams` from the CLI configuration.
///
/// Merges the legacy flat HSM config (prefix `"hsm"`) with the new TOML
/// `[[hsm]]` array (prefix `"hsm::<model>"`), disambiguating duplicate model
/// names with a numeric suffix.
fn build_hsm_instances(conf: &ClapConfig) -> Vec<HsmInstanceParams> {
    let mut instances = Vec::new();

    // Legacy flat config → prefix "hsm" (old UID format: hsm::<slot>::<key>)
    if !conf.hsm.hsm_slot.is_empty() {
        instances.push(HsmInstanceParams {
            model: conf.hsm.hsm_model.clone(),
            admin: conf.hsm.hsm_admin.clone(),
            slot_passwords: conf.hsm.slot_passwords(),
            prefix: "hsm".to_owned(),
        });
    }

    // New TOML array → prefix "hsm::<model>" (new UID format: hsm::<model>::<slot>::<key>)
    let mut model_counts: HashMap<String, usize> = HashMap::new();
    for inst in conf.hsm_instances.iter().filter(|i| !i.hsm_slot.is_empty()) {
        let model_lower = inst.hsm_model.to_lowercase();
        let count = model_counts.entry(model_lower.clone()).or_insert(0);
        let prefix = if *count == 0 {
            format!("hsm::{model_lower}")
        } else {
            format!("hsm::{model_lower}_{count}")
        };
        *count += 1;
        instances.push(HsmInstanceParams {
            model: inst.hsm_model.clone(),
            admin: inst.hsm_admin.clone(),
            slot_passwords: inst.slot_passwords(),
            prefix,
        });
    }

    instances
}

/// Validate and normalise the KMIP policy ID, then return the corresponding allowlists.
///
/// Returns `(policy_id, allowlists)`.
fn parse_kmip_policy(
    conf: &ClapConfig,
) -> KResult<(Option<String>, crate::config::KmipAllowlistsConfig)> {
    let policy_id: Option<String> = conf
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

    // DEFAULT enforces the conservative allowlist; any other value uses the configured one.
    let allowlists = if policy_id.as_deref() == Some("DEFAULT") {
        crate::config::KmipAllowlistsConfig::conservative()
    } else {
        conf.kmip_policy.allowlists.clone()
    };

    Ok((policy_id, allowlists))
}

/// Parse the `--default-unwrap-type` CLI list into a typed `Vec<ObjectType>`.
///
/// Accepts the special value `"All"` (case-insensitive) to mean every object type.
fn parse_default_unwrap_types(types: Option<Vec<String>>) -> KResult<Option<Vec<ObjectType>>> {
    types
        .map(|ts| {
            if ts.iter().any(|s| s.eq_ignore_ascii_case("All")) {
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
                ts.into_iter()
                    .map(|s| {
                        ObjectType::from_str(&s).map_err(|e| {
                            KmsError::ServerError(format!(
                                "Invalid ObjectType: '{s}'. Valid values are: All, Certificate, \
                                 CertificateRequest, OpaqueObject, PGPKey, PrivateKey, PublicKey, \
                                 SecretData, SplitKey, SymmetricKey. Error: {e}"
                            ))
                        })
                    })
                    .collect()
            }
        })
        .transpose()
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
            .field("force_default_username", &self.force_default_username)
            .field("vendor_identification", &self.vendor_identification);

        if let Some(ref db_params) = self.main_db_params {
            debug_struct.field("main_db_params", db_params);
        }

        debug_struct
            .field("clear_db_on_start", &self.clear_db_on_start)
            .field("unwrapped_cache_max_age", &self.unwrapped_cache_max_age)
            .field("unwrapped_cache_max_size", &self.unwrapped_cache_max_size)
            .field("unwrapped_cache_max_ttl", &self.unwrapped_cache_max_ttl)
            .field("disable_unwrapped_cache", &self.disable_unwrapped_cache);

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
        if self.kmip_policy.policy_id.is_none() {
            debug_struct.field(
                "kmip_algorithm_policy",
                &"no restrictions — all supported algorithms are allowed",
            );
        } else {
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

        if self.api_token_id.is_some() {
            debug_struct.field("api_token_id", &self.api_token_id);
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
                    &self
                        .google_cse
                        .google_cse_migration_key
                        .as_ref()
                        .map(|_| "[PEM key provided]"),
                );
        } else {
            debug_struct.field("google_cse_enable", &self.google_cse.google_cse_enable);
        }

        if let Some(aws_xks_params) = &self.aws_xks_params {
            debug_struct
                .field("aws_xks_params", &"configured")
                .field("aws_xks_region", &aws_xks_params.region)
                .field("aws_xks_service", &aws_xks_params.service)
                .field(
                    "aws_xks_sigv4_access_key_id",
                    &aws_xks_params.sigv4_access_key_id,
                );
        } else {
            debug_struct.field("aws_xks_params", &"not configured");
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

        if self.hsm_instances.is_empty() {
            debug_struct.field("hsm_instances", &"no HSM configured");
        } else {
            for inst in &self.hsm_instances {
                debug_struct
                    .field(&format!("[{}] model", inst.prefix), &inst.model)
                    .field(&format!("[{}] admin", inst.prefix), &inst.admin);
                for (slot, password) in &inst.slot_passwords {
                    let masked = if password.is_some() {
                        "***"
                    } else {
                        "<NO_LOGIN>"
                    };
                    debug_struct.field(&format!("[{}] slot_{slot}", inst.prefix), &masked);
                }
            }
        }

        if self.key_wrapping_key.is_some() {
            debug_struct.field("key_wrapping_key", &"[configured]");
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
                self.http_hostname,
                self.http_port
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
        debug_struct.field("ui_enable", &self.ui_enable);
        debug_struct.field("rate_limit_per_second", &self.rate_limit_per_second);
        debug_struct.field("http_workers", &self.http_workers);
        debug_struct.field("cors_allowed_origins", &self.cors_allowed_origins);
        debug_struct.field("max_locate_items", &self.max_locate_items);
        debug_struct.field(
            "auto_rotation_check_interval_secs",
            &self.auto_rotation_check_interval_secs,
        );
        debug_struct.field("keyset_warn_depth", &self.keyset_warn_depth);
        if self.jwks_endpoint.jwks_endpoint_enabled {
            debug_struct
                .field(
                    "jwks_endpoint_enabled",
                    &self.jwks_endpoint.jwks_endpoint_enabled,
                )
                .field(
                    "jwks_endpoint_max_keys",
                    &self.jwks_endpoint.jwks_endpoint_max_keys,
                )
                .field(
                    "jwks_endpoint_auto_tag",
                    &self.jwks_endpoint.jwks_endpoint_auto_tag,
                );
        } else {
            debug_struct.field(
                "jwks_endpoint_enabled",
                &self.jwks_endpoint.jwks_endpoint_enabled,
            );
        }

        // Vault API fields
        debug_struct.field("vault_api_enabled", &self.vault_api_enabled);
        if self.vault_api_enabled {
            debug_struct
                .field("vault_auth_verifier_url", &self.vault_auth_verifier_url)
                .field(
                    "vault_auth_verifier_ca_cert",
                    &self.vault_auth_verifier_ca_cert,
                )
                .field(
                    "vault_auth_verifier_accept_invalid_certs",
                    &self.vault_auth_verifier_accept_invalid_certs,
                )
                .field("vault_transit_mount", &self.vault_transit_mount)
                .field("vault_pki_mount", &self.vault_pki_mount)
                .field("vault_pki_ca_key_label", &self.vault_pki_ca_key_label)
                .field(
                    "vault_token_cache_ttl_secs",
                    &self.vault_token_cache_ttl_secs,
                );
        }

        debug_struct.finish()
    }
}
