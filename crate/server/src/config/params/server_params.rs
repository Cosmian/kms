use std::{collections::HashMap, fmt, path::PathBuf, time::Duration};

use cosmian_kms_server_database::MainDbParams;
use cosmian_logger::{debug, warn};

use super::TlsParams;
use crate::{
    config::{
        ClapConfig, DEFAULT_COSMIAN_UI_DIST_PATH, GoogleCseConfig, IdpConfig, OidcConfig,
        params::proxy_params::ProxyParams,
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
    /// Each entry must be the string name of a KMIP `ObjectType`, for example:
    /// `["SecretData", "SymmetricKey"]`.
    ///
    /// If `None`, no automatic unwrapping will be performed.
    pub default_unwrap_types: Option<Vec<String>>,

    /// The non-revocable key ID used for demo purposes
    pub non_revocable_key_id: Option<Vec<String>>,

    /// Users who have initial rights to create and grant access rights for Create Kmip Operation
    /// If None, all users can create and grant create access rights.
    pub privileged_users: Option<Vec<String>>,
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

        let ui_index_html_folder: PathBuf = if conf.ui_config.ui_index_html_folder.is_empty() {
            DEFAULT_COSMIAN_UI_DIST_PATH.to_owned()
        } else {
            conf.ui_config.ui_index_html_folder
        }
        .into();
        debug!("{ui_index_html_folder:#?}");
        if ui_index_html_folder.join("index.html").exists() {
            debug!("{ui_index_html_folder:#?}");
        } else {
            warn!(
                "The UI index HTML folder does not contain an index.html file: \
                 {ui_index_html_folder:#?}"
            );
        }

        let tls_params =
            TlsParams::try_from(&conf.tls, &conf.http).context("failed to create TLS params")?;

        let slot_passwords: HashMap<usize, Option<String>> = conf
            .hsm
            .hsm_slot
            .iter()
            .zip(&conf.hsm.hsm_password)
            .map(|(s, p)| {
                let password = if p.is_empty() { None } else { Some(p.clone()) };
                (*s, password)
            })
            .collect();

        let res = Self {
            identity_provider_configurations: {
                // Try the new IdpAuthConfig first, then fall back to the deprecated JwtAuthConfig
                if let Some(idp_configs) = conf
                    .idp_auth
                    .extract_idp_configs()
                    .context("failed initializing IdPs from idp_auth")?
                {
                    Some(idp_configs)
                } else {
                    conf.auth
                        .extract_idp_configs()
                        .context("failed initializing IdPs from auth")?
                }
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
            default_unwrap_types: conf.default_unwrap_type,
            non_revocable_key_id: conf.non_revocable_key_id,
            privileged_users: conf.privileged_users,
            proxy_params: ProxyParams::try_from(&conf.proxy)
                .context("failed to create ProxyParams")?,
        };
        debug!("{res:#?}");

        Ok(res)
    }
}

impl fmt::Debug for ServerParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("ServerParams");

        // Add all fields systematically
        debug_struct
            .field(
                "identity_provider_configurations",
                &self.identity_provider_configurations,
            )
            .field("default_username", &self.default_username)
            .field("force_default_username", &self.force_default_username)
            .field("main_db_params", &self.main_db_params)
            .field("clear_db_on_start", &self.clear_db_on_start)
            .field("unwrapped_cache_max_age", &self.unwrapped_cache_max_age)
            .field("non_revocable_key_id", &self.non_revocable_key_id)
            .field("default_unwrap_types", &self.default_unwrap_types);

        if self.start_socket_server {
            debug_struct
                .field("socket_server_hostname", &self.socket_server_hostname)
                .field("socket_server_port", &self.socket_server_port);
        } else {
            debug_struct.field("socket_server", &"disabled");
        }

        debug_struct
            .field("tls_params", &self.tls_params)
            .field("api_token_id", &self.api_token_id)
            .field("ms_dke_service_url", &self.ms_dke_service_url);
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
        if self.hsm_model.is_some() {
            debug_struct
                .field("hsm_admin", &self.hsm_admin)
                .field("hsm_model", &self.hsm_model);
        } else {
            debug_struct.field("hsm_model", &"no HSM configured");
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
        debug_struct.field("non_revocable_key_id", &self.non_revocable_key_id);
        debug_struct.field("privileged_users", &self.privileged_users);

        debug_struct.finish_non_exhaustive()
    }
}
