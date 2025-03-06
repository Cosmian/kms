use std::{collections::HashMap, fmt, path::PathBuf};

use cosmian_kms_server_database::MainDbParams;
use openssl::x509::X509;

use super::HttpParams;
use crate::{
    config::{ClapConfig, IdpConfig, OidcConfig},
    kms_bail,
    result::KResult,
};

/// This structure is the context used by the server
/// while it is running. There is a singleton instance
/// shared between all threads.
pub struct ServerParams {
    /// The JWT Config if Auth is enabled
    pub identity_provider_configurations: Option<Vec<IdpConfig>>,

    /// The OIDC config used to handle login from UI
    pub ui_oidc_auth: OidcConfig,

    /// The username to use if no authentication method is provided
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    pub force_default_username: bool,

    /// The DB parameters may be supplied on the command line
    pub main_db_params: Option<MainDbParams>,

    /// Whether to clear the database on start
    pub clear_db_on_start: bool,

    pub hostname: String,

    pub port: u16,

    pub http_params: HttpParams,

    /// The certificate used to verify the client TLS certificates
    /// used for authentication
    pub authority_cert_file: Option<X509>,

    /// The API authentication token used both server and client side
    pub api_token_id: Option<String>,

    /// This setting enables the Google Workspace Client Side Encryption feature of this KMS server.
    ///
    /// It should contain the external URL of this server as configured in Google Workspace client side encryption settings
    /// For instance, if this server is running on domain `cse.my_domain.com`,
    /// the URL should be something like <https://cse.my_domain.com/google_cse>
    pub google_cse_kacls_url: Option<String>,

    /// This setting disables the validation of the tokens used by the Google Workspace CSE feature of this server.
    pub google_cse_disable_tokens_validation: bool,

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

    /// The non-revocable keys ID used for demo purposes
    pub non_revocable_key_id: Option<Vec<String>>,
}

/// Represents the server parameters.
impl ServerParams {
    /// Tries to create a `ServerParams` instance from the given `ClapConfig`.
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
        let http_params = HttpParams::try_from(&conf.http)?;

        // Should we verify the client TLS certificates?
        let authority_cert_file = conf
            .http
            .authority_cert_file
            .map(|cert_file| {
                if http_params.is_running_https() {
                    Self::load_cert(&cert_file)
                } else {
                    kms_bail!(
                        "The authority certificate file can only be used when the server is \
                         running in HTTPS mode"
                    )
                }
            })
            .transpose()?;

        let slot_passwords: HashMap<usize, Option<String>> = conf
            .hsm_slot
            .iter()
            .zip(&conf.hsm_password)
            .map(|(s, p)| {
                let password = if p.is_empty() {
                    None
                } else {
                    Some(p.to_string())
                };
                (*s, password)
            })
            .collect();

        Ok(Self {
            identity_provider_configurations: conf.auth.extract_idp_configs()?,
            ui_oidc_auth: conf.ui_oidc_auth,
            main_db_params: Some(conf.db.init(&conf.workspace.init()?)?),
            clear_db_on_start: conf.db.clear_database,
            hostname: conf.http.hostname,
            port: conf.http.port,
            http_params,
            default_username: conf.default_username,
            force_default_username: conf.force_default_username,
            authority_cert_file,
            api_token_id: conf.http.api_token_id,
            google_cse_disable_tokens_validation: conf.google_cse_disable_tokens_validation,
            google_cse_kacls_url: conf.google_cse_kacls_url,
            ms_dke_service_url: conf.ms_dke_service_url,
            hsm_admin: conf.hsm_admin,
            hsm_model: if slot_passwords.is_empty() {
                None
            } else {
                Some(conf.hsm_model)
            },
            slot_passwords,
            non_revocable_key_id: conf.non_revocable_key_id,
        })
    }

    /// Loads the certificate from the given file path.
    ///
    /// # Arguments
    ///
    /// * `authority_cert_file` - The path to the authority certificate file.
    ///
    /// # Returns
    ///
    /// Returns a `KResult` containing the loaded `X509` certificate if successful, or an error if the loading fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate file cannot be read or if the parsing of the certificate fails.
    fn load_cert(authority_cert_file: &PathBuf) -> KResult<X509> {
        // Open and read the file into a byte vector
        let pem_bytes = std::fs::read(authority_cert_file)?;

        // Parse the byte vector as a X509 object
        let x509 = X509::from_pem(pem_bytes.as_slice())?;
        Ok(x509)
    }
}

impl fmt::Debug for ServerParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
        let x = x
            .field(
                "kms_url",
                &format!(
                    "http{}://{}:{}",
                    if self.http_params.is_running_https() {
                        "s"
                    } else {
                        ""
                    },
                    &self.hostname,
                    &self.port
                ),
            )
            .field("db_params", &self.main_db_params)
            .field("clear_db_on_start", &self.clear_db_on_start);
        let x = if let Some(identity_provider_configurations) =
            &self.identity_provider_configurations
        {
            x.field(
                "identity_provider_configurations",
                &identity_provider_configurations,
            )
        } else {
            x
        };
        let x = x.field("ui_oidc_auth", &self.ui_oidc_auth);

        let x = if let Some(verify_cert) = &self.authority_cert_file {
            x.field("verify_cert CN", verify_cert.subject_name())
        } else {
            x
        };
        let x = x
            .field("default_username", &self.default_username)
            .field("force_default_username", &self.force_default_username);
        let x = x.field("http_params", &self.http_params);
        let x = x.field(
            "google_cse_disable_tokens_validation",
            &self.google_cse_disable_tokens_validation,
        );
        let x = if let Some(google_cse_kacls_url) = &self.google_cse_kacls_url {
            x.field("google_cse_kacls_url", &google_cse_kacls_url)
        } else {
            x
        };
        let x = x.field("ms_dke_service_url", &self.ms_dke_service_url);
        let x = x.field("api_token_id", &self.api_token_id);
        let x = x.field("HSM_username", &self.hsm_admin);
        let x = x.field(
            "hsm_model",
            if self.slot_passwords.is_empty() {
                &"NO HSM"
            } else {
                &self.hsm_model
            },
        );
        let x = x.field(
            "slot_passwords",
            &self
                .slot_passwords
                .iter()
                .map(|(s, p)| {
                    let p = if p.is_some() { "********" } else { "" };
                    format!("{s} -> {p}")
                })
                .collect::<Vec<String>>(),
        );
        let x = x.field("non_revocable_key_id", &self.non_revocable_key_id);
        x.finish()
    }
}

/// Creates a partial clone of the `ServerParams`
/// the `DbParams`, PKCS#12 information and Proteccio password are not copied
/// since it may contain sensitive material
impl Clone for ServerParams {
    fn clone(&self) -> Self {
        Self {
            identity_provider_configurations: self.identity_provider_configurations.clone(),
            ui_oidc_auth: self.ui_oidc_auth.clone(),
            default_username: self.default_username.clone(),
            force_default_username: self.force_default_username,
            main_db_params: None,
            clear_db_on_start: self.clear_db_on_start,
            hostname: self.hostname.clone(),
            port: self.port,
            http_params: HttpParams::Http,
            authority_cert_file: self.authority_cert_file.clone(),
            api_token_id: self.api_token_id.clone(),
            google_cse_disable_tokens_validation: self.google_cse_disable_tokens_validation,
            google_cse_kacls_url: self.google_cse_kacls_url.clone(),
            ms_dke_service_url: self.ms_dke_service_url.clone(),
            hsm_admin: self.hsm_admin.clone(),
            hsm_model: self.hsm_model.clone(),
            slot_passwords: self
                .slot_passwords
                .clone()
                .into_keys()
                .map(|s| (s, None))
                .collect(),
            non_revocable_key_id: self.non_revocable_key_id.clone(),
        }
    }
}
