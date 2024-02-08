use std::{fmt, fs::File, io::Read, path::PathBuf};

use openssl::x509::X509;

use super::{DbParams, HttpParams};
use crate::{
    config::{command_line::JWEConfig, ClapConfig},
    kms_bail,
    result::KResult,
};

/// This structure is the context used by the server
/// while it is running. There is a singleton instance
/// shared between all threads.
pub struct ServerParams {
    // The JWT issuer URI if Auth is enabled
    pub jwt_issuer_uri: Option<String>,

    // The JWKS URI if Auth is enabled
    pub jwks_uri: Option<String>,

    pub jwe_config: JWEConfig,

    /// The JWT audience if Auth is enabled
    pub jwt_audience: Option<String>,

    /// The username to use if no authentication method is provided
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    pub force_default_username: bool,

    /// The DB parameters may be supplied on the command line
    pub db_params: Option<DbParams>,

    /// Whether to clear the database on start
    pub clear_db_on_start: bool,

    pub hostname: String,

    pub port: u16,

    pub http_params: HttpParams,

    /// The certificate used to verify the client TLS certificates
    /// used for authentication
    pub client_cert: Option<X509>,

    /// This setting enables the Google Workspace Client Side Encryption feature of this KMS server.
    ///
    /// It should contain the external URL of this server as configured in Google Workspace client side encryption settings
    /// For instance, if this server is running on domain `cse.my_domain.com`,
    /// the URL should be something like <https://cse.my_domain.com/google_cse>
    pub google_cse_kacls_url: Option<String>,

    /// This setting enables the Microsoft Double Key Encryption service feature of this server.
    ///
    /// It should contain the external URL of this server as configured in
    /// App Registrations of Azure as the DKE Service.
    /// Check this link: https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store
    ///
    /// The URL should be something like <https://cse.my_domain.com/ms_dke>
    pub ms_dke_service_url: Option<String>,
}

impl ServerParams {
    pub async fn try_from(conf: &ClapConfig) -> KResult<Self> {
        // Initialize the workspace
        let workspace = conf.workspace.init()?;

        // The HTTP/HTTPS parameters
        let http_params = HttpParams::try_from(conf)?;

        // Should we verify the client TLS certificates?
        let verify_cert = if let Some(authority_cert_file) = &conf.http.authority_cert_file {
            if http_params.is_running_https() {
                Some(Self::load_cert(authority_cert_file)?)
            } else {
                kms_bail!(
                    "The authority certificate file can only be used when the server is running \
                     in HTTPS mode"
                )
            }
        } else {
            None
        };

        let server_conf = Self {
            jwks_uri: conf.auth.jwks_uri.clone(),
            jwt_issuer_uri: conf.auth.jwt_issuer_uri.clone(),
            jwe_config: conf.jwe.clone(),
            jwt_audience: conf.auth.jwt_audience.clone(),
            db_params: conf.db.init(&workspace)?,
            clear_db_on_start: conf.db.clear_database,
            hostname: conf.http.hostname.clone(),
            port: conf.http.port,
            http_params: HttpParams::try_from(conf)?,
            default_username: conf.default_username.clone(),
            force_default_username: conf.force_default_username,
            client_cert: verify_cert,
            google_cse_kacls_url: conf.google_cse_kacls_url.clone(),
            ms_dke_service_url: conf.ms_dke_service_url.clone(),
        };
        Ok(server_conf)
    }

    fn load_cert(authority_cert_file: &PathBuf) -> KResult<X509> {
        // Open and read the file into a byte vector
        let mut file = File::open(authority_cert_file)?;
        let mut pem_bytes = Vec::new();
        file.read_to_end(&mut pem_bytes)?;

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
            .field("db_params", &self.db_params)
            .field("clear_db_on_start", &self.clear_db_on_start);
        let x = if let Some(jwt_issuer_uri) = &self.jwt_issuer_uri {
            x.field("jwt_issuer_uri", &jwt_issuer_uri)
                .field("jwks_uri", &self.jwks_uri)
                .field("jwt_audience", &self.jwt_audience)
        } else {
            x
        };
        let x = if let Some(verify_cert) = &self.client_cert {
            x.field("verify_cert CN", verify_cert.subject_name())
        } else {
            x
        };
        let x = x
            .field("default_username", &self.default_username)
            .field("force_default_username", &self.force_default_username);
        let x = x.field("http_params", &self.http_params);
        let x = if let Some(google_cse_kacls_url) = &self.google_cse_kacls_url {
            x.field("google_cse_kacls_url", &google_cse_kacls_url)
        } else {
            x
        };
        let x = x.field("ms_dke_service_url", &self.ms_dke_service_url);
        x.finish()
    }
}

/// Creates a partial clone of the `ServerParams`
/// the `DbParams` and PKCS#12 information is not copied
/// since it may contain sensitive material
impl Clone for ServerParams {
    fn clone(&self) -> Self {
        Self {
            jwt_issuer_uri: self.jwt_issuer_uri.clone(),
            jwks_uri: self.jwks_uri.clone(),
            jwe_config: self.jwe_config.clone(),
            jwt_audience: self.jwt_audience.clone(),
            default_username: self.default_username.clone(),
            force_default_username: self.force_default_username,
            db_params: None,
            clear_db_on_start: self.clear_db_on_start,
            hostname: self.hostname.clone(),
            port: self.port,
            http_params: HttpParams::Http,
            client_cert: self.client_cert.clone(),
            google_cse_kacls_url: self.google_cse_kacls_url.clone(),
            ms_dke_service_url: self.ms_dke_service_url.clone(),
        }
    }
}
