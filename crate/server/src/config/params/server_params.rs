use std::{
    fmt::{self},
    sync::{Arc, Mutex},
};

use alcoholic_jwt::JWKS;
use libsgx::utils::is_running_inside_enclave;
use openssl::{pkcs12::ParsedPkcs12_2, x509::X509};

use super::{BootstrapServerParams, DbParams, EnclaveParams};
use crate::{
    config::{
        clap::{HttpsCertbotConfig, JWEConfig},
        ClapConfig,
    },
    core::certbot::Certbot,
    result::KResult,
};

/// This structure is the context used by the server
/// while it is running. There is a singleton instance
/// shared between all threads.
pub struct ServerParams {
    // The JWT issuer URI if Auth is enabled
    pub jwt_issuer_uri: Option<String>,

    // The JWKS if Auth is enabled
    pub jwks: Option<JWKS>,

    pub jwe_config: JWEConfig,

    /// The JWT audience if Auth is enabled
    pub jwt_audience: Option<String>,

    /// The username to use if no authentication method is provided
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    pub force_default_username: bool,

    /// The DB parameters may be supplied on the command line or via the bootstrap server
    pub db_params: Option<DbParams>,

    /// Whether to clear the database on start
    pub clear_db_on_start: bool,

    pub hostname: String,

    pub port: u16,

    /// The provided PKCS#12 when HTTPS is enabled
    pub server_pkcs_12: Option<ParsedPkcs12_2>,

    /// The certbot engine if certbot is enabled
    pub certbot: Option<Arc<Mutex<Certbot>>>,

    /// The enclave parameters when running inside an enclave
    pub enclave_params: EnclaveParams,

    /// The certificate used to verify the client TLS certificates
    /// used for authentication
    pub verify_cert: Option<X509>,

    /// Use a bootstrap server (inside an enclave for instance)
    pub bootstrap_server_config: BootstrapServerParams,
}

impl ServerParams {
    pub async fn try_from(conf: &ClapConfig) -> KResult<Self> {
        // Initialize the workspace
        let workspace = conf.workspace.init()?;

        // Initialize the HTTP server
        let (server_pkcs_12, verify_cert) = conf.http.init()?;

        let server_conf = Self {
            jwks: conf.auth.fetch_jwks().await?,
            jwt_issuer_uri: conf.auth.jwt_issuer_uri.clone(),
            jwe_config: conf.jwe.clone(),
            jwt_audience: conf.auth.jwt_audience.clone(),
            db_params: conf
                .db
                .init(&workspace, conf.bootstrap_server.use_bootstrap_server)?,
            clear_db_on_start: conf.db.clear_database,
            hostname: conf.http.hostname.clone(),
            port: conf.http.port,
            enclave_params: conf.enclave.init(&workspace)?,
            certbot: if conf.certbot_https.use_certbot {
                Some(Arc::new(Mutex::new(HttpsCertbotConfig::init(
                    &conf.certbot_https,
                    &workspace,
                )?)))
            } else {
                None
            },
            default_username: conf.default_username.clone(),
            force_default_username: conf.force_default_username,
            server_pkcs_12,
            verify_cert,
            bootstrap_server_config: conf.bootstrap_server.clone(),
        };
        Ok(server_conf)
    }
}

impl fmt::Debug for ServerParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
        let x = if self.bootstrap_server_config.use_bootstrap_server {
            x.field(
                "bootstrap server url",
                &format!(
                    "https://{}:{}",
                    &self.hostname, &self.bootstrap_server_config.bootstrap_server_port
                ),
            )
            .field(
                "bootstrap server CN",
                &self.bootstrap_server_config.bootstrap_server_common_name,
            )
        } else {
            &mut x
        };
        let x = x
            .field(
                "kms_url",
                &format!(
                    "http{}://{}:{}",
                    if self.server_pkcs_12.is_some() {
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
                .field("jwks", &self.jwks)
                .field("jwt_audience", &self.jwt_audience)
        } else {
            x
        };
        let x = if let Some(verify_cert) = &self.verify_cert {
            x.field("verify_cert CN", verify_cert.subject_name())
        } else {
            x
        };
        let x = x
            .field("default_username", &self.default_username)
            .field("force_default_username", &self.force_default_username);
        let x = if let Some(ParsedPkcs12_2 {
            cert: Some(x509), ..
        }) = &self.server_pkcs_12
        {
            x.field("server certificate CN", &x509.subject_name())
        } else {
            x
        };
        let x = if self.certbot.is_some() {
            x.field("certbot", &self.certbot)
        } else {
            x
        };
        let x = if is_running_inside_enclave() {
            x.field("enclave_params", &self.enclave_params)
        } else {
            x
        };
        x.finish()
    }
}

/// Creates a partial clone of the ServerConfig
/// the DbParams and PKCS#12 information is not copied
/// since it may contain sensitive material
impl Clone for ServerParams {
    fn clone(&self) -> Self {
        Self {
            jwt_issuer_uri: self.jwt_issuer_uri.clone(),
            jwks: self.jwks.clone(),
            jwe_config: self.jwe_config.clone(),
            jwt_audience: self.jwt_audience.clone(),
            default_username: self.default_username.clone(),
            force_default_username: self.force_default_username,
            db_params: None,
            clear_db_on_start: self.clear_db_on_start,
            hostname: self.hostname.clone(),
            port: self.port,
            server_pkcs_12: None,
            certbot: self.certbot.clone(),
            enclave_params: self.enclave_params.clone(),
            verify_cert: self.verify_cert.clone(),
            bootstrap_server_config: self.bootstrap_server_config.clone(),
        }
    }
}
