mod certbot_https;
pub mod db;
mod enclave;
pub mod http;
pub mod jwt_auth_config;
mod workspace;

use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use alcoholic_jwt::JWKS;
use clap::Parser;
use libsgx::utils::is_running_inside_enclave;
use once_cell::sync::OnceCell;
use openssl::{pkcs12::ParsedPkcs12_2, x509::X509};
use tracing::{debug, info};

use crate::{
    config::{
        certbot_https::HttpsCertbotConfig, db::DBConfig, enclave::EnclaveConfig, http::HTTPConfig,
        jwt_auth_config::JwtAuthConfig, workspace::WorkspaceConfig,
    },
    core::certbot::Certbot,
    result::KResult,
};

static INSTANCE_CONFIG: OnceCell<SharedConfig> = OnceCell::new();

#[derive(Parser, Default)]
#[clap(version, about, long_about = None)]
pub struct Config {
    #[clap(flatten)]
    pub auth: JwtAuthConfig,

    #[clap(flatten)]
    pub db: DBConfig,

    #[clap(flatten)]
    pub enclave: EnclaveConfig,

    #[clap(flatten)]
    pub certbot_https: HttpsCertbotConfig,

    #[clap(flatten)]
    pub http: HTTPConfig,

    #[clap(flatten)]
    pub workspace: WorkspaceConfig,

    /// The default username to use when no authentication method is provided
    #[clap(long, env = "KMS_DEFAULT_USERNAME", default_value = "admin")]
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    #[clap(long, env = "KMS_FORCE_DEFAULT_USERNAME", default_value = "false")]
    pub force_default_username: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("Config");
        let x = x.field("db", &self.db);
        let x = if self.auth.jwt_issuer_uri.is_some() {
            x.field("auth0", &self.auth)
        } else {
            x
        };
        let x = if is_running_inside_enclave() {
            x.field("enclave", &self.enclave)
        } else {
            x
        };
        let x = x.field("http", &self.http);
        let x = if self.certbot_https.use_certbot {
            x.field("certbot", &self.certbot_https)
        } else {
            x
        };
        let x = x.field("workspace", &self.workspace);
        x.finish()
    }
}

#[derive(Clone, Debug)]
pub enum DbParams {
    // contains the dir of the sqlite db file (not the db file itself)
    Sqlite(PathBuf),
    // contains the dir of the sqlcipher db file (not the db file itself)
    SqliteEnc(PathBuf),
    // contains the postgres connection URL
    Postgres(String),
    // contains the mysql connection URL
    Mysql(String),
}

#[derive(Clone, Debug)]
pub struct EnclaveParams {
    // contains the path to the manifest
    pub manifest_path: PathBuf,
    // contains the path to the signer public key
    pub public_key_path: PathBuf,
}

/// This structure is the context used by the server
/// while it is running. There is a singleton instance
/// shared between all threads.
pub struct SharedConfig {
    // The JWT issuer URI if Auth is enabled
    pub jwt_issuer_uri: Option<String>,

    // The JWKS if Auth is enabled
    pub jwks: Option<JWKS>,

    /// The JWT audience if Auth is enabled
    pub jwt_audience: Option<String>,

    /// The username to use if not authentication method is provided
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    pub force_default_username: bool,

    pub db_params: DbParams,

    pub hostname_port: String,

    /// The provided PKCS#12 when HTTPS is enabled
    pub server_pkcs_12: Option<ParsedPkcs12_2>,

    /// The certbot engine if certbot is enabled
    pub certbot: Option<Arc<Mutex<Certbot>>>,

    /// The enclave parameters when running inside an enclave
    pub enclave_params: EnclaveParams,

    /// The certificate used to verify the client TLS certificates
    /// used for authentication
    pub verify_cert: Option<X509>,
}

/// Initialize the configuration and set the singleton instance
pub async fn init_config(conf: &Config) -> KResult<()> {
    info!("initializing with configuration: {conf:#?}");

    let workspace = conf.workspace.init()?;

    let (hostname_port, server_pkcs_12, verify_cert) = conf.http.init()?;

    let shared_conf = SharedConfig {
        jwks: conf.auth.fetch_jwks().await?,
        jwt_issuer_uri: conf.auth.jwt_issuer_uri.clone(),
        jwt_audience: conf.auth.jwt_audience.clone(),
        db_params: conf.db.init(&workspace)?,
        hostname_port,
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
    };

    debug!("generated shared conf: {shared_conf:#?}");

    // Set the singleton instance that holds the SharedConfig
    let _ = INSTANCE_CONFIG.set(shared_conf);

    Ok(())
}

impl fmt::Debug for SharedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("SharedConfig");
        let x = x
            .field("kms_url", &self.hostname_port)
            .field("db_params", &self.db_params);
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

impl SharedConfig {
    #[inline(always)]
    pub(crate) fn jwt_issuer_uri() -> Option<String> {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .jwt_issuer_uri
            .clone()
    }

    #[inline(always)]
    pub(crate) fn jwks() -> Option<JWKS> {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .jwks
            .clone()
    }

    #[inline(always)]
    pub(crate) fn jwt_audience() -> Option<String> {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .jwt_audience
            .clone()
    }

    #[inline(always)]
    pub(crate) fn default_username() -> String {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .default_username
            .clone()
    }

    #[inline(always)]
    pub(crate) fn force_default_username() -> bool {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .force_default_username
    }

    #[inline(always)]
    pub(crate) fn db_params() -> DbParams {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .db_params
            .clone()
    }

    #[inline(always)]
    pub(crate) fn enclave_params() -> EnclaveParams {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .enclave_params
            .clone()
    }

    #[inline(always)]
    pub(crate) fn hostname_port() -> String {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .hostname_port
            .clone()
    }

    #[inline(always)]
    pub(crate) fn certbot() -> &'static Option<Arc<Mutex<Certbot>>> {
        &INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .certbot
    }

    #[inline(always)]
    pub(crate) fn server_pkcs12() -> &'static Option<ParsedPkcs12_2> {
        &INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .server_pkcs_12
    }

    #[inline(always)]
    pub(crate) fn verify_cert() -> &'static Option<X509> {
        &INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .verify_cert
    }
}
