pub mod auth0;
mod certbot_https;
pub mod db;
mod enclave;
pub mod http;
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
use openssl::pkcs12::ParsedPkcs12_2;
use tracing::{debug, info};

use crate::{
    config::{
        auth0::Auth0Config, certbot_https::HttpsCertbotConfig, db::DBConfig,
        enclave::EnclaveConfig, http::HTTPConfig, workspace::WorkspaceConfig,
    },
    core::certbot::Certbot,
    result::KResult,
};

static INSTANCE_CONFIG: OnceCell<SharedConfig> = OnceCell::new();

#[derive(Parser, Default)]
#[clap(version, about, long_about = None)]
pub struct Config {
    #[clap(flatten)]
    pub auth0: Auth0Config,

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
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("Config");
        let x = x.field("db", &self.db);
        let x = if self.auth0.auth0_authority_domain.is_some() {
            x.field("auth0", &self.auth0)
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
    // The security domain if Auth0 is enabled
    pub auth0_authority_domain: Option<String>,

    // The JWKS if Auth0 is enabled
    pub jwks: Option<JWKS>,

    /// The username if Auth0 is disabled
    pub default_username: Option<String>,

    pub db_params: DbParams,

    pub hostname_port: String,

    /// The provided PKCS#12 when HTTPS is enabled
    pub server_pkcs_12: Option<ParsedPkcs12_2>,

    /// The certbot engine if certbot is enabled
    pub certbot: Option<Arc<Mutex<Certbot>>>,

    /// The enclave parameters when running inside an enclave
    pub enclave_params: EnclaveParams,
}

impl fmt::Debug for SharedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("SharedConfig");
        let x = x
            .field("kms_url", &self.hostname_port)
            .field("db_params", &self.db_params);
        let x = if let Some(authority_domain) = &self.auth0_authority_domain {
            x.field("auth0_authority_domain", &authority_domain)
                .field("jwks", &self.jwks)
        } else {
            x.field("default_username", &self.default_username)
        };
        let x = if let Some(ParsedPkcs12_2 {
            cert: Some(x509), ..
        }) = &self.server_pkcs_12
        {
            x.field("certificate CN", &x509.subject_name())
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

pub(crate) fn init(conf: SharedConfig) {
    let _ = INSTANCE_CONFIG.set(conf);
}

impl SharedConfig {
    #[inline(always)]
    pub(crate) fn auth0_authority_domain() -> Option<String> {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .auth0_authority_domain
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
    pub(crate) fn default_username() -> Option<String> {
        INSTANCE_CONFIG
            .get()
            .expect("config must be initialized")
            .default_username
            .clone()
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
}

pub async fn init_config(conf: &Config) -> KResult<()> {
    info!("initializing with configuration: {conf:#?}");

    let workspace = conf.workspace.init()?;

    let (hostname_port, server_pkcs_12) = conf.http.init()?;

    let shared_conf = SharedConfig {
        jwks: conf.auth0.init().await?,
        auth0_authority_domain: conf.auth0.auth0_authority_domain.clone(),
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
        default_username: match conf.auth0.auth0_authority_domain {
            Some(_) => None,
            None => Some("admin".to_string()),
        },
        server_pkcs_12,
    };

    debug!("generated shared conf: {shared_conf:#?}");

    init(shared_conf);

    Ok(())
}
