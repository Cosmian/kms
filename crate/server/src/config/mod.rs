pub mod auth;
mod db;
mod enclave;
mod http;
mod https;
mod workspace;

use std::{fmt, path::PathBuf};

#[cfg(feature = "auth")]
use alcoholic_jwt::JWKS;
use clap::Parser;
use once_cell::sync::OnceCell;
use tracing::{debug, info};
#[cfg(feature = "https")]
use {
    crate::core::certbot::Certbot,
    std::sync::{Arc, Mutex},
};

use crate::config::{
    auth::AuthConfig, db::DBConfig, enclave::EnclaveConfig, http::HTTPConfig, https::HTTPSConfig,
    workspace::WorkspaceConfig,
};

static INSTANCE_CONFIG: OnceCell<SharedConfig> = OnceCell::new();

#[derive(Parser, Default)]
#[clap(version, about, long_about = None)]
pub struct Config {
    #[cfg_attr(not(feature = "auth"), clap(skip))]
    #[cfg_attr(feature = "auth", clap(flatten))]
    pub auth: AuthConfig,

    #[clap(flatten)]
    pub db: DBConfig,

    #[cfg_attr(not(feature = "enclave"), clap(skip))]
    #[cfg_attr(feature = "enclave", clap(flatten))]
    pub enclave: EnclaveConfig,

    #[cfg_attr(not(feature = "https"), clap(skip))]
    #[cfg_attr(feature = "https", clap(flatten))]
    pub https: HTTPSConfig,

    #[cfg_attr(not(feature = "https"), clap(flatten))]
    #[cfg_attr(feature = "https", clap(skip))]
    pub http: HTTPConfig,

    #[cfg_attr(all(not(feature = "https"), not(feature = "enclave")), clap(skip))]
    #[cfg_attr(any(feature = "https", feature = "enclave"), clap(flatten))]
    pub workspace: WorkspaceConfig,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("Config");
        let x = x.field("db", &self.db);

        #[cfg(feature = "auth")]
        let x = x.field("auth", &self.auth);
        #[cfg(feature = "enclave")]
        let x = x.field("enclave", &self.enclave);
        #[cfg(not(feature = "https"))]
        let x = x.field("http", &self.http);
        #[cfg(feature = "https")]
        let x = x.field("https", &self.https);
        #[cfg(any(feature = "https", feature = "enclave"))]
        let x = x.field("workspace", &self.workspace);
        x.finish()
    }
}

#[derive(Clone, Debug)]
pub enum DbParams {
    // contains the path to the db file
    Sqlite(PathBuf),
    // contains the postgres connection URL
    Postgres(String),
    // contains the mysql connection URL
    Mysql(String, Option<PathBuf>),
}

#[derive(Clone, Debug)]
pub struct SharedConfig {
    #[cfg(feature = "auth")]
    pub delegated_authority_domain: String,

    #[cfg(feature = "auth")]
    pub jwks: JWKS,

    /// The username if Auth0 is disabled
    #[cfg(not(feature = "auth"))]
    pub default_username: String,

    pub db_params: DbParams,

    pub kms_url: String,

    #[cfg(feature = "https")]
    pub certbot: Arc<Mutex<Certbot>>,

    #[cfg(feature = "enclave")]
    pub manifest_path: PathBuf,
}

pub(crate) fn init(conf: SharedConfig) {
    let _ = INSTANCE_CONFIG.set(conf);
}

#[inline(always)]
#[cfg(feature = "auth")]
pub(crate) fn delegated_authority_domain() -> String {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .delegated_authority_domain
        .clone()
}

#[inline(always)]
#[cfg(feature = "auth")]
pub(crate) fn jwks() -> JWKS {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .jwks
        .clone()
}

#[inline(always)]
#[cfg(not(feature = "auth"))]
pub(crate) fn default_username() -> String {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .default_username
        .clone()
}

#[inline(always)]
pub(crate) fn db_params() -> DbParams {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .db_params
        .clone()
}

#[inline(always)]
#[cfg(feature = "enclave")]
pub(crate) fn manifest_path() -> PathBuf {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .manifest_path
        .clone()
}

#[inline(always)]
pub(crate) fn kms_url() -> String {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .kms_url
        .clone()
}

#[inline(always)]
#[cfg(feature = "https")]
pub(crate) fn certbot() -> &'static Arc<Mutex<Certbot>> {
    &INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .certbot
}

pub async fn init_config(conf: &Config) -> eyre::Result<()> {
    info!("initialising with configuration: {conf:#?}");

    #[cfg(any(feature = "https", feature = "enclave"))]
    let workspace = conf.workspace.init()?;

    // In case of HTTPS, we build the http_url by ourself
    let http_url = {
        #[cfg(not(feature = "https"))]
        {
            conf.http.clone()
        }
        #[cfg(feature = "https")]
        {
            HTTPConfig {
                hostname: String::from("0.0.0.0"),
                port: 443,
            }
        }
    };

    let shared_conf = SharedConfig {
        #[cfg(feature = "auth")]
        jwks: conf.auth.init().await?,
        #[cfg(feature = "auth")]
        delegated_authority_domain: conf.auth.delegated_authority_domain.to_owned(),
        db_params: conf.db.init()?,
        kms_url: http_url.init()?,
        #[cfg(feature = "enclave")]
        manifest_path: conf.enclave.init(&workspace)?,
        #[cfg(feature = "https")]
        certbot: Arc::new(Mutex::new(HTTPSConfig::init(&conf.https, &workspace)?)),
        #[cfg(not(feature = "auth"))]
        default_username: "admin".to_string(),
    };

    debug!("generated shared conf: {shared_conf:#?}");

    init(shared_conf);

    Ok(())
}
