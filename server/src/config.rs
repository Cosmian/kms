use std::path::{Path, PathBuf};

use alcoholic_jwt::JWKS;
use once_cell::sync::OnceCell;
use tracing::{debug, info};

use crate::{kms_bail, kms_error, result::KResult};

static INSTANCE_CONFIG: OnceCell<SharedConfig> = OnceCell::new();

#[twelf::config]
#[derive(Debug)]
pub struct Config {
    /// Delegated authority domain coming from auth0
    pub delegated_authority_domain: Option<String>,

    #[serde(default = "default_postgres_url")]
    pub postgres_url: String,

    #[serde(default = "default_mysql_url")]
    pub mysql_url: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_root_dir")]
    pub root_dir: String,

    #[serde(default = "default_hostname")]
    pub hostname: String,
}

/// A default implementation to use in tests
#[cfg(test)]
impl Default for Config {
    fn default() -> Self {
        Config {
            delegated_authority_domain: std::option_env!("KMS_DELEGATED_AUTHORITY_DOMAIN")
                .map(|v| v.to_string()),
            postgres_url: "".to_string(),
            mysql_url: "".to_string(),
            port: 9998,
            root_dir: "/tmp".to_string(),
            hostname: "0.0.0.0".to_string(),
        }
    }
}

fn default_postgres_url() -> String {
    String::from("")
}

fn default_mysql_url() -> String {
    String::from("")
}

fn default_port() -> u16 {
    9998_u16
}

fn default_root_dir() -> String {
    String::from("/tmp")
}

fn default_hostname() -> String {
    String::from("0.0.0.0")
}

#[derive(Clone, Debug)]
pub enum DbParams {
    // contains the path to the db file
    Sqlite(PathBuf),
    // contain the postgres connection URL
    Postgres(String),
    // contain the mysql connection URL
    Mysql(String),
}

#[derive(Clone, Debug)]
pub struct SharedConfig {
    pub delegated_authority_domain: Option<String>,
    pub jwks: Option<JWKS>,
    pub db_params: DbParams,
    pub hostname: String,
    pub port: u16,
}

pub(crate) fn init(conf: SharedConfig) {
    let _ = INSTANCE_CONFIG.set(conf);
}

#[inline(always)]
pub(crate) fn delegated_authority_domain() -> Option<String> {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .delegated_authority_domain
        .clone()
}

#[inline(always)]
pub(crate) fn jwks() -> Option<JWKS> {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .jwks
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
pub(crate) fn hostname() -> String {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .hostname
        .clone()
}

#[inline(always)]
pub(crate) fn port() -> u16 {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .port
}

pub async fn init_config(conf: &Config) -> KResult<()> {
    let delegated_authority_domain: Option<String> = conf
        .delegated_authority_domain
        .to_owned()
        .map(|d| d.trim_end_matches('/').to_string());

    let jwks = if let Some(dad) = &delegated_authority_domain {
        let jwks_uri = format!("https://{dad}/.well-known/jwks.json");
        Some(
            reqwest::get(jwks_uri)
                .await
                .map_err(|e| kms_error!("Unable to connect to retrieve JWKS: {:?}", e))?
                .json::<JWKS>()
                .await
                .map_err(|e| kms_error!("Unable to get JWKS as a JSON: {:?}", e))?,
        )
    } else {
        None
    };

    if !conf.postgres_url.is_empty() && !conf.mysql_url.is_empty() {
        kms_bail!("Postgres and MariaDB/MySQL URL are both set, can't decide which one to use");
    }

    let db_params = if !conf.postgres_url.is_empty() {
        DbParams::Postgres(conf.postgres_url.to_owned())
    } else if !conf.mysql_url.is_empty() {
        DbParams::Mysql(conf.mysql_url.to_owned())
    } else {
        DbParams::Sqlite(Path::new(&conf.root_dir).canonicalize()?.join("kms.db"))
    };

    let shared_conf = SharedConfig {
        jwks,
        delegated_authority_domain,
        db_params,
        hostname: conf.hostname.to_owned(),
        port: conf.port,
    };
    debug!("shared conf: {shared_conf:#?}");

    init(shared_conf);

    info!("initialising with configuration: {conf:#?}");
    Ok(())
}
