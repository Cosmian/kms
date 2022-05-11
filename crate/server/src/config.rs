#[cfg(all(not(feature = "dev"), not(test)))]
use std::env;
#[cfg(all(not(feature = "dev"), not(test)))]
use std::fs;
use std::path::{Path, PathBuf};

use alcoholic_jwt::JWKS;
use eyre::Context;
use once_cell::sync::OnceCell;
use tracing::{debug, info};

use crate::core::certbot::Certbot;
#[cfg(all(not(feature = "dev"), not(test)))]
use crate::error::KmsError;

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

    #[serde(default = "default_user_cert_path")]
    pub user_cert_path: String,

    // For test/dev environment only. Unused in staging/prod.
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_root_dir")]
    pub root_dir: String,

    // For test/dev environment only. Unused in staging/prod.
    #[serde(default = "default_hostname")]
    pub hostname: String,

    // For staging/prod environment only. Unused in test/dev.
    #[serde(default = "default_email")]
    pub email: String,

    // For staging/prod environment only. Unused in test/dev.
    #[serde(default = "default_days_threshold_before_renew")]
    pub days_threshold_before_renew: i64,

    // For staging/prod environment only. Unused in test/dev.
    #[serde(default = "default_keys_path")]
    pub keys_path: String,

    // For staging/prod environment only. Unused in test/dev.
    #[serde(default = "default_http_root_path")]
    pub http_root_path: String,

    // For staging/prod environment only. Unused in test/dev.
    #[serde(default = "default_domain_name")]
    pub domain_name: String,
}

#[cfg(any(feature = "dev", test))]
impl Default for Config {
    fn default() -> Self {
        Config {
            delegated_authority_domain: std::option_env!("KMS_DELEGATED_AUTHORITY_DOMAIN")
                .map(|v| v.to_string()),
            postgres_url: default_postgres_url(),
            mysql_url: default_mysql_url(),
            user_cert_path: std::option_env!("KMS_USER_CERT_PATH")
                .map_or(default_user_cert_path(), |p| p.to_string()),
            port: default_port(),
            root_dir: default_root_dir(),
            hostname: default_hostname(),
            email: default_email(),
            days_threshold_before_renew: default_days_threshold_before_renew(),
            keys_path: default_keys_path(),
            http_root_path: default_http_root_path(),
            domain_name: default_domain_name(),
        }
    }
}

fn default_domain_name() -> String {
    String::from("")
}

fn default_email() -> String {
    String::from("")
}

fn default_days_threshold_before_renew() -> i64 {
    15
}

fn default_keys_path() -> String {
    String::from(".")
}

fn default_http_root_path() -> String {
    String::from("/var/www/html/")
}

fn default_postgres_url() -> String {
    String::from("")
}

fn default_mysql_url() -> String {
    String::from("")
}

fn default_user_cert_path() -> String {
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
    Mysql(String, PathBuf),
}

#[derive(Clone, Debug)]
pub struct SharedConfig {
    pub delegated_authority_domain: Option<String>,
    pub jwks: Option<JWKS>,
    pub db_params: DbParams,
    pub hostname: String,
    pub port: u16,
    pub certbot: Option<Certbot>,
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

#[inline(always)]
pub(crate) fn certbot() -> Option<Certbot> {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .certbot
        .clone()
}

pub async fn init_config(conf: &Config) -> eyre::Result<()> {
    let delegated_authority_domain: Option<String> = conf
        .delegated_authority_domain
        .to_owned()
        .map(|d| d.trim_end_matches('/').to_string());

    let jwks = if let Some(dad) = &delegated_authority_domain {
        let jwks_uri = format!("https://{dad}/.well-known/jwks.json");
        Some(
            reqwest::get(jwks_uri)
                .await
                .with_context(|| "Unable to connect to retrieve JWKS")?
                .json::<JWKS>()
                .await
                .with_context(|| "Unable to get JWKS as a JSON")?,
        )
    } else {
        None
    };

    if !conf.postgres_url.is_empty() && !conf.mysql_url.is_empty() {
        eyre::bail!("Postgres and MariaDB/MySQL URL are both set, can't decide which one to use");
    }

    let db_params = if !conf.postgres_url.is_empty() {
        DbParams::Postgres(conf.postgres_url.to_owned())
    } else if !conf.mysql_url.is_empty() {
        DbParams::Mysql(
            conf.mysql_url.to_owned(),
            PathBuf::from(&conf.user_cert_path),
        )
    } else {
        DbParams::Sqlite(Path::new(&conf.root_dir).canonicalize()?.join("kms.db"))
    };

    #[cfg(any(feature = "dev", test))]
    let certbot = None;

    #[cfg(all(not(feature = "dev"), not(test)))]
    let certbot =
        {
            let path = env::current_dir()?;

            if conf.email == default_email() {
                eyre::bail!("Email can't be empty in staging/production environment");
            }
            if conf.domain_name == default_domain_name() {
                eyre::bail!("Domain name can't be empty in staging/production environment");
            }
            if conf.days_threshold_before_renew <= 1 {
                eyre::bail!("The 'days_threshold_before_renew' should be larger than 1 day");
            }

            let keys_path =
                if Path::new(&conf.keys_path).is_absolute() {
                    conf.keys_path.to_owned()
                } else {
                    String::from(path.join(&conf.keys_path).to_str().ok_or_else(|| {
                        KmsError::ServerError("Can't manage `keys_path`".to_owned())
                    })?)
                };

            if !Path::new(&keys_path).exists() {
                eyre::bail!("Can't find '{}' as keys_path", conf.keys_path);
            }

            let http_root_path = if Path::new(&conf.http_root_path).is_absolute() {
                conf.http_root_path.to_owned()
            } else {
                String::from(path.join(&conf.http_root_path).to_str().ok_or_else(|| {
                    KmsError::ServerError("Can't manage `http_root_path`".to_owned())
                })?)
            };

            if !Path::new(&http_root_path).exists() {
                info!("Creating {http_root_path}...");
                fs::create_dir_all(&http_root_path)?;
            }

            Some(Certbot::new(
                conf.days_threshold_before_renew,
                conf.email.clone(),
                conf.domain_name.clone(),
                http_root_path,
                keys_path,
            ))
        };

    let shared_conf = SharedConfig {
        jwks,
        delegated_authority_domain,
        db_params,
        hostname: conf.hostname.to_owned(),
        port: conf.port,
        certbot,
    };
    debug!("shared conf: {shared_conf:#?}");

    init(shared_conf);

    info!("initialising with configuration: {conf:#?}");
    Ok(())
}
