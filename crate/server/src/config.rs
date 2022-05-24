#[cfg(all(not(feature = "dev"), not(test)))]
use std::fs;
use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use alcoholic_jwt::JWKS;
use eyre::Context;
use libsgx::utils::is_running_inside_enclave;
use once_cell::sync::OnceCell;
use tracing::{debug, info};

use crate::{core::certbot::Certbot, error::KmsError};

static INSTANCE_CONFIG: OnceCell<SharedConfig> = OnceCell::new();

#[twelf::config]
#[derive(Debug)]
pub struct Config {
    /// Delegated authority domain coming from auth0
    pub delegated_authority_domain: Option<String>,

    /// The url of the postgres database
    #[serde(default = "default_postgres_url")]
    pub postgres_url: String,

    /// The url of the mysql database
    #[serde(default = "default_mysql_url")]
    pub mysql_url: String,

    /// The path of the client certificate if key-file is the authentication method
    #[serde(default = "default_user_cert_path")]
    pub user_cert_path: String,

    /// The dir of the sqlite database
    #[serde(default = "default_root_dir")]
    pub root_dir: String,

    /// The server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// The server hostname
    #[serde(default = "default_hostname")]
    pub hostname: String,

    /// The email used during the HTTPS certification process
    pub email: Option<String>,

    /// The duration before the renew due date of the HTTPS cert
    #[serde(default = "default_days_threshold_before_renew")]
    pub days_threshold_before_renew: i64,

    /// The location to store the HTTPS certificate and keys
    pub keys_path: Option<PathBuf>,

    /// The root dir used by the HTTP server during the HTTPS certification process
    pub http_root_path: Option<PathBuf>,

    /// The domain name of the HTTPS server
    pub domain_name: Option<String>,

    /// The path of the sgx manifest
    pub manifest_path: Option<String>,
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
            email: None,
            days_threshold_before_renew: default_days_threshold_before_renew(),
            keys_path: None,
            http_root_path: None,
            domain_name: None,
            manifest_path: None,
        }
    }
}

fn default_days_threshold_before_renew() -> i64 {
    15
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

fn default_default_username() -> String {
    String::from("admin")
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
    pub certbot: Arc<Mutex<Certbot>>,
    pub manifest_path: Option<String>,
    /// The username if Auth0 is disabled
    pub default_username: String,
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
pub(crate) fn manifest_path() -> Option<String> {
    INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .manifest_path
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
pub(crate) fn certbot() -> &'static Arc<Mutex<Certbot>> {
    &INSTANCE_CONFIG
        .get()
        .expect("config must be initialised")
        .certbot
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
    let certbot = Certbot::default();

    let path = env::current_dir()?;

    #[cfg(all(not(feature = "dev"), not(test)))]
    let certbot = {
        let email = conf
            .email
            .to_owned()
            .ok_or_else(|| eyre::eyre!("Email can't be empty in staging/production environment"))?;

        let domain_name = conf.domain_name.to_owned().ok_or_else(|| {
            eyre::eyre!("Domain name can't be empty in staging/production environment")
        })?;

        if conf.days_threshold_before_renew <= 1 {
            eyre::bail!("The 'days_threshold_before_renew' should be larger than 1 day");
        }

        let keys_path = conf.keys_path.as_ref().ok_or_else(|| {
            eyre::eyre!("keys_path can't be empty in staging/production environment")
        })?;

        let keys_path = if keys_path.is_absolute() {
            keys_path.to_owned()
        } else {
            path.join(&keys_path)
        };

        if !Path::new(&keys_path).exists() {
            eyre::bail!("Can't find '{:?}' as keys_path", keys_path);
        }

        let http_root_path = conf.http_root_path.as_ref().ok_or_else(|| {
            eyre::eyre!("http_root_path can't be empty in staging/production environment")
        })?;

        let http_root_path = if http_root_path.is_absolute() {
            http_root_path.to_owned()
        } else {
            path.join(&http_root_path)
        };

        if !Path::new(&http_root_path).exists() {
            info!("Creating {:?}...", http_root_path);
            fs::create_dir_all(&http_root_path)?;
        }

        Certbot::new(
            conf.days_threshold_before_renew,
            email,
            domain_name,
            http_root_path,
            keys_path,
        )
    };

    let manifest_path = if is_running_inside_enclave() {
        let manifest_path = conf.manifest_path.clone().ok_or_else(|| {
            KmsError::ServerError(
                "`manifest_path` is mandatory when running inside the enclave".to_owned(),
            )
        })?;

        let manifest_path =
            if Path::new(&manifest_path).is_absolute() {
                manifest_path
            } else {
                String::from(path.join(&manifest_path).to_str().ok_or_else(|| {
                    KmsError::ServerError("Can't manage `manifest_path`".to_owned())
                })?)
            };

        if !Path::new(&manifest_path).exists() {
            eyre::bail!("Can't find '{}' as manifest_path", manifest_path);
        }

        Some(manifest_path)
    } else {
        None
    };

    let shared_conf = SharedConfig {
        jwks,
        delegated_authority_domain,
        db_params,
        hostname: conf.hostname.to_owned(),
        port: conf.port,
        manifest_path,
        certbot: Arc::new(Mutex::new(certbot)),
        default_username: default_default_username(),
    };
    debug!("shared conf: {shared_conf:#?}");

    init(shared_conf);

    info!("initialising with configuration: {conf:#?}");
    Ok(())
}
