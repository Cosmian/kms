mod certbot_https;
pub mod db;
mod enclave;
pub mod http;
pub mod jwe;
pub mod jwt_auth_config;
mod workspace;

use std::{
    fmt::{self, Display},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use alcoholic_jwt::JWKS;
use clap::Parser;
use cloudproof::reexport::crypto_core::SymmetricKey;
use libsgx::utils::is_running_inside_enclave;
use openssl::{pkcs12::ParsedPkcs12_2, x509::X509};
use tracing::info;

use crate::{
    config::{
        certbot_https::HttpsCertbotConfig, db::DBConfig, enclave::EnclaveConfig, http::HTTPConfig,
        jwe::JWEConfig, jwt_auth_config::JwtAuthConfig, workspace::WorkspaceConfig,
    },
    core::certbot::Certbot,
    database::redis::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
    result::KResult,
};

#[derive(Parser, Default)]
#[clap(version, about, long_about = None)]
pub struct ClapConfig {
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
    pub jwe: JWEConfig,

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

impl fmt::Debug for ClapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
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
        let x = x.field("default username", &self.default_username);
        let x = x.field("force default username", &self.force_default_username);
        x.finish()
    }
}

pub enum DbParams {
    /// contains the dir of the sqlite db file (not the db file itself)
    Sqlite(PathBuf),
    /// contains the dir of the sqlcipher db file (not the db file itself)
    SqliteEnc(PathBuf),
    /// contains the Postgres connection URL
    Postgres(String),
    /// contains the MySql connection URL
    Mysql(String),
    /// contains
    /// - the Redis connection URL
    /// - the master key used to encrypt the DB and the Index
    /// - a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the key
    RedisFindex(
        String,
        SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        Vec<u8>,
    ),
}

impl Display for DbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbParams::Sqlite(path) => write!(f, "sqlite: {}", path.display()),
            DbParams::SqliteEnc(path) => write!(f, "sqlcipher: {}", path.display()),
            DbParams::Postgres(url) => write!(f, "postgres: {url}"),
            DbParams::Mysql(url) => write!(f, "mysql: {url}"),
            DbParams::RedisFindex(url, _, label) => {
                write!(
                    f,
                    "redis-findex: {}, key: [****], label: 0x{}",
                    url,
                    hex::encode(label)
                )
            }
        }
    }
}

impl std::fmt::Debug for DbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
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
pub struct ServerConfig {
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

    pub db_params: DbParams,

    /// Whether to clear the database on start
    pub clear_db_on_start: bool,

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

impl ServerConfig {
    pub async fn try_from(conf: &ClapConfig) -> KResult<Self> {
        info!("initializing the server with user configuration: {conf:#?}");

        // Initialize the workspace
        let workspace = conf.workspace.init()?;

        // Initialize the HTTP server
        let (hostname_port, server_pkcs_12, verify_cert) = conf.http.init()?;

        let server_conf = Self {
            jwks: conf.auth.fetch_jwks().await?,
            jwt_issuer_uri: conf.auth.jwt_issuer_uri.clone(),
            jwe_config: conf.jwe.clone(),
            jwt_audience: conf.auth.jwt_audience.clone(),
            db_params: conf.db.init(&workspace)?,
            clear_db_on_start: conf.db.clear_database,
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

        info!("generated server conf: {server_conf:#?}");

        Ok(server_conf)
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
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
