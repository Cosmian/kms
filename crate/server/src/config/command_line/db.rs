use std::{fmt::Display, path::PathBuf};

use clap::Args;
use cosmian_kms_server_database::MainDbParams;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::redis_master_key_from_password;
use serde::{Deserialize, Serialize};
use url::Url;

use super::workspace::WorkspaceConfig;
use crate::{
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

pub const DEFAULT_SQLITE_PATH: &str = "./sqlite-data";

/// Configuration for the database
#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MainDBConfig {
    /// The main database of the KMS server that holds default cryptographic objects and permissions.
    /// - postgresql: `PostgreSQL`. The database URL must be provided
    /// - mysql: `MySql` or `MariaDB`. The database URL must be provided
    /// - sqlite: `SQLite`. The data will be stored at the `sqlite_path` directory
    ///   A key must be supplied on every call
    /// - redis-findex [non-FIPS]: a Redis database with encrypted data and indexes thanks to Findex.
    ///   The Redis URL must be provided, as well as the redis-master-password and the redis-findex-label
    #[clap(
        long,
        env("KMS_DATABASE_TYPE"),
        value_parser([
            "postgresql",
            "mysql",
            "sqlite",
            #[cfg(feature = "non-fips")]
            "redis-findex"
        ]),
        verbatim_doc_comment
    )]
    pub database_type: Option<String>,

    /// The URL of the database for `Postgres`, `MySQL`, or `Findex-Redis`
    #[clap(
        long,
        env = "KMS_DATABASE_URL",
        required_if_eq_any([
            ("database_type", "postgresql"),
            ("database_type", "mysql"),
            #[cfg(feature = "non-fips")]
            ("database_type", "redis-findex")
        ])
    )]
    pub database_url: Option<String>,

    /// The directory path of the `SQLite`
    #[clap(
        long,
        env = "KMS_SQLITE_PATH",
        default_value = DEFAULT_SQLITE_PATH,
        required_if_eq_any([("database_type", "sqlite")])
    )]
    pub sqlite_path: PathBuf,

    /// redis-findex: a master password used to encrypt the Redis data and indexes
    #[cfg(feature = "non-fips")]
    #[clap(
        long,
        env = "KMS_REDIS_MASTER_PASSWORD",
        required_if_eq("database_type", "redis-findex")
    )]
    pub redis_master_password: Option<String>,

    /// redis-findex: a public arbitrary label that can be changed to rotate the Findex ciphertexts
    /// without changing the key
    #[deprecated(
        since = "5.12.0",
        note = "!IMPORTANT if this KMS is launched with a non-empty Redis store that with \
                versions prior to 5.12.0, you MUST provide the same label as before, otherwise the \
                migration might fail and data can be forever lost. If you are launching a fresh \
                KMS with an empty Redis store, or one that was already used with version 5.12.0 or \
                later, you can safely discard this parameter."
    )]
    #[cfg(feature = "non-fips")]
    #[clap(long, env = "KMS_REDIS_FINDEX_LABEL")]
    pub redis_findex_label: Option<String>,

    /// Clear the database on start.
    /// WARNING: This will delete ALL the data in the database
    #[clap(long, env = "KMS_CLEAR_DATABASE", verbatim_doc_comment)]
    pub clear_database: bool,

    /// Maximum number of connections for the relational database pool.
    /// When not provided, falls back to the current defaults:
    /// - `PostgreSQL`/`MySQL`: min(10, 2 × CPU cores), fallback 10
    /// - `SQLite`: number of CPUs
    #[clap(long, env = "KMS_DB_MAX_CONNECTIONS")]
    pub max_connections: Option<u32>,

    /// When a wrapped object is fetched from the database,
    /// it is unwrapped and stored in the unwrapped cache.
    /// This option specifies the maximum age in minutes of the unwrapped objects in the cache
    /// after its last use.
    /// The default is 15 minutes.
    /// About 2/3 of the objects will be evicted after this time; the other 1/3 will be evicted
    /// after a maximum of 150% of the time.
    #[clap(
        long,
        env = "KMS_UNWRAPPED_CACHE_MAX_AGE",
        default_value = "15",
        verbatim_doc_comment
    )]
    pub unwrapped_cache_max_age: u64,
}

impl Default for MainDBConfig {
    fn default() -> Self {
        Self {
            sqlite_path: PathBuf::from(DEFAULT_SQLITE_PATH),
            database_type: None,
            database_url: None,
            clear_database: false,
            max_connections: None,
            unwrapped_cache_max_age: 15,
            #[cfg(feature = "non-fips")]
            redis_master_password: None,
            #[cfg(feature = "non-fips")]
            #[allow(deprecated)] // Label will still be accepted until all data is migrated
            redis_findex_label: None,
        }
    }
}

impl Display for MainDBConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(database_type) = &self.database_type {
            match database_type.as_str() {
                "postgresql" => write!(
                    f,
                    "postgresql: {}",
                    &self
                        .database_url
                        .as_ref()
                        .map_or("[INVALID URL]", |url| url.as_str())
                ),
                "mysql" => write!(
                    f,
                    "mysql: {}",
                    &self
                        .database_url
                        .as_ref()
                        .map_or("[INVALID URL]", |url| url.as_str())
                ),
                "sqlite" => write!(f, "sqlite: {}", self.sqlite_path.display()),
                #[cfg(feature = "non-fips")]
                #[allow(deprecated)]
                // Label will still be accepted until all data is migrated
                "redis-findex" => write!(
                    f,
                    "redis-findex: {}, password: [****]{}",
                    &self
                        .database_url
                        .as_ref()
                        .map_or("[INVALID URL]", |url| url.as_str()),
                    self.redis_findex_label
                        .as_ref()
                        .map_or_else(String::new, |label| format!(
                            ", label: 0x{} (the label parameter is deprecated and will be removed \
                             in future versions, use it only to migrate existing data)",
                            hex::encode(label.as_bytes())
                        ))
                ),
                unknown => write!(f, "Unknown database type: {unknown}"),
            }?;
        } else {
            write!(f, "No database configuration provided")?;
        }
        write!(f, ", clear_database?: {}", self.clear_database)
    }
}

impl std::fmt::Debug for MainDBConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}

impl MainDBConfig {
    /// Initialize the DB parameters based on the command-line parameters
    ///
    /// # Parameters
    /// - `workspace`: The workspace configuration used to determine the public and shared paths
    ///
    /// # Returns
    /// - The DB parameters
    ///
    /// # Errors
    /// - If both Postgres and MariaDB/MySQL URLs are set
    /// - If `SQLCipher` is set along with a Postgres or MariaDB/MySQL URL
    pub(crate) fn init(&self, workspace: &WorkspaceConfig) -> KResult<MainDbParams> {
        if let Some(database_type) = &self.database_type {
            return Ok(match database_type.as_str() {
                "postgresql" => {
                    let url = ensure_url(self.database_url.as_deref(), "KMS_POSTGRES_URL")
                        .context("db:init")?;
                    MainDbParams::Postgres(url, self.max_connections)
                }
                "mysql" => {
                    let url = ensure_url(self.database_url.as_deref(), "KMS_MYSQL_URL")
                        .context("db:init")?;
                    MainDbParams::Mysql(url, self.max_connections)
                }
                "sqlite" => {
                    let path = workspace
                        .finalize_directory(&self.sqlite_path)
                        .context("db:init")?;
                    MainDbParams::Sqlite(path, self.max_connections)
                }
                #[cfg(feature = "non-fips")]
                #[allow(deprecated)]
                // Label will still be accepted until all data is migrated
                "redis-findex" => {
                    let url = ensure_url(self.database_url.as_deref(), "KMS_REDIS_URL")
                        .context("db:init")?;
                    // Check if a Redis master password was provided
                    let redis_master_password = ensure_value(
                        self.redis_master_password.as_deref(),
                        "redis-master-password",
                        "KMS_REDIS_MASTER_PASSWORD",
                    )?;
                    // Generate the symmetric key from the master password
                    let master_key = redis_master_key_from_password(&redis_master_password)
                        .context("db:init")?;
                    MainDbParams::RedisFindex(url, master_key)
                }
                unknown => kms_bail!("Unknown database type: {unknown}"),
            });
        }
        // No database configuration provided; use the default config
        let path = workspace
            .finalize_directory(&self.sqlite_path)
            .context("db:init; workspace finalize")?;
        Ok(MainDbParams::Sqlite(path, self.max_connections))
    }
}

fn ensure_url(database_url: Option<&str>, alternate_env_variable: &str) -> KResult<Url> {
    let url = database_url.map_or_else(
        || {
            std::env::var(alternate_env_variable).map_err(|_e| {
                kms_error!(
                    "No database URL supplied either using the 'database-url' option, or the \
                     KMS_DATABASE_URL or the {alternate_env_variable} environment variables",
                )
            })
        },
        |url| Ok(url.to_owned()),
    )?;
    let url = Url::parse(&url)?;
    Ok(url)
}

#[cfg(feature = "non-fips")]
fn ensure_value(
    value: Option<&str>,
    option_name: &str,
    env_variable_name: &str,
) -> KResult<String> {
    value.map_or_else(
        || {
            std::env::var(env_variable_name).map_err(|_e| {
                kms_error!(
                    "No value supplied either using the {} option, or the {} environment variable",
                    option_name,
                    env_variable_name
                )
            })
        },
        |value| Ok(value.to_owned()),
    )
}
