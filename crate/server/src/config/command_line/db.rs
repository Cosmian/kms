use std::{fmt::Display, path::PathBuf};

use clap::Args;
use cloudproof_findex::Label;
use cosmian_kms_server_database::{redis_master_key_from_password, MainDbParams};
use serde::{Deserialize, Serialize};
use url::Url;

use super::workspace::WorkspaceConfig;
use crate::{kms_bail, kms_error, result::KResult};

pub const DEFAULT_SQLITE_PATH: &str = "./sqlite-data";

/// Configuration for the database
#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MainDBConfig {
    /// The main database of the KMS server that holds default cryptographic objects and permissions.
    /// - postgresql: `PostgreSQL`. The database url must be provided
    /// - mysql: `MySql` or `MariaDB`. The database url must be provided
    /// - sqlite: `SQLite`. The data will be stored at the `sqlite_path` directory
    /// - sqlite-enc: `SQLite` encrypted at rest. the data will be stored at the `sqlite_path` directory.
    ///   A key must be supplied on every call
    /// - redis-findex: a Redis database with encrypted data and encrypted indexes thanks to Findex.
    ///   The Redis url must be provided, as well as the redis-master-password and the redis-findex-label
    #[clap(
        long,
        env("KMS_DATABASE_TYPE"),
        value_parser(["postgresql", "mysql", "sqlite", "sqlite-enc", "redis-findex"]),
        verbatim_doc_comment
    )]
    pub database_type: Option<String>,

    /// The url of the database for postgresql, mysql or findex-redis
    #[clap(
        long,
        env = "KMS_DATABASE_URL",
        required_if_eq_any([("database_type", "postgresql"), ("database_type", "mysql"), ("database_type", "redis-findex")])
    )]
    pub database_url: Option<String>,

    /// The directory path of the sqlite or sqlite-enc
    #[clap(
        long,
        env = "KMS_SQLITE_PATH",
        default_value = DEFAULT_SQLITE_PATH,
        required_if_eq_any([("database_type", "sqlite"), ("database_type", "sqlite-enc")])
    )]
    pub sqlite_path: PathBuf,

    /// redis-findex: a master password used to encrypt the Redis data and indexes
    #[clap(
        long,
        env = "KMS_REDIS_MASTER_PASSWORD",
        required_if_eq("database_type", "redis-findex")
    )]
    pub redis_master_password: Option<String>,

    /// redis-findex: a public arbitrary label that can be changed to rotate the Findex ciphertexts
    /// without changing the key
    #[clap(
        long,
        env = "KMS_REDIS_FINDEX_LABEL",
        required_if_eq("database_type", "redis-findex")
    )]
    pub redis_findex_label: Option<String>,

    /// Clear the database on start.
    /// WARNING: This will delete ALL the data in the database
    #[clap(long, env = "KMS_CLEAR_DATABASE", verbatim_doc_comment)]
    pub clear_database: bool,
}

impl Default for MainDBConfig {
    fn default() -> Self {
        Self {
            sqlite_path: PathBuf::from(DEFAULT_SQLITE_PATH),
            database_type: None,
            database_url: None,
            clear_database: false,
            redis_master_password: None,
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
                "sqlite-enc" => write!(f, "sqlcipher: {}", self.sqlite_path.display()),
                "redis-findex" => write!(
                    f,
                    "redis-findex: {}, password: [****], label: 0x{}",
                    &self
                        .database_url
                        .as_ref()
                        .map_or("[INVALID LABEL]", |url| url.as_str()),
                    hex::encode(
                        self.redis_findex_label
                            .as_ref()
                            .map_or("[INVALID LABEL]", |url| url.as_str()),
                    )
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
    /// - If both Postgres and MariaDB/MySQL URL are set
    /// - If `SQLCipher` is set along with Postgres or MariaDB/MySQL URL
    pub(crate) fn init(&self, workspace: &WorkspaceConfig) -> KResult<MainDbParams> {
        if let Some(database_type) = &self.database_type {
            return Ok(match database_type.as_str() {
                "postgresql" => {
                    let url = ensure_url(self.database_url.as_deref(), "KMS_POSTGRES_URL")?;
                    MainDbParams::Postgres(url)
                }
                "mysql" => {
                    let url = ensure_url(self.database_url.as_deref(), "KMS_MYSQL_URL")?;
                    MainDbParams::Mysql(url)
                }
                "sqlite" => {
                    let path = workspace.finalize_directory(&self.sqlite_path)?;
                    MainDbParams::Sqlite(path)
                }
                "sqlite-enc" => {
                    let path = workspace.finalize_directory(&self.sqlite_path)?;
                    MainDbParams::SqliteEnc(path)
                }
                "redis-findex" => {
                    let url = ensure_url(self.database_url.as_deref(), "KMS_REDIS_URL")?;
                    // Check if a Redis master password was provided
                    let redis_master_password = ensure_value(
                        self.redis_master_password.as_deref(),
                        "redis-master-password",
                        "KMS_REDIS_MASTER_PASSWORD",
                    )?;
                    // Generate the symmetric key from the master password
                    let master_key = redis_master_key_from_password(&redis_master_password)?;
                    let redis_findex_label = ensure_value(
                        self.redis_findex_label.as_deref(),
                        "redis-findex-label",
                        "KMS_REDIS_FINDEX_LABEL",
                    )?;
                    MainDbParams::RedisFindex(
                        url,
                        master_key,
                        Label::from(redis_findex_label.into_bytes()),
                    )
                }
                unknown => kms_bail!("Unknown database type: {unknown}"),
            });
        }
        // No database configuration provided; use the default config
        let path = workspace.finalize_directory(&self.sqlite_path)?;
        Ok(MainDbParams::Sqlite(path))
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
