use std::{fmt::Display, path::PathBuf};

use clap::Args;
use cloudproof::reexport::crypto_core::{FixedSizeCBytes, SymmetricKey};
use cosmian_kms_utils::crypto::password_derivation::{derive_key_from_password, KMS_ARGON2_SALT};

use super::{workspace::WorkspaceConfig, DbParams};
use crate::{
    database::redis::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH, kms_bail, kms_error, result::KResult,
};

/// Configuration for the database
#[derive(Args, Clone)]
pub struct DBConfig {
    /// The type of database used as backend
    /// - postgresql: PostgreSQL. The database url must be provided
    /// - mysql: MySql or MariaDB. The database url must be provided
    /// - sqlite: SQLite. The data will be stored at the sqlite_path directory
    /// - sqlite-enc: SQLite encrypted at rest. the data will be stored at the sqlite_path directory.
    ///   A key must be supplied on every call
    /// - redis-findex: and encrypted redis database with an encrypted index using Findex.
    ///   The database url must be provided, as well as the redis-master-password and the redis-findex-label
    /// _
    #[clap(
        long,
        env("KMS_DATABASE_TYPE"),
        value_parser(["postgresql", "mysql", "sqlite", "sqlite-enc", "redis-findex"]),
        default_value("sqlite"),
        verbatim_doc_comment
    )]
    pub database_type: String,

    /// The url of the database for postgresql, mysql or findex-redis
    #[clap(long, env = "KMS_DATABASE_URL")]
    pub database_url: Option<String>,

    /// The directory path of the sqlite or sqlite-enc
    #[clap(long, env = "KMS_SQLITE_PATH", default_value = "./sqlite-data")]
    pub sqlite_path: PathBuf,

    /// redis-findex: a master password used to encrypt the Redis data and indexes
    #[clap(long, env = "KMS_REDIS_MASTER_PASSWORD")]
    pub redis_master_password: Option<String>,

    /// redis-findex: a public arbitrary label that can be changed to rotate the Findex ciphertexts
    /// without changing the key
    #[clap(long, env = "KMS_REDIS_FINDEX_LABEL")]
    pub redis_findex_label: Option<String>,

    /// Clear the database on start.
    /// WARNING: This will delete ALL the data in the database
    #[clap(
        long,
        env = "KMS_CLEAR_DATABASE",
        default_value = "false",
        verbatim_doc_comment
    )]
    pub clear_database: bool,
}

impl Display for DBConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.database_type.as_str() {
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
            unknown => write!(f, "Unknown database type: {}", unknown),
        }?;
        write!(f, ", clear_database?: {}", self.clear_database)
    }
}

impl std::fmt::Debug for DBConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}

impl Default for DBConfig {
    fn default() -> Self {
        Self {
            database_type: "sqlite".to_string(),
            database_url: None,
            sqlite_path: PathBuf::from("./sqlite-data"),
            clear_database: false,
            redis_master_password: None,
            redis_findex_label: None,
        }
    }
}

impl DBConfig {
    /// Initialize the DB parameters based on the configuration
    ///
    /// # Parameters
    /// - `workspace`: The workspace configuration, used to determine the public and shared paths
    ///
    /// # Returns
    /// - The DB parameters
    ///
    /// # Errors
    /// - If both Postgres and MariaDB/MySQL URL are set
    /// - If `SQLCipher` is set along with Postgres or MariaDB/MySQL URL
    pub fn init(&self, workspace: &WorkspaceConfig) -> KResult<DbParams> {
        match self.database_type.as_str() {
            "postgresql" => {
                let url = ensure_url(self.database_url.as_deref(), "KMS_POSTGRES_URL")?;
                Ok(DbParams::Postgres(url))
            }
            "mysql" => {
                let url = ensure_url(self.database_url.as_deref(), "KMS_MYSQL_URL")?;
                Ok(DbParams::Mysql(url))
            }
            "sqlite" => {
                let path = workspace.finalize_directory(&self.sqlite_path)?;
                Ok(DbParams::Sqlite(path))
            }
            "sqlite-enc" => {
                let path = workspace.finalize_directory(&self.sqlite_path)?;
                Ok(DbParams::SqliteEnc(path))
            }
            "redis-findex" => {
                let url = ensure_url(self.database_url.as_deref(), "KMS_REDIS_URL")?;
                let master_redis_password = ensure_value(
                    self.redis_master_password.as_deref(),
                    "redis-master-password",
                    "KMS_REDIS_MASTER_PASSWORD",
                )?;
                let redis_findex_label = ensure_value(
                    self.redis_findex_label.as_deref(),
                    "redis-findex-label",
                    "KMS_REDIS_FINDEX_LABEL",
                )?;
                // derive a SymmetricKey from the master password
                let master_secret_key =
                    SymmetricKey::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::try_from_bytes(
                        derive_key_from_password::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>(
                            master_redis_password.as_bytes(),
                            KMS_ARGON2_SALT,
                        )?,
                    )?;
                Ok(DbParams::RedisFindex(
                    url,
                    master_secret_key,
                    redis_findex_label.into_bytes(),
                ))
            }
            unknown => kms_bail!("Unknown database type: {unknown}"),
        }
    }
}

fn ensure_url(database_url: Option<&str>, alternate_env_variable: &str) -> KResult<String> {
    if let Some(url) = database_url {
        Ok(url.to_string())
    } else {
        std::env::var(alternate_env_variable).map_err(|_e| {
            kms_error!(
                "No database URL supplied either using the 'database-url' option, or the \
                 KMS_DATABASE_URL or the {alternate_env_variable} environment variables",
            )
        })
    }
}

fn ensure_value(
    value: Option<&str>,
    option_name: &str,
    env_variable_name: &str,
) -> KResult<String> {
    if let Some(value) = value {
        Ok(value.to_string())
    } else {
        std::env::var(env_variable_name).map_err(|_e| {
            kms_error!(
                "No value supplied either using the {} option, or the {} environment variable",
                option_name,
                env_variable_name
            )
        })
    }
}
