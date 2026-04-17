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

/// Mask the password component of a database connection URL before logging.
///
/// Uses [`url::Url::parse`] for standard single-host URLs; falls back to a simple
/// string scan for multi-host `PostgreSQL` connection strings
/// (e.g. `postgresql://user:pass@host1,host2/db`) that [`url::Url`] cannot parse.
///
/// Returns the original string unchanged when no password is detected.
fn mask_db_url_password(url: &str) -> String {
    // Fast path: standard URL that `url::Url` can parse (MySQL, single-host Postgres, Redis)
    if let Ok(mut parsed) = url::Url::parse(url) {
        if parsed.password().is_some() {
            // `set_password` can only fail if the URL has no host (e.g. `data:`), which
            // won't happen for a database URL, so the error is intentionally discarded.
            let _ = parsed.set_password(Some("****"));
        }
        return parsed.to_string();
    }
    // Slow path: multi-host PostgreSQL URL — scan manually
    // Pattern: scheme://[user[:pass]@]... → replace :pass@ with :****@
    if let Some(at_pos) = url.rfind('@') {
        if let Some(scheme_end) = url.find("://") {
            let creds = &url[scheme_end + 3..at_pos];
            if let Some(colon_pos) = creds.find(':') {
                let user = &creds[..colon_pos];
                let scheme = &url[..scheme_end];
                let rest = &url[at_pos + 1..];
                return format!("{scheme}://{user}:****@{rest}");
            }
        }
    }
    url.to_owned()
}

/// Supported database backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    Sqlite,
    Postgresql,
    Mysql,
    #[cfg(feature = "non-fips")]
    RedisFindex,
}

impl DatabaseType {
    pub const FIPS_VARIANTS: &'static [Self] = &[Self::Sqlite, Self::Postgresql, Self::Mysql];
    #[cfg(feature = "non-fips")]
    pub const NON_FIPS_VARIANTS: &'static [Self] = &[
        Self::Sqlite,
        Self::Postgresql,
        Self::Mysql,
        Self::RedisFindex,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgresql => "postgresql",
            Self::Mysql => "mysql",
            #[cfg(feature = "non-fips")]
            Self::RedisFindex => "redis-findex",
        }
    }
}

impl Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
        }
    }
}

impl Display for MainDBConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(database_type) = &self.database_type {
            match database_type.as_str() {
                "postgresql" => {
                    let masked = self
                        .database_url
                        .as_deref()
                        .map_or_else(|| "[INVALID URL]".to_owned(), mask_db_url_password);
                    write!(f, "postgresql: {masked}")
                }
                "mysql" => {
                    let masked = self
                        .database_url
                        .as_deref()
                        .map_or_else(|| "[INVALID URL]".to_owned(), mask_db_url_password);
                    write!(f, "mysql: {masked}")
                }
                "sqlite" => write!(f, "sqlite: {}", self.sqlite_path.display()),
                #[cfg(feature = "non-fips")]
                #[allow(deprecated)]
                // Label will still be accepted until all data is migrated
                "redis-findex" => write!(
                    f,
                    "redis-findex: {}, password: [****]",
                    &self
                        .database_url
                        .as_ref()
                        .map_or("[INVALID URL]", |url| url.as_str()),
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
                    let url = ensure_url_string(self.database_url.as_deref(), "KMS_POSTGRES_URL")
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

/// Resolve the database URL from the command-line option or an environment variable,
/// returning the raw string.  This avoids `Url::parse()` which cannot handle
/// multi-host `PostgreSQL` connection strings
/// (e.g. `postgresql://host1:5432,host2:5432/db?target_session_attrs=read-write`).
fn ensure_url_string(database_url: Option<&str>, alternate_env_variable: &str) -> KResult<String> {
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
    if url.is_empty() {
        return Err(kms_error!("Database URL must not be empty"));
    }
    if !url.starts_with("postgresql://") && !url.starts_with("postgres://") {
        return Err(kms_error!(
            "PostgreSQL URL must start with 'postgresql://' or 'postgres://'"
        ));
    }
    Ok(url)
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unwrap_in_result,
    clippy::assertions_on_result_states
)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_url_string_valid_postgresql_scheme() {
        let result = ensure_url_string(Some("postgresql://host/db"), "UNUSED_ENV");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "postgresql://host/db");
    }

    #[test]
    fn test_ensure_url_string_valid_postgres_scheme() {
        let result = ensure_url_string(Some("postgres://host/db"), "UNUSED_ENV");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_url_string_invalid_mysql_scheme() {
        let result = ensure_url_string(Some("mysql://host/db"), "UNUSED_ENV");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("postgresql://"));
    }

    #[test]
    fn test_ensure_url_string_invalid_http_scheme() {
        let result = ensure_url_string(Some("http://host/db"), "UNUSED_ENV");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("postgresql://"));
    }

    #[test]
    fn test_ensure_url_string_not_a_url() {
        let result = ensure_url_string(Some("not-a-url"), "UNUSED_ENV");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("postgresql://"));
    }

    #[test]
    fn test_ensure_url_string_empty() {
        let result = ensure_url_string(Some(""), "UNUSED_ENV");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"));
    }

    // ── N1–N5: Database URL password masking (OSSTMM Visibility · NIST PR.DS-5) ─

    /// N1: Standard single-host `PostgreSQL` URL – password must be replaced with `****`.
    #[test]
    fn n01_postgres_single_host_password_masked() {
        let url = "postgresql://user:secret@localhost:5432/db";
        let masked = mask_db_url_password(url);
        assert!(
            !masked.contains("secret"),
            "Password must not appear in masked URL: {masked}"
        );
        assert!(
            masked.contains("****"),
            "Masked URL must contain ****: {masked}"
        );
        assert!(
            masked.contains("user:"),
            "Username must be preserved: {masked}"
        );
    }

    /// N2: `MySQL` URL – password must be masked.
    #[test]
    fn n02_mysql_password_masked() {
        let url = "mysql://admin:pass@127.0.0.1:3306/kms";
        let masked = mask_db_url_password(url);
        assert!(
            !masked.contains("pass"),
            "Password must not appear: {masked}"
        );
        assert!(masked.contains("****"), "Must contain ****: {masked}");
    }

    /// N3: Multi-host `PostgreSQL` URL that `url::Url` cannot parse – slow-path masking.
    #[test]
    fn n03_postgres_multi_host_password_masked() {
        let url = "postgresql://user:secret@host1,host2,host3/db";
        let masked = mask_db_url_password(url);
        assert!(
            !masked.contains("secret"),
            "Password must not appear in multi-host URL: {masked}"
        );
        assert!(masked.contains("****"), "Must contain ****: {masked}");
    }

    /// N4: URL without a password – string must be unchanged.
    #[test]
    fn n04_no_password_unchanged() {
        let url = "postgresql://user@localhost/db";
        let masked = mask_db_url_password(url);
        assert_eq!(
            url, masked,
            "URL without password must be returned unchanged"
        );
    }

    /// N5: Completely invalid URL – must not panic, return unchanged string.
    #[test]
    fn n05_invalid_url_no_panic() {
        let url = "not-a-url-at-all";
        let masked = mask_db_url_password(url);
        assert_eq!(
            url, masked,
            "Invalid URL must be returned unchanged without panic"
        );
    }
}
