use std::path::PathBuf;

use clap::Args;

use super::{workspace::WorkspaceConfig, DbParams};

/// Configuration for the database
#[derive(Debug, Args, Clone)]
pub struct DBConfig {
    /// The type of database used as backend
    /// - postgresql: PostgreSQL. The database url must be provided
    /// - mysql: MySql or MariaDB. The database url must be provided
    /// - sqlite: SQLite. The data will be stored at the sqlite_path directory
    /// - sqlite-enc: SQLite encrypted at rest. the data will be stored at the sqlite_path directory.
    ///   A key must be supplied on every call
    ///
    /// _
    #[clap(
        long,
        env("KMS_DATABASE_TYPE"),
        value_parser(["postgresql", "mysql", "sqlite", "sqlite-enc"]),
        default_value("sqlite"),
        verbatim_doc_comment
    )]
    pub database_type: String,

    /// The url of the database for postgresql or mysql
    #[clap(long, env = "KMS_DATABASE_URL")]
    pub database_url: Option<String>,

    /// The directory path of the sqlite or sqlite-enc
    #[clap(long, env = "KMS_SQLITE_PATH", default_value = "./sqlite-data")]
    pub sqlite_path: PathBuf,

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

impl Default for DBConfig {
    fn default() -> Self {
        Self {
            database_type: "sqlite".to_string(),
            database_url: None,
            sqlite_path: PathBuf::from("./sqlite-data"),
            clear_database: false,
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
    pub fn init(&self, workspace: &WorkspaceConfig) -> eyre::Result<DbParams> {
        match self.database_type.as_str() {
            "postgresql" => {
                let url = ensure_url(&self.database_url, "KMS_POSTGRES_URL")?;
                Ok(DbParams::Postgres(url))
            }
            "mysql" => {
                let url = ensure_url(&self.database_url, "KMS_MYSQL_URL")?;
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
            unknown => eyre::bail!("Unknown database type: {}", unknown),
        }
    }
}

fn ensure_url(database_url: &Option<String>, alternate_env_variable: &str) -> eyre::Result<String> {
    if let Some(url) = database_url {
        Ok(url.clone())
    } else {
        std::env::var(alternate_env_variable).map_err(|_e| {
            eyre::eyre!(
                "No database URL supplied either using the 'database-url' option, or the \
                 KMS_DATABASE_URL or the {} environment variables",
                alternate_env_variable
            )
        })
    }
}
