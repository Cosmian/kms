use std::path::PathBuf;

use clap::{Args, Parser};
use cosmian_kms_client::KmsRestClient;

use crate::error::{result::CliResultHelper, CliError};

/// Provide configuration and start the KMS server via the bootstrap server.
///
/// When the server is started using the bootstrap server,
/// this command is used to provide configuration information, such as
/// - database configuration
/// - PKCS12 to use as the KMS HTTPS server certificate
/// and start the configured KMS server.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct BootstrapServerAction {
    #[clap(flatten)]
    pub db: DatabaseConfig,

    #[clap(flatten)]
    pub pkcs12: Pkcs12Config,
}

impl BootstrapServerAction {
    pub async fn process(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        let version = kms_rest_client
            .version()
            .await
            .with_context(|| "Can't execute the bootstrap command on the server")?;

        println!("{}", version);

        Ok(())
    }
}

/// Configuration for the database
#[derive(Args, Clone)]
pub struct DatabaseConfig {
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
        value_parser(["postgresql", "mysql", "sqlite", "sqlite-enc", "redis-findex"]),
        verbatim_doc_comment
    )]
    pub database_type: Option<String>,

    /// The url of the database for postgresql, mysql or findex-redis
    #[clap(
        long,
        required_if_eq_any([("database_type", "postgresql"), ("database_type", "mysql"), ("database_type", "redis-findex")])
    )]
    pub database_url: Option<String>,

    /// The directory path of the sqlite or sqlite-enc
    #[clap(
        long,
        default_value = "./sqlite-data",
        required_if_eq_any([("database_type", "sqlite"), ("database_type", "sqlite-enc")])
    )]
    pub sqlite_path: PathBuf,

    /// redis-findex: a master password used to encrypt the Redis data and indexes
    #[clap(long, required_if_eq("database_type", "redis-findex"))]
    pub redis_master_password: Option<String>,

    /// redis-findex: a public arbitrary label that can be changed to rotate the Findex ciphertexts
    /// without changing the key
    #[clap(long, required_if_eq("database_type", "redis-findex"))]
    pub redis_findex_label: Option<String>,

    /// Clear the database on start.
    /// WARNING: This will delete ALL the data in the database
    #[clap(long, default_value = "false", verbatim_doc_comment)]
    pub clear_database: bool,
}

#[derive(Args, Clone)]
pub struct Pkcs12Config {
    /// The KMS server optional PKCS#12 Certificate file. If provided, this will start the server in HTTPS mode.
    #[clap(long)]
    pub https_p12_file: Option<PathBuf>,

    /// The password to open the PKCS#12 Certificate file if not an empty string
    #[clap(long, default_value = "")]
    pub https_p12_password: String,
}
