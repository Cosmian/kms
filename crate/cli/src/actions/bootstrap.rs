use std::path::PathBuf;

use clap::{Args, Parser};
use cosmian_kms_client::BootstrapRestClient;

use crate::{cli_bail, error::CliError};

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
    pub async fn process(
        &self,
        bootstrap_rest_client: &BootstrapRestClient,
    ) -> Result<(), CliError> {
        println!("Server response:");

        // set the password if provided, if not set the empty string
        bootstrap_rest_client
            .set_pkcs12_password(&self.pkcs12.https_p12_password)
            .await?;

        // upload the PKCS12 file if provided
        if let Some(pkcs12_file) = &self.pkcs12.https_p12_file {
            let response = bootstrap_rest_client.upload_pkcs12(pkcs12_file).await?;
            println!("  -> {}", response.success);
        }

        // set the database configuration
        if let Some(database_type) = &self.db.database_type {
            let response = match database_type.as_str() {
                "redis-findex" => {
                    let database_url = self.db.database_url.as_ref().ok_or_else(|| {
                        CliError::Default("Missing the database url for redis-findex".to_string())
                    })?;
                    let redis_master_password =
                        self.db.redis_master_password.as_ref().ok_or_else(|| {
                            CliError::Default(
                                "Missing the Redis master password for redis-findex".to_string(),
                            )
                        })?;
                    let redis_findex_label =
                        self.db.redis_findex_label.as_ref().ok_or_else(|| {
                            CliError::Default(
                                "Missing the Findex label for redis-findex".to_string(),
                            )
                        })?;
                    bootstrap_rest_client
                        .set_redis_findex_config(
                            database_url,
                            redis_master_password,
                            redis_findex_label,
                        )
                        .await?
                }
                "postgresql" => {
                    if let Some(database_url) = &self.db.database_url {
                        bootstrap_rest_client
                            .set_postgresql_config(database_url)
                            .await?
                    } else {
                        cli_bail!("Missing the database url for postgresql")
                    }
                }
                "mysql" => {
                    if let Some(database_url) = &self.db.database_url {
                        bootstrap_rest_client.set_mysql_config(database_url).await?
                    } else {
                        cli_bail!("Missing the database url for mysql")
                    }
                }
                "sqlite" => {
                    bootstrap_rest_client
                        .set_sqlite_config(&self.db.sqlite_path)
                        .await?
                }
                "sqlite-enc" => {
                    bootstrap_rest_client
                        .set_sqlite_enc_config(&self.db.sqlite_path)
                        .await?
                }
                _ => {
                    cli_bail!("Invalid database type");
                }
            };
            println!("  -> {}", response.success);
        }

        let response = bootstrap_rest_client
            .start_kms_server(self.db.clear_database)
            .await?;
        println!("  -> {}", response.success);

        Ok(())
    }
}

/// Configuration for the database
#[derive(Args, Clone)]
pub struct DatabaseConfig {
    /// The database type of the KMS server:
    /// - postgresql: PostgreSQL. The database url must be provided
    /// - mysql: MySql or MariaDB. The database url must be provided
    /// - sqlite: SQLite. The data will be stored at the sqlite_path directory
    /// - sqlite-enc: SQLite encrypted at rest. The data will be stored at the sqlite_path directory.
    ///   A key must be supplied on every call
    /// - redis-findex: and redis database with encrypted data and encrypted indexes thanks to Findex.
    ///   The Redis database url must be provided, as well as the redis-master-password and the redis-findex-label
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
    /// The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode.
    #[clap(long)]
    pub https_p12_file: Option<PathBuf>,

    /// The password to open the PKCS#12 Certificates and Key file if not an empty string
    #[clap(long, default_value = "")]
    pub https_p12_password: String,
}
