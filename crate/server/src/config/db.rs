use std::path::PathBuf;

use clap::Args;

use super::{workspace::WorkspaceConfig, DbParams};

#[derive(Debug, Args, Clone, Default)]
pub struct DBConfig {
    /// The url of the postgres database
    #[clap(long, env = "KMS_POSTGRES_URL")]
    pub postgres_url: Option<String>,

    /// The url of the mysql database
    #[clap(long, env = "KMS_MYSQL_URL")]
    pub mysql_url: Option<String>,

    /// The path of the client certificate if key-file is the authentication method
    #[clap(long, env = "KMS_USER_CERT_PATH", parse(from_os_str))]
    pub user_cert_path: Option<PathBuf>,

    /// Wether to use sqlcipher
    #[clap(long, env = "KMS_SQLCIPHER")]
    pub sqlcipher: bool,
}

impl DBConfig {
    pub fn init(&self, workspace: &WorkspaceConfig) -> eyre::Result<DbParams> {
        if self.postgres_url.is_some() && self.mysql_url.is_some() {
            eyre::bail!(
                "Postgres and MariaDB/MySQL URL are both set, can't decide which one to use"
            );
        }

        if self.sqlcipher && (self.postgres_url.is_some() || self.mysql_url.is_some()) {
            eyre::bail!("SQLCipher is incompatible with Postgres and MariaDB/MySQL URL");
        }

        if let Some(postgres_url) = &self.postgres_url {
            Ok(DbParams::Postgres(postgres_url.to_string()))
        } else if let Some(mysql_url) = &self.mysql_url {
            Ok(DbParams::Mysql(
                mysql_url.to_string(),
                self.user_cert_path.clone(),
            ))
        } else if self.sqlcipher {
            Ok(DbParams::SqlCipher(workspace.public_path.clone()))
        } else {
            Ok(DbParams::Sqlite(workspace.shared_path.clone()))
        }
    }
}
