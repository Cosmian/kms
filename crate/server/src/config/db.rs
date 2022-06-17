use std::path::{Path, PathBuf};

use clap::Args;

use super::DbParams;

#[derive(Debug, Args, Clone)]
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

    /// The dir of the sqlite database
    #[clap(
        long,
        env = "KMS_SQLITE_DIR",
        parse(from_os_str),
        default_value_os_t =  std::env::temp_dir()
    )]
    pub sqlite_dir: PathBuf,
}

impl Default for DBConfig {
    fn default() -> Self {
        DBConfig {
            postgres_url: None,
            mysql_url: None,
            user_cert_path: None,
            sqlite_dir: std::env::temp_dir(),
        }
    }
}

impl DBConfig {
    pub fn init(&self) -> eyre::Result<DbParams> {
        if self.postgres_url.is_some() && self.mysql_url.is_some() {
            eyre::bail!(
                "Postgres and MariaDB/MySQL URL are both set, can't decide which one to use"
            );
        }

        if let Some(postgres_url) = &self.postgres_url {
            Ok(DbParams::Postgres(postgres_url.to_string()))
        } else if let Some(mysql_url) = &self.mysql_url {
            Ok(DbParams::Mysql(
                mysql_url.to_string(),
                self.user_cert_path.clone(),
            ))
        } else {
            Ok(DbParams::Sqlite(
                Path::new(&self.sqlite_dir).canonicalize()?.join("kms.db"),
            ))
        }
    }
}
