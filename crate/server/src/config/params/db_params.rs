use std::{
    fmt::{self, Display},
    path::PathBuf,
};

use cloudproof::reexport::{crypto_core::SymmetricKey, findex::Label};
use url::Url;

use crate::database::redis::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;

pub enum DbParams {
    /// contains the dir of the sqlite db file (not the db file itself)
    Sqlite(PathBuf),
    /// contains the dir of the sqlcipher db file (not the db file itself)
    SqliteEnc(PathBuf),
    /// contains the Postgres connection URL
    Postgres(Url),
    /// contains the MySql connection URL
    Mysql(Url),
    /// contains
    /// - the Redis connection URL
    /// - the master key used to encrypt the DB and the Index
    /// - a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the key
    RedisFindex(
        Url,
        SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        Label,
    ),
}

impl DbParams {
    /// Return the name of the database type
    #[must_use]
    pub fn db_name(&self) -> &str {
        match &self {
            DbParams::Sqlite(_) => "Sqlite",
            DbParams::SqliteEnc(_) => "Sqlite Enc.",
            DbParams::Postgres(_) => "PostgreSQL",
            DbParams::Mysql(_) => "MySql/MariaDB",
            DbParams::RedisFindex(_, _, _) => "Redis-Findex",
        }
    }
}

impl Display for DbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbParams::Sqlite(path) => write!(f, "sqlite: {}", path.display()),
            DbParams::SqliteEnc(path) => write!(f, "sqlcipher: {}", path.display()),
            DbParams::Postgres(url) => write!(f, "postgres: {}", redact_url(url)),
            DbParams::Mysql(url) => write!(f, "mysql: {}", redact_url(url)),
            DbParams::RedisFindex(url, _, label) => {
                write!(
                    f,
                    "redis-findex: {}, master key: [****], Findex label: 0x{}",
                    redact_url(url),
                    hex::encode(label)
                )
            }
        }
    }
}

/// Redact the username and password from the URL for logging purposes
fn redact_url(original: &Url) -> Url {
    let mut url = original.clone();

    if url.username() != "" {
        url.set_username("****").unwrap();
    }
    if url.password().is_some() {
        url.set_password(Some("****")).unwrap();
    }

    url
}

impl std::fmt::Debug for DbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}
