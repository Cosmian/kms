use std::{
    collections::HashMap,
    fmt::{self, Display},
    path::PathBuf,
};

use cosmian_crypto_core::SymmetricKey;
use cloudproof_findex::Label;
use url::Url;

use crate::stores::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;

pub enum MainDbParams {
    /// contains the dir of the sqlite db file (not the db file itself)
    Sqlite(PathBuf),
    /// contains the dir of the sqlcipher db file (not the db file itself)
    SqliteEnc(PathBuf),
    /// contains the Postgres connection URL
    Postgres(Url),
    /// contains the `MySql` connection URL
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

impl MainDbParams {
    /// Return the name of the database type
    #[must_use]
    pub const fn db_name(&self) -> &str {
        match &self {
            Self::Sqlite(_) => "Sqlite",
            Self::SqliteEnc(_) => "Sqlite Enc.",
            Self::Postgres(_) => "PostgreSQL",
            Self::Mysql(_) => "MySql/MariaDB",
            Self::RedisFindex(_, _, _) => "Redis-Findex",
        }
    }
}

impl Display for MainDbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(path) => write!(f, "sqlite: {}", path.display()),
            Self::SqliteEnc(path) => write!(f, "sqlcipher: {}", path.display()),
            Self::Postgres(url) => write!(f, "postgres: {}", redact_url(url)),
            Self::Mysql(url) => write!(f, "mysql: {}", redact_url(url)),
            Self::RedisFindex(url, _, label) => {
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
#[allow(clippy::expect_used)]
fn redact_url(original: &Url) -> Url {
    let mut url = original.clone();

    if url.username() != "" {
        url.set_username("****").expect("masking username failed");
    }
    if url.password().is_some() {
        url.set_password(Some("****"))
            .expect("masking password failed");
    }

    url
}

impl fmt::Debug for MainDbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}

#[derive(Debug)]
pub enum AdditionalObjectStoresParams {
    /// Proteccio HSM: the Object UIDs prefix, HSM admin username and the slot passwords
    ProteccioHsm((String, String, HashMap<usize, Option<String>>)),
}
