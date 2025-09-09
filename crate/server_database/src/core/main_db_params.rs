use std::{
    collections::HashMap,
    fmt::{self, Display},
    path::PathBuf,
};

#[cfg(feature = "non-fips")]
use cosmian_kms_crypto::reexport::cosmian_crypto_core::SymmetricKey;
use url::Url;

#[cfg(feature = "non-fips")]
use crate::stores::FINDEX_KEY_LENGTH;

pub enum MainDbParams {
    /// contains the directory of the `SQLite` DB file (not the DB file itself)
    Sqlite(PathBuf),
    /// contains the `Postgres` connection URL
    Postgres(Url),
    /// contains the `MySQL` connection URL
    Mysql(Url),
    /// contains
    /// - the `Redis` connection URL
    /// - the master key used to encrypt the DB and the Index
    #[cfg(feature = "non-fips")]
    RedisFindex(Url, SymmetricKey<FINDEX_KEY_LENGTH>),
}

impl MainDbParams {
    /// Return the name of the database type
    #[must_use]
    pub const fn db_name(&self) -> &str {
        match &self {
            Self::Sqlite(_) => "Sqlite",
            Self::Postgres(_) => "PostgreSQL",
            Self::Mysql(_) => "MySql/MariaDB",
            #[cfg(feature = "non-fips")]
            Self::RedisFindex(_, _) => "Redis-Findex",
        }
    }
}

impl Display for MainDbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(path) => write!(f, "sqlite: {}", path.display()),
            Self::Postgres(url) => write!(f, "postgres: {}", redact_url(url)),
            Self::Mysql(url) => write!(f, "mysql: {}", redact_url(url)),
            #[cfg(feature = "non-fips")]
            Self::RedisFindex(url, _) => {
                write!(f, "redis-findex: {}, master key: [****]", redact_url(url),)
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
    /// Proteccio HSM: the Object UIDs prefix, HSM admin username, and the slot passwords
    ProteccioHsm((String, String, HashMap<usize, Option<String>>)),
}
