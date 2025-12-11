use std::{
    collections::HashMap,
    fmt::{self, Display},
    path::PathBuf,
};

#[cfg(feature = "non-fips")]
use cloudproof_findex::Label;
#[cfg(feature = "non-fips")]
use cosmian_kms_crypto::reexport::cosmian_crypto_core::SymmetricKey;
use url::Url;

#[cfg(feature = "non-fips")]
use crate::stores::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;

pub enum MainDbParams {
    /// contains the directory of the `SQLite` DB file (not the DB file itself)
    /// and an optional `max_connections` override
    Sqlite(PathBuf, Option<u32>),
    /// contains the `Postgres` connection URL and an optional `max_connections` override
    Postgres(Url, Option<u32>),
    /// contains the `MySQL` connection URL and an optional `max_connections` override
    Mysql(Url, Option<u32>),
    /// contains
    /// - the `Redis` connection URL
    /// - the master key used to encrypt the DB and the Index
    #[cfg(feature = "non-fips")]
    RedisFindex(
        Url,
        SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        Option<Label>,
    ),
}

impl MainDbParams {
    /// Return the name of the database type
    #[must_use]
    pub const fn db_name(&self) -> &str {
        match &self {
            Self::Sqlite(_, _) => "Sqlite",
            Self::Postgres(_, _) => "PostgreSQL",
            Self::Mysql(_, _) => "MySql/MariaDB",
            #[cfg(feature = "non-fips")]
            Self::RedisFindex(_, _, _) => "Redis-Findex",
        }
    }
}

impl Display for MainDbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(path, _) => write!(f, "sqlite: {}", path.display()),
            Self::Postgres(url, _) => write!(f, "postgres: {}", redact_url(url)),
            Self::Mysql(url, _) => write!(f, "mysql: {}", redact_url(url)),
            #[cfg(feature = "non-fips")]
            Self::RedisFindex(url, _, _) => {
                write!(f, "redis-findex: {}, master key: [****]", redact_url(url),)
            }
        }
    }
}

/// Redact the username and password from the URL for logging purposes
#[expect(clippy::expect_used)]
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
