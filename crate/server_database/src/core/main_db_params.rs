use std::{
    collections::HashMap,
    fmt::{self, Display},
    path::PathBuf,
};

#[cfg(feature = "non-fips")]
use cosmian_kms_crypto::reexport::cosmian_crypto_core::SymmetricKey;
use url::Url;

#[cfg(feature = "non-fips")]
use crate::stores::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;

pub enum MainDbParams {
    /// contains the directory of the `SQLite` DB file (not the DB file itself)
    /// and an optional `max_connections` override
    Sqlite(PathBuf, Option<u32>),
    /// contains the `Postgres` connection URL (raw string to support multi-host URLs
    /// like `postgresql://host1:5432,host2:5432/db?target_session_attrs=read-write`)
    /// and an optional `max_connections` override
    Postgres(String, Option<u32>),
    /// contains the `MySQL` connection URL and an optional `max_connections` override
    Mysql(Url, Option<u32>),
    /// contains
    /// - the `Redis` connection URL
    /// - the master key used to encrypt the DB and the Index
    #[cfg(feature = "non-fips")]
    RedisFindex(Url, SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>),
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
            Self::RedisFindex(_, _) => "Redis-Findex",
        }
    }
}

impl Display for MainDbParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(path, _) => write!(f, "sqlite: {}", path.display()),
            Self::Postgres(url, _) => write!(f, "postgres: {}", redact_connection_string(url)),
            Self::Mysql(url, _) => write!(f, "mysql: {}", redact_url(url)),
            #[cfg(feature = "non-fips")]
            Self::RedisFindex(url, _) => {
                write!(f, "redis-findex: {}, master key: [****]", redact_url(url))
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

/// Redact credentials from a raw connection string (supports multi-host URLs).
fn redact_connection_string(s: &str) -> String {
    if let Some(scheme_end) = s.find("://") {
        let after_scheme = &s[scheme_end + 3..];
        if let Some(at_pos) = after_scheme.find('@') {
            let creds = &after_scheme[..at_pos];
            let redacted = if creds.contains(':') {
                "****:****"
            } else {
                "****"
            };
            return format!(
                "{}://{}@{}",
                &s[..scheme_end],
                redacted,
                &after_scheme[at_pos + 1..]
            );
        }
    }
    s.to_owned()
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_connection_string_user_and_pass() {
        assert_eq!(
            redact_connection_string("postgresql://user:pass@host/db"),
            "postgresql://****:****@host/db"
        );
    }

    #[test]
    fn test_redact_connection_string_user_only() {
        assert_eq!(
            redact_connection_string("postgresql://admin@host/db"),
            "postgresql://****@host/db"
        );
    }

    #[test]
    fn test_redact_connection_string_no_credentials() {
        assert_eq!(
            redact_connection_string("postgresql://host/db"),
            "postgresql://host/db"
        );
    }

    #[test]
    fn test_redact_connection_string_multi_host() {
        assert_eq!(
            redact_connection_string("postgresql://u:p@h1:5432,h2:5432/db"),
            "postgresql://****:****@h1:5432,h2:5432/db"
        );
    }

    #[test]
    fn test_redact_connection_string_empty_creds() {
        assert_eq!(
            redact_connection_string("postgresql://@host/db"),
            "postgresql://****@host/db"
        );
    }

    #[test]
    fn test_redact_connection_string_preserves_query_params() {
        assert_eq!(
            redact_connection_string(
                "postgresql://user:pass@host/db?target_session_attrs=read-write"
            ),
            "postgresql://****:****@host/db?target_session_attrs=read-write"
        );
    }

    #[test]
    fn test_redact_connection_string_empty_string() {
        assert_eq!(redact_connection_string(""), "");
    }

    #[test]
    fn test_redact_connection_string_not_a_url() {
        assert_eq!(redact_connection_string("not-a-url"), "not-a-url");
    }
}
