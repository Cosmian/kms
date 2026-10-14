//! Characterization tests pinning the BASE behavior of the credential masking helpers.

use std::path::PathBuf;

use url::Url;

use super::{MainDbParams, redact_url};

fn redacted(raw: &str) -> String {
    redact_url(&Url::parse(raw).unwrap()).to_string()
}

#[test]
fn characterization_redact_url_user_and_password() {
    assert_eq!(
        redacted("mysql://user:pass@host:3306/db"),
        "mysql://****:****@host:3306/db"
    );
}

#[test]
fn characterization_redact_url_user_only() {
    assert_eq!(redacted("mysql://user@host/db"), "mysql://****@host/db");
}

#[test]
fn characterization_redact_url_password_only() {
    assert_eq!(redacted("mysql://:secret@host/db"), "mysql://:****@host/db");
}

#[test]
fn characterization_redact_url_no_credentials() {
    assert_eq!(redacted("mysql://host:3306/db"), "mysql://host:3306/db");
}

#[test]
fn characterization_redact_url_keeps_query_and_path() {
    assert_eq!(
        redacted("redis://u:p@localhost:6379/0?timeout=5"),
        "redis://****:****@localhost:6379/0?timeout=5"
    );
}

#[test]
fn characterization_redact_url_does_not_mutate_original() {
    let original = Url::parse("mysql://user:pass@host/db").unwrap();
    let masked = redact_url(&original);
    assert_eq!(original.username(), "user");
    assert_eq!(original.password(), Some("pass"));
    assert_eq!(masked.username(), "****");
    assert_eq!(masked.password(), Some("****"));
}

#[test]
fn characterization_main_db_params_display_masks_credentials() {
    let mysql = MainDbParams::Mysql(Url::parse("mysql://user:pass@host:3306/db").unwrap(), None);
    assert_eq!(mysql.to_string(), "mysql: mysql://****:****@host:3306/db");
    assert_eq!(
        format!("{mysql:?}"),
        "mysql: mysql://****:****@host:3306/db"
    );

    let postgres = MainDbParams::Postgres("postgresql://user:pass@host/db".to_owned(), Some(4));
    assert_eq!(
        postgres.to_string(),
        "postgres: postgresql://****:****@host/db"
    );

    let sqlite = MainDbParams::Sqlite(PathBuf::from("/tmp/kms"), None);
    assert_eq!(sqlite.to_string(), "sqlite: /tmp/kms");
}

#[test]
fn characterization_main_db_params_db_name() {
    assert_eq!(
        MainDbParams::Sqlite(PathBuf::from("/tmp/kms"), None).db_name(),
        "Sqlite"
    );
    assert_eq!(
        MainDbParams::Postgres(String::new(), None).db_name(),
        "PostgreSQL"
    );
    assert_eq!(
        MainDbParams::Mysql(Url::parse("mysql://h/db").unwrap(), None).db_name(),
        "MySql/MariaDB"
    );
}

#[cfg(feature = "non-fips")]
#[test]
fn characterization_main_db_params_display_redis_masks_credentials() {
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::{FixedSizeCBytes, SymmetricKey};

    let key = SymmetricKey::try_from_bytes([0_u8; 32]).unwrap();
    let redis =
        MainDbParams::RedisFindex(Url::parse("redis://user:pass@host:6379/0").unwrap(), key);
    assert_eq!(
        redis.to_string(),
        "redis-findex: redis://****:****@host:6379/0, master key: [****]"
    );
    assert_eq!(redis.db_name(), "Redis-Findex");
}
