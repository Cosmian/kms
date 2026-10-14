//! Characterization tests pinning the BASE error behavior of the non-sqlite arms of
//! `Database::instantiate` when the server is unreachable (no live server needed).

use std::{collections::HashMap, num::NonZeroUsize, time::Duration};

use url::Url;

use super::{CacheParams, Database, MainDbParams};

/// The ONLY place that calls `Database::instantiate` (its signature changes upstream).
async fn instantiate_err(params: MainDbParams) -> String {
    Database::instantiate(
        &params,
        false,
        HashMap::new(),
        CacheParams {
            max_age: Duration::from_secs(1),
            max_size: NonZeroUsize::new(100).unwrap(),
            max_ttl: None,
            disabled: false,
        },
        None,
        None,
    )
    .await
    .err()
    .unwrap()
    .to_string()
}

#[tokio::test]
async fn characterization_instantiate_postgres_unreachable_returns_error() {
    let err = instantiate_err(MainDbParams::Postgres(
        "postgres://127.0.0.1:1/kms".to_owned(),
        Some(1),
    ))
    .await;
    assert_eq!(
        err,
        "Sql error: Error occurred while creating a new object: error connecting to server"
    );
}

#[tokio::test]
async fn characterization_instantiate_mysql_unreachable_returns_error() {
    let err = instantiate_err(MainDbParams::Mysql(
        Url::parse("mysql://user:pass@127.0.0.1:1/kms").unwrap(),
        Some(1),
    ))
    .await;
    // the errno suffix is OS specific (61 on macOS, 111 on Linux)
    assert!(
        err.starts_with("Sql error: Input/output error: Input/output error: Connection refused")
    );
}
