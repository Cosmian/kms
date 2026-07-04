#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_in_result
)]
use std::path::Path;

use cosmian_logger::{log_init, reexport::tracing};
use tempfile::TempDir;

use self::{
    database_tests::{crud, tx_and_list, upsert},
    find_attributes_test::find_attributes,
    json_access_test::json_access,
    owner_test::owner,
    permissions_test::permissions,
    tagging_tests::tags,
};
#[cfg(feature = "non-fips")]
use crate::stores::RedisWithFindex;
#[cfg(feature = "non-fips")]
use crate::stores::additional_redis_findex_tests::{
    test_active_key_count_counter, test_corner_case, test_live_count_counter, test_objects_db,
    test_permissions_db,
};
use crate::{
    error::{DbError, DbResult},
    stores::{MySqlPool, PgPool, SqlitePool},
    tests::{
        database_tests::{
            atomic, block_cipher_mode_migration_after_json_deserialization,
            find_due_for_rotation_test,
        },
        list_uids_for_tags_test::list_uids_for_tags_test,
    },
};

mod database_tests;
mod find_attributes_test;
mod json_access_test;
mod list_uids_for_tags_test;
mod owner_test;
mod permissions_test;
mod tagging_tests;

#[cfg(feature = "non-fips")]
pub(crate) fn get_redis_url() -> String {
    std::env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    )
}

async fn get_sqlite(db_file: &Path) -> DbResult<SqlitePool> {
    SqlitePool::instantiate(db_file, true, None).await
}

// To run local tests with a Postgres in Docker, run
// docker run --name postgres -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432  -d postgres
async fn get_pgsql() -> DbResult<PgPool> {
    let postgres_url =
        option_env!("KMS_POSTGRES_URL").unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms");
    let pg = PgPool::instantiate(postgres_url, true, None).await?;
    Ok(pg)
}

// To run local tests with a MariaDB in Docker, run
// docker run --name mariadb --env MARIADB_DATABASE=kms  --env MARIADB_USER=kms --env MARIADB_PASSWORD=kms --env MARIADB_ROOT_PASSWORD=cosmian -p 3306:3306 -d mariadb
// docker run --name mysql --env MYSQL_DATABASE=kms  --env MYSQL_USER=kms --env MYSQL_PASSWORD=kms --env MYSQL_ROOT_PASSWORD=cosmian -p 3306:3306 -d mysql:8.0.42
async fn get_mysql() -> DbResult<MySqlPool> {
    let mysql_url = option_env!("KMS_MYSQL_URL").unwrap_or("mysql://kms:kms@localhost:3306/kms");
    let my_sql = MySqlPool::instantiate(mysql_url, true, None).await?;
    Ok(my_sql)
}

// To run local tests with a Redis in Docker (and local storage - needed for transactions), run
// docker run --name redis -p 6379:6379 -d redis redis-server --save 60 1 --loglevel verbose
#[cfg(feature = "non-fips")]
async fn get_redis_with_findex() -> DbResult<RedisWithFindex> {
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
        CsRng, Secret, reexport::rand_core::SeedableRng,
    };

    use crate::stores::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;
    let mut rng = CsRng::from_entropy();

    let redis_url = get_redis_url();
    let redis_url = option_env!("KMS_REDIS_URL").unwrap_or(&redis_url);
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
    let redis_findex = RedisWithFindex::instantiate(redis_url, master_key, true).await?;
    Ok(redis_findex)
}

#[ignore = "Requires a running Redis instance"]
#[allow(clippy::large_stack_frames)] // This a test, we can skip this as long as test machines can handle such a stack
#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_db_redis_with_findex() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    test_objects_db().await?;
    test_permissions_db().await?;
    test_corner_case().await?;
    test_live_count_counter().await?;
    test_active_key_count_counter().await?;
    Box::pin(json_access(&get_redis_with_findex().await?)).await?;
    find_attributes(&get_redis_with_findex().await?).await?;
    owner(&get_redis_with_findex().await?).await?;
    permissions(&get_redis_with_findex().await?).await?;
    Box::pin(tags(&get_redis_with_findex().await?, false)).await?;
    tx_and_list(&get_redis_with_findex().await?).await?;
    Box::pin(atomic(&get_redis_with_findex().await?)).await?;
    upsert(&get_redis_with_findex().await?).await?;
    crud(&get_redis_with_findex().await?).await?;
    list_uids_for_tags_test(&get_redis_with_findex().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_redis_with_findex().await?).await?;
    find_due_for_rotation_test(&get_redis_with_findex().await?).await?;
    Ok(())
}

/// Run the tests with a `SQLite` database.
/// For additional logging, run the tests with
/// ```Rust
/// log_init(Some(
///     "info,cosmian_kms_server=trace,cosmian_kms_server_database=trace,\
///      cosmian_kms_interfaces=trace",
/// ));
/// ```
#[tokio::test]
pub(crate) async fn test_db_sqlite() -> DbResult<()> {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("info"));
    let dir = TempDir::new()?;
    let db_file = dir.path().join("test_sqlite.db");
    if db_file.exists() {
        std::fs::remove_file(&db_file)?;
    }
    Box::pin(json_access(&get_sqlite(&db_file).await?)).await?;
    find_attributes(&get_sqlite(&db_file).await?).await?;
    owner(&get_sqlite(&db_file).await?).await?;
    permissions(&get_sqlite(&db_file).await?).await?;
    Box::pin(tags(&get_sqlite(&db_file).await?, true)).await?;
    tx_and_list(&get_sqlite(&db_file).await?).await?;
    Box::pin(atomic(&get_sqlite(&db_file).await?)).await?;
    upsert(&get_sqlite(&db_file).await?).await?;
    crud(&get_sqlite(&db_file).await?).await?;
    list_uids_for_tags_test(&get_sqlite(&db_file).await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_sqlite(&db_file).await?).await?;
    find_due_for_rotation_test(&get_sqlite(&db_file).await?).await?;
    Ok(())
}

#[ignore = "Requires a running PostgreSQL instance"]
#[tokio::test]
pub(crate) async fn test_db_postgresql() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("trace"));
    Box::pin(json_access(&get_pgsql().await?)).await?;
    find_attributes(&get_pgsql().await?).await?;
    owner(&get_pgsql().await?).await?;
    permissions(&get_pgsql().await?).await?;
    Box::pin(tags(&get_pgsql().await?, true)).await?;
    tx_and_list(&get_pgsql().await?).await?;
    Box::pin(atomic(&get_pgsql().await?)).await?;
    upsert(&get_pgsql().await?).await?;
    crud(&get_pgsql().await?).await?;
    list_uids_for_tags_test(&get_pgsql().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_pgsql().await?).await?;
    find_due_for_rotation_test(&get_pgsql().await?).await?;
    Ok(())
}

// Multi-host PostgreSQL tests — require two running PostgreSQL instances:
//   Port 5432: docker run --name pg1 -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432 -d postgres
//   Port 5433: docker run --name pg2 -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5433:5432 -d postgres
async fn get_pgsql_multihost() -> DbResult<PgPool> {
    let url = option_env!("KMS_POSTGRES_MULTIHOST_URL").unwrap_or(
        "postgresql://kms:kms@127.0.0.1:5432,127.0.0.1:5433/kms?target_session_attrs=read-write",
    );
    PgPool::instantiate(url, true, None).await
}

#[ignore = "Requires two running PostgreSQL instances on ports 5432 and 5433. \
             Must not run concurrently with test_db_postgresql (shared DB on port 5432)."]
#[tokio::test]
pub(crate) async fn test_db_postgresql_multihost() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    // Verify that a multi-host connection string with target_session_attrs works
    let pg = get_pgsql_multihost().await?;
    crud(&pg).await?;
    Box::pin(atomic(&pg)).await?;
    upsert(&pg).await?;
    Ok(())
}

/// `PostgreSQL` failover retry test.
///
/// Verifies that when one node in a multi-host `PostgreSQL` cluster goes down, the
/// `pg_retry!` and `pg_retry_tx!` macros detect the connection-level error,
/// **discard** the stale pool connection, and successfully complete the operation
/// via the surviving node.
///
/// # Setup
/// This test is orchestrated by the MISE task `test:db:psql`.  Run it with:
/// ```bash
/// mise run test:db:psql
/// ```
/// The MISE task starts the `pg-failover` Docker Compose profile (containers
/// **pg1** on port 5434 and **pg2** on port 5435), then coordinates the pg1
/// stop/restart via two signal files whose paths it exports as:
/// - `KMS_PG_FAILOVER_READY_FILE` — the test writes this when the pool is warm
/// - `KMS_PG_FAILOVER_STOP_FILE`  — the MISE task writes this after stopping pg1
///
/// If neither env var is set the test returns `Ok(())` immediately (silently
/// skipped when running under `check_and_test_db`).
///
/// # How the test works
/// 1. Initialises the schema on both nodes independently (simulates streaming
///    replication in a real HA setup).
/// 2. Opens a dual-host pool and runs `crud()` while both nodes are up.
/// 3. Signals readiness → waits for the external stop signal.
/// 4. Re-runs `crud()` + `tx_and_list()` through the same pool.  The pool
///    holds stale connections to pg1; the retry macros must detect the IO error,
///    discard the stale connections, and reconnect to pg2.
/// 5. Asserts success within a reasonable elapsed time.
///
/// The test uses `target_session_attrs=any` so two completely independent
/// (non-replicated) `PostgreSQL` instances satisfy the connection requirements.
#[ignore = "Orchestrated by `mise run test:db:psql` (requires the pg-failover \
             Docker Compose profile and the KMS_PG_FAILOVER_* signal-file env vars)."]
#[tokio::test]
pub(crate) async fn test_db_postgresql_failover() -> DbResult<()> {
    log_init(Some("warn,cosmian_kms_server_database=warn"));

    // ── Guard: skip unless orchestrated by the MISE task ─────────────────────
    // The MISE psql task sets KMS_PG_FAILOVER_READY_FILE before running this
    // test.  When absent (e.g. called by check_and_test_db with only the
    // standard test_db_postgresql filter), we return Ok to avoid hanging.
    let ready_file = {
        let Ok(p) = std::env::var("KMS_PG_FAILOVER_READY_FILE") else {
            tracing::info!(
                "test_db_postgresql_failover: KMS_PG_FAILOVER_READY_FILE not set — skipped"
            );
            return Ok(());
        };
        p
    };
    let stop_file = std::env::var("KMS_PG_FAILOVER_STOP_FILE")
        .map_err(|e| DbError::ServerError(format!("KMS_PG_FAILOVER_STOP_FILE must be set: {e}")))?;

    // ── URL configuration ─────────────────────────────────────────────────────
    // Default ports match the docker-compose pg-failover profile (5434/5435).
    let pg1_url = option_env!("KMS_PG_FAILOVER_PRIMARY_URL")
        .unwrap_or("postgresql://kms:kms@127.0.0.1:5434/kms");
    let pg2_url = option_env!("KMS_PG_FAILOVER_SECONDARY_URL")
        .unwrap_or("postgresql://kms:kms@127.0.0.1:5435/kms");
    let multihost_url = option_env!("KMS_PG_FAILOVER_MULTIHOST_URL").unwrap_or(
        "postgresql://kms:kms@127.0.0.1:5434,127.0.0.1:5435/kms?target_session_attrs=any",
    );

    // ── Schema initialisation ─────────────────────────────────────────────────
    // pg1 (port 5434) — will be stopped to simulate a primary failure.
    PgPool::instantiate(pg1_url, true, None).await?;
    // pg2 (port 5435) — the surviving node the pool must fail over to.
    PgPool::instantiate(pg2_url, true, None).await?;

    // ── Pool setup ────────────────────────────────────────────────────────────
    let pg = PgPool::instantiate(multihost_url, false, None).await?;

    // ── Baseline: both nodes up ───────────────────────────────────────────────
    // Warm up the pool: creates a connection to pg1 (first host in the URL).
    crud(&pg).await?;

    // ── Signal readiness to the MISE orchestrator ─────────────────────────────
    std::fs::write(&ready_file, b"")
        .map_err(|e| DbError::ServerError(format!("write ready-file {ready_file}: {e}")))?;

    // ── Wait for the MISE orchestrator to stop pg1 ────────────────────────────
    // The orchestrator runs `docker stop pg1` then writes to stop_file.
    // We poll using spawn_blocking to avoid blocking the async runtime.
    let stop_file_clone = stop_file.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !Path::new(&stop_file_clone).exists() {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timed out (60s) waiting for stop signal at {stop_file_clone}"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    })
    .await
    .map_err(|e| DbError::ServerError(format!("spawn_blocking join: {e}")))?
    .map_err(DbError::ServerError)?;

    // No grace period: RecyclingMethod::Verified detects dead connections during
    // pool.get() itself (via simple_query("")) — no sleep needed before the
    // failover operations.

    // ── Failover: operations MUST succeed via pg2 ─────────────────────────────
    let before = std::time::Instant::now();

    // create() → pg_retry_tx! (transactional retry path)
    crud(&pg).await?;
    // retrieve() / find() → pg_retry! (non-transactional retry path)
    Box::pin(tx_and_list(&pg)).await?;

    let elapsed = before.elapsed();

    // ── Assertions ────────────────────────────────────────────────────────────
    if elapsed >= std::time::Duration::from_secs(5) {
        return Err(DbError::ServerError(format!(
            "Expected failover to complete within 5s but took {elapsed:?}"
        )));
    }

    Ok(())
}

#[ignore = "Requires a running MySQL or MariaDB instance"]
#[tokio::test]
pub(crate) async fn test_db_mysql() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    Box::pin(json_access(&get_mysql().await?)).await?;
    find_attributes(&get_mysql().await?).await?;
    owner(&get_mysql().await?).await?;
    permissions(&get_mysql().await?).await?;
    Box::pin(tags(&get_mysql().await?, true)).await?;
    tx_and_list(&get_mysql().await?).await?;
    Box::pin(atomic(&get_mysql().await?)).await?;
    upsert(&get_mysql().await?).await?;
    crud(&get_mysql().await?).await?;
    list_uids_for_tags_test(&get_mysql().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_mysql().await?).await?;
    find_due_for_rotation_test(&get_mysql().await?).await?;
    Ok(())
}
