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
    test_permissions_db, test_wrapped_by_backfill,
};
use crate::{
    error::{DbError, DbResult},
    stores::{MySqlPool, PgPool, SqlitePool},
    tests::{
        database_tests::{
            atomic, block_cipher_mode_migration_after_json_deserialization,
            find_due_for_rotation_test, wrapping_key_link_test,
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
    test_wrapped_by_backfill().await?;
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
    Box::pin(wrapping_key_link_test(&get_redis_with_findex().await?)).await?;
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
    Box::pin(wrapping_key_link_test(&get_sqlite(&db_file).await?)).await?;
    Ok(())
}

/// Faithful migration test: build a **legacy** `SQLite` database whose `objects`
/// table predates the `wrapping_key_id` column, insert a wrapped object row by
/// hand, then open it with the current [`SqlitePool`]. Opening must add the
/// column, create its index and backfill the wrapping-key link so the object
/// becomes discoverable through `find_wrapped_by`.
#[tokio::test]
async fn test_sqlite_wrapping_key_id_backfill_migration() -> DbResult<()> {
    use std::collections::HashSet;

    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes, kmip_objects::Object, kmip_types::CryptographicAlgorithm,
        },
    };
    use cosmian_kms_interfaces::{ObjectsStore, UserId};
    use uuid::Uuid;

    log_init(Some("info"));
    let dir = TempDir::new()?;
    let db_file = dir.path().join("legacy_sqlite.db");

    let owner = "legacy_owner";
    let wrapping_key_uid = "legacy_wrapping_key";
    let wrapped_uid = Uuid::new_v4().to_string();

    // Serialize a wrapped object exactly as the database stores it.
    let wrapped_obj: Object = serde_json::from_value(serde_json::json!({
        "SymmetricKey": {
            "KeyBlock": {
                "KeyFormatType": "TransparentSymmetricKey",
                "CryptographicAlgorithm": "AES",
                "CryptographicLength": 256,
                "KeyWrappingData": {
                    "WrappingMethod": "Encrypt",
                    "EncryptionKeyInformation": { "UniqueIdentifier": wrapping_key_uid },
                    "EncodingOption": "TTLVEncoding"
                }
            }
        }
    }))
    .map_err(|e| DbError::ServerError(format!("failed to build wrapped object: {e}")))?;
    let object_json =
        serde_json::to_string(&wrapped_obj).map_err(|e| DbError::ServerError(e.to_string()))?;
    let attributes_json = serde_json::to_string(&Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        ..Default::default()
    })
    .map_err(|e| DbError::ServerError(e.to_string()))?;

    // ── Create a legacy-schema database (objects table WITHOUT wrapping_key_id) ──
    {
        let conn = rusqlite::Connection::open(&db_file)
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE objects (
                 id VARCHAR(128) PRIMARY KEY,
                 object VARCHAR NOT NULL,
                 attributes jsonb NOT NULL,
                 state VARCHAR(32),
                 owner VARCHAR(255)
             );",
        )
        .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        conn.execute(
            "INSERT INTO objects (id, object, attributes, state, owner) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![wrapped_uid, object_json, attributes_json, "Active", owner],
        )
        .map_err(|e| DbError::DatabaseError(e.to_string()))?;
    } // raw connection is dropped/closed here

    // ── Open with the current backend → triggers the column add + backfill ──
    let pool = SqlitePool::instantiate(&db_file, false, None).await?;

    // The pre-existing wrapped object must now be discoverable by its wrapping key.
    let found = pool
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    let found_uids: HashSet<&str> = found.iter().map(|(uid, _, _)| uid.as_str()).collect();
    if !found_uids.contains(wrapped_uid.as_str()) {
        return Err(DbError::ServerError(format!(
            "backfill migration: wrapped object '{wrapped_uid}' should be discoverable via \
             find_wrapped_by after migration, got: {found_uids:?}"
        )));
    }

    // Re-opening must be a no-op (marker set): the object stays discoverable.
    let pool2 = SqlitePool::instantiate(&db_file, false, None).await?;
    let found2 = pool2
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    if found2.iter().all(|(uid, _, _)| uid != &wrapped_uid) {
        return Err(DbError::ServerError(
            "backfill migration: wrapped object lost after re-opening the database".to_owned(),
        ));
    }

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
    Box::pin(wrapping_key_link_test(&get_pgsql().await?)).await?;
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

#[ignore = "Requires a running PostgreSQL instance"]
#[tokio::test]
pub(crate) async fn test_db_postgresql_state_monotonic_merge() -> DbResult<()> {
    use std::collections::HashSet;

    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
            kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
        },
    };
    use cosmian_kms_interfaces::{AtomicOperation, ObjectsStore, UserId};
    use uuid::Uuid;

    log_init(option_env!("RUST_LOG"));
    let pg = get_pgsql().await?;
    let owner = UserId::from("state_merge_test_user");
    let sym_key_bytes = [0_u8; 32];
    let key_obj = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &sym_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )
    .map_err(|e| DbError::DatabaseError(e.to_string()))?;

    let uid_a = Uuid::new_v4().to_string();
    let uid_b = Uuid::new_v4().to_string();

    pg.atomic(
        &owner,
        &[
            AtomicOperation::Create((
                uid_a.clone(),
                owner.clone(),
                key_obj.clone(),
                Attributes::default(),
                HashSet::new(),
            )),
            AtomicOperation::Create((
                uid_b.clone(),
                owner.clone(),
                key_obj.clone(),
                Attributes::default(),
                HashSet::new(),
            )),
        ],
    )
    .await?;

    // Ordering 1: local already Destroyed; a replicated write tries to arrive at Deactivated.
    pg.update_state(&uid_a, State::Destroyed).await?;
    // Local write attempt to downgrade: blocked by ENABLE ALWAYS trigger
    pg.update_state(&uid_a, State::Deactivated).await?;
    let (state_a1, _) = pg.retrieve_state(&uid_a).await?.expect("object exists");
    if state_a1 != State::Destroyed {
        return Err(DbError::ServerError(format!(
            "Expected state_a1 to be Destroyed, got {state_a1:?}"
        )));
    }

    // Replicated write attempt to downgrade: also coerced
    {
        let client = pg.raw_pool().get().await.map_err(DbError::from)?;
        client
            .batch_execute("SET session_replication_role = 'replica';")
            .await
            .map_err(DbError::from)?;
        client
            .execute(
                "UPDATE objects SET state = $1 WHERE id = $2",
                &[&"Deactivated", &uid_a],
            )
            .await
            .map_err(DbError::from)?;
        client
            .batch_execute("SET session_replication_role = 'origin';")
            .await
            .map_err(DbError::from)?;
    }
    let (state_a2, _) = pg.retrieve_state(&uid_a).await?.expect("object exists");
    if state_a2 != State::Destroyed {
        return Err(DbError::ServerError(format!(
            "Expected state_a2 to be Destroyed, got {state_a2:?}"
        )));
    }

    // Ordering 2 (reversed): local Deactivated; replicated write carries the higher-rank Destroyed.
    pg.update_state(&uid_b, State::Deactivated).await?;
    {
        let client = pg.raw_pool().get().await.map_err(DbError::from)?;
        client
            .batch_execute("SET session_replication_role = 'replica';")
            .await
            .map_err(DbError::from)?;
        client
            .execute(
                "UPDATE objects SET state = $1 WHERE id = $2",
                &[&"Destroyed", &uid_b],
            )
            .await
            .map_err(DbError::from)?;
        client
            .batch_execute("SET session_replication_role = 'origin';")
            .await
            .map_err(DbError::from)?;
    }
    let (state_b, _) = pg.retrieve_state(&uid_b).await?.expect("object exists");
    if state_b != State::Destroyed {
        return Err(DbError::ServerError(format!(
            "Expected state_b to be Destroyed, got {state_b:?}"
        )));
    }

    // Regression guard: explicit KMIP batch UNDO backward transition using
    // update_state_allow_downgrade bypass succeeds.
    pg.update_state_allow_downgrade(&uid_b, State::PreActive)
        .await?;
    let (state_b2, _) = pg.retrieve_state(&uid_b).await?.expect("object exists");
    if state_b2 != State::PreActive {
        return Err(DbError::ServerError(format!(
            "Expected state_b2 to be PreActive, got {state_b2:?}"
        )));
    }

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

#[ignore = "Orchestrated by `mise run test:db:pgedge` (requires the pgedge Docker Compose profile)."]
#[tokio::test]
pub(crate) async fn test_db_pgedge_active_active() -> DbResult<()> {
    use std::{collections::HashSet, time::Duration};

    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation, extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
            kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
        },
    };
    use cosmian_kms_interfaces::{AtomicOperation, ObjectsStore, PermissionsStore, UserId};
    use uuid::Uuid;

    log_init(option_env!("RUST_LOG"));

    let url1 = std::env::var("KMS_PGEDGE_1_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6432/kms".to_owned());
    let url2 = std::env::var("KMS_PGEDGE_2_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6433/kms".to_owned());

    // Instantiate PgPool on both nodes: creates KMS schema, PK migrations, and monotonic trigger
    let pg1 = PgPool::instantiate(&url1, true, None).await?;
    let pg2 = PgPool::instantiate(&url2, true, None).await?;

    // Wire Spock logical multi-master replication on both nodes (idempotent setup)
    {
        let c1 = pg1.raw_pool().get().await.map_err(DbError::from)?;
        c1.batch_execute("CREATE EXTENSION IF NOT EXISTS spock;")
            .await
            .map_err(DbError::from)?;
        let n1_exists: bool = c1
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.node WHERE node_name = 'n1');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !n1_exists {
            c1.batch_execute(
                "SELECT spock.node_create(node_name := 'n1', dsn := 'host=pgedge1 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c1.batch_execute("SELECT spock.repset_add_all_tables('default', ARRAY['public']);")
            .await
            .map_err(DbError::from)?;
    }

    {
        let c2 = pg2.raw_pool().get().await.map_err(DbError::from)?;
        c2.batch_execute("CREATE EXTENSION IF NOT EXISTS spock;")
            .await
            .map_err(DbError::from)?;
        let n2_exists: bool = c2
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.node WHERE node_name = 'n2');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !n2_exists {
            c2.batch_execute(
                "SELECT spock.node_create(node_name := 'n2', dsn := 'host=pgedge2 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c2.batch_execute("SELECT spock.repset_add_all_tables('default', ARRAY['public']);")
            .await
            .map_err(DbError::from)?;
    }

    // Create subscriptions and wait for initial sync
    {
        let c1 = pg1.raw_pool().get().await.map_err(DbError::from)?;
        let sub1_exists: bool = c1
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.subscription WHERE sub_name = 'sub_n1_n2');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !sub1_exists {
            c1.batch_execute(
                "SELECT spock.sub_create(subscription_name := 'sub_n1_n2', provider_dsn := 'host=pgedge2 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c1.batch_execute("SELECT spock.sub_wait_for_sync('sub_n1_n2');")
            .await
            .map_err(DbError::from)?;
    }

    {
        let c2 = pg2.raw_pool().get().await.map_err(DbError::from)?;
        let sub2_exists: bool = c2
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.subscription WHERE sub_name = 'sub_n2_n1');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !sub2_exists {
            c2.batch_execute(
                "SELECT spock.sub_create(subscription_name := 'sub_n2_n1', provider_dsn := 'host=pgedge1 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c2.batch_execute("SELECT spock.sub_wait_for_sync('sub_n2_n1');")
            .await
            .map_err(DbError::from)?;
    }

    // Prepare test objects
    let owner = UserId::from("pgedge_test_user");
    let sym_key_bytes = [0_u8; 32];
    let key_obj = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &sym_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )
    .map_err(|e| DbError::DatabaseError(e.to_string()))?;

    let uid_1 = Uuid::new_v4().to_string();
    let uid_2 = Uuid::new_v4().to_string();

    pg1.atomic(
        &owner,
        &[
            AtomicOperation::Create((
                uid_1.clone(),
                owner.clone(),
                key_obj.clone(),
                Attributes::default(),
                HashSet::new(),
            )),
            AtomicOperation::Create((
                uid_2.clone(),
                owner.clone(),
                key_obj.clone(),
                Attributes::default(),
                HashSet::new(),
            )),
        ],
    )
    .await?;

    // Wait for initial object replication to arrive on pg2
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if pg2.retrieve_state(&uid_1).await?.is_some()
                && pg2.retrieve_state(&uid_2).await?.is_some()
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DbError::ServerError(
                    "Timed out waiting for initial objects to replicate from pg1 to pg2".to_owned(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    // State convergence Ordering 1:
    // pg1 writes Destroyed; pg2 writes Deactivated on same object
    pg1.update_state(&uid_1, State::Destroyed).await?;
    pg2.update_state(&uid_1, State::Deactivated).await?;

    // State convergence Ordering 2:
    // pg2 writes Destroyed; pg1 writes Deactivated on same object
    pg2.update_state(&uid_2, State::Destroyed).await?;
    pg1.update_state(&uid_2, State::Deactivated).await?;

    // Poll both nodes until convergence for both objects
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let s1_on_pg1 = pg1.retrieve_state(&uid_1).await?.map(|(s, _)| s);
            let s1_on_pg2 = pg2.retrieve_state(&uid_1).await?.map(|(s, _)| s);
            let s2_on_pg1 = pg1.retrieve_state(&uid_2).await?.map(|(s, _)| s);
            let s2_on_pg2 = pg2.retrieve_state(&uid_2).await?.map(|(s, _)| s);
            if s1_on_pg1 == Some(State::Destroyed)
                && s1_on_pg2 == Some(State::Destroyed)
                && s2_on_pg1 == Some(State::Destroyed)
                && s2_on_pg2 == Some(State::Destroyed)
            {
                break;
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(DbError::ServerError(format!(
                    "Timed out waiting for state convergence to Destroyed. uid_1: (pg1={s1_on_pg1:?}, pg2={s1_on_pg2:?}), uid_2: (pg1={s2_on_pg1:?}, pg2={s2_on_pg2:?})"
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    // Grant/revoke convergence (documented LWW limitation)
    let alice = UserId::from("alice");
    // First create a permission row for alice on uid_1 on pg1 and wait for it to replicate
    pg1.grant_operations(&uid_1, &alice, HashSet::from([KmipOperation::Get]))
        .await?;
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let r2 = pg2
                .list_user_operations_on_object(&uid_1, &alice, false)
                .await?;
            if r2.contains(&KmipOperation::Get) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DbError::ServerError(
                    "Timed out waiting for initial grant to replicate from pg1 to pg2".to_owned(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    // Concurrently revoke on pg2 and grant additional operations on pg1
    pg2.remove_operations(&uid_1, &alice, HashSet::from([KmipOperation::Get]))
        .await?;
    pg1.grant_operations(&uid_1, &alice, HashSet::from([KmipOperation::Encrypt]))
        .await?;

    // Poll until read_access converges to the same state on both nodes
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let perm1 = pg1
                .list_user_operations_on_object(&uid_1, &alice, false)
                .await?;
            let perm2 = pg2
                .list_user_operations_on_object(&uid_1, &alice, false)
                .await?;

            if perm1 == perm2 {
                // Both nodes agreed (converged)
                break;
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(DbError::ServerError(format!(
                    "Timed out waiting for read_access convergence. pg1={perm1:?}, pg2={perm2:?}"
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
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
    Box::pin(wrapping_key_link_test(&get_mysql().await?)).await?;
    Ok(())
}
