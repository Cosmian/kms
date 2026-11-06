use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore, UserId};
use rusqlite::{Connection, types::Value};
use tempfile::TempDir;

use crate::{
    db_ensure, db_error,
    error::DbResult,
    stores::{
        SqlitePool,
        migrate::{
            CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM, DbParameters, DbState, Migrate,
            MigrationStep::{self, CertificateSerialTagBackfill, WrappingKeyIdBackfill},
            WRAPPING_KEY_BACKFILL_PARAM,
        },
    },
};

const TARGET: &str = "5.29.0";
const BOTH_STEPS: [MigrationStep; 2] = [WrappingKeyIdBackfill, CertificateSerialTagBackfill];
type TableRows = Vec<Vec<Value>>;

fn copy_fixture(version: &str) -> DbResult<(TempDir, PathBuf)> {
    cosmian_logger::log_init(Some("info"));
    let directory = TempDir::new()?;
    let path = directory.path().join("kms.db");
    let source = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test_data/db_migration"
    ))
    .join(version)
    .join("sqlite/kms.db");
    fs::copy(source, &path)?;
    Ok((directory, path))
}

fn query_rows(path: &Path, sql: &str) -> DbResult<TableRows> {
    let connection = Connection::open(path)?;
    let mut statement = connection.prepare(sql)?;
    let columns = statement.column_count();
    let rows = statement.query_map([], |row| {
        (0..columns).map(|column| row.get(column)).collect()
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn preserved_data(path: &Path) -> DbResult<[TableRows; 3]> {
    Ok([
        query_rows(
            path,
            "SELECT id, object, attributes, state, owner FROM objects ORDER BY id",
        )?,
        query_rows(
            path,
            "SELECT id, tag FROM tags WHERE tag NOT GLOB '_serial=*' ORDER BY id, tag",
        )?,
        query_rows(
            path,
            "SELECT id, userid, permissions FROM read_access ORDER BY id, userid",
        )?,
    ])
}

fn complete_data(path: &Path) -> DbResult<[TableRows; 4]> {
    Ok([
        query_rows(path, "SELECT * FROM objects ORDER BY id")?,
        query_rows(path, "SELECT * FROM tags ORDER BY id, tag")?,
        query_rows(path, "SELECT * FROM read_access ORDER BY id, userid")?,
        query_rows(path, "SELECT * FROM parameters ORDER BY name")?,
    ])
}

fn seed_parameters(path: &Path, parameters: &[(&str, &str)]) -> DbResult<()> {
    let connection = Connection::open(path)?;
    for (name, value) in parameters {
        connection.execute(
            "INSERT INTO parameters (name, value) VALUES (?1, ?2) \
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            [name, value],
        )?;
    }
    Ok(())
}

async fn assert_ready(pool: &SqlitePool, target: &str) -> DbResult<()> {
    let version = pool.get_db_version().await?;
    db_ensure!(
        version.as_deref() == Some(target),
        "Expected version {target}, got {version:?}"
    );
    let state = pool.get_db_state().await?;
    db_ensure!(
        state == Some(DbState::Ready),
        "Expected ready state, got {state:?}"
    );
    Ok(())
}

fn expect_steps(actual: &[MigrationStep], expected: &[MigrationStep]) -> DbResult<()> {
    db_ensure!(
        actual == expected,
        "Expected applied steps {expected:?}, got {actual:?}"
    );
    Ok(())
}

async fn assert_markers(pool: &SqlitePool, completed: &[MigrationStep]) -> DbResult<()> {
    for step in BOTH_STEPS {
        let actual = pool.get_parameter(step.marker()).await?;
        let expected = completed.contains(&step).then_some("true");
        db_ensure!(
            actual.as_deref() == expected,
            "Marker {}: expected {expected:?}, got {actual:?}",
            step.marker()
        );
    }
    Ok(())
}

fn assert_lock_released(path: &Path) -> DbResult<()> {
    let file = fs::File::options()
        .write(true)
        .open(path.with_file_name("kms.db.migration.lock"))?;
    file.try_lock().map_err(std::io::Error::from)?;
    Ok(())
}

async fn assert_fixture_preserved(
    pool: &SqlitePool,
    path: &Path,
    original: &[TableRows; 3],
) -> DbResult<()> {
    assert_lock_released(path)?;
    db_ensure!(
        &preserved_data(path)? == original,
        "Object payloads, states, original tags, or permissions changed"
    );
    let objects: Vec<(String, String)> = {
        let connection = Connection::open(path)?;
        let mut statement = connection.prepare("SELECT id, state FROM objects ORDER BY id")?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    db_ensure!(
        objects.len() == 8,
        "Expected eight fixture objects, got {}",
        objects.len()
    );
    for (id, state) in objects {
        let expected = if id == "mig_revoked" {
            "Deactivated"
        } else {
            "Active"
        };
        db_ensure!(
            state == expected,
            "Unexpected stored state for {id}: {state}"
        );
        let object = pool
            .retrieve(&id)
            .await?
            .ok_or_else(|| db_error!("Fixture object {id} could not be retrieved"))?;
        db_ensure!(
            object.owner() == "admin",
            "Fixture object {id} changed owner"
        );
        let expected = if id == "mig_revoked" {
            State::Deactivated
        } else {
            State::Active
        };
        db_ensure!(
            object.state() == expected,
            "Unexpected retrieved state for {id}: {:?}",
            object.state()
        );
        db_ensure!(
            pool.retrieve_tags(&id).await?.contains("mig"),
            "Fixture object {id} lost its tag"
        );
    }
    let expected = HashSet::from([
        KmipOperation::Get,
        KmipOperation::Encrypt,
        KmipOperation::Decrypt,
    ]);
    let grants = pool.list_object_operations_granted("mig_kek").await?;
    db_ensure!(
        grants.get("mig_user") == Some(&expected),
        "The mig_user permission grant changed"
    );
    Ok(())
}

async fn assert_wrapped_key_found(pool: &SqlitePool) -> DbResult<()> {
    let found = pool
        .find_wrapped_by("mig_kek", &UserId::from("admin"))
        .await?;
    let ids: Vec<_> = found.iter().map(|(id, _, _)| id.as_str()).collect();
    db_ensure!(ids == ["mig_wrapped"], "Expected mig_wrapped, got {ids:?}");
    Ok(())
}

async fn assert_serial_tag(pool: &SqlitePool, present: bool) -> DbResult<()> {
    let tags = pool.retrieve_tags("mig_cert").await?;
    let serial_tags: Vec<_> = tags
        .iter()
        .filter(|tag| tag.starts_with("_serial="))
        .collect();
    db_ensure!(
        serial_tags.len() == usize::from(present),
        "Expected serial tag present={present}, got {serial_tags:?}"
    );
    if let Some(tag) = serial_tags.first() {
        let serial = tag
            .strip_prefix("_serial=")
            .ok_or_else(|| db_error!("Missing certificate serial tag prefix"))?;
        db_ensure!(
            !serial.is_empty()
                && serial
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')),
            "Expected a nonempty uppercase hexadecimal serial tag"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_sqlite_migration_fresh() -> DbResult<()> {
    let directory = TempDir::new()?;
    let (pool, applied) = SqlitePool::instantiate_at_version(
        &directory.path().join("kms.db"),
        false,
        Some(1),
        env!("CARGO_PKG_VERSION"),
    )
    .await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        !pool.has_data().await?,
        "A fresh database must have no objects"
    );
    assert_lock_released(&directory.path().join("kms.db"))?;
    assert_ready(&pool, env!("CARGO_PKG_VERSION")).await?;
    assert_markers(&pool, &[]).await
}

#[tokio::test]
async fn test_sqlite_migration_unversioned_empty() -> DbResult<()> {
    let directory = TempDir::new()?;
    let path = directory.path().join("kms.db");
    let (pool, initial) =
        SqlitePool::instantiate_at_version(&path, true, Some(1), "5.20.0").await?;
    expect_steps(&initial, &[])?;
    drop(pool);
    Connection::open(&path)?.execute("DELETE FROM parameters WHERE name = 'db_version'", [])?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        !pool.has_data().await?,
        "Schema-only database must remain empty"
    );
    assert_markers(&pool, &[]).await?;
    assert_ready(&pool, TARGET).await
}

#[tokio::test]
async fn test_sqlite_migration_unversioned_with_data() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_step_by_step() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    let (pool, applied) =
        SqlitePool::instantiate_at_version(&path, false, Some(1), "5.24.0").await?;
    expect_steps(&applied, &[])?;
    assert_ready(&pool, "5.24.0").await?;
    assert_markers(&pool, &[]).await?;
    db_ensure!(
        pool.find_wrapped_by("mig_kek", &UserId::from("admin"))
            .await?
            .is_empty(),
        "The wrapping-key backfill must not run before 5.25.0"
    );
    assert_serial_tag(&pool, false).await?;
    assert_fixture_preserved(&pool, &path, &original).await?;

    expect_steps(
        &pool.bootstrap(false, "5.25.0").await?,
        &[WrappingKeyIdBackfill],
    )?;
    assert_ready(&pool, "5.25.0").await?;
    assert_markers(&pool, &[WrappingKeyIdBackfill]).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, false).await?;
    assert_fixture_preserved(&pool, &path, &original).await?;

    expect_steps(
        &pool.bootstrap(false, TARGET).await?,
        &[CertificateSerialTagBackfill],
    )?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_all_at_once_matches_step_by_step() -> DbResult<()> {
    let (_first_directory, first_path) = copy_fixture("5.20.0")?;
    let (_second_directory, second_path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&first_path)?;
    let (first, applied) =
        SqlitePool::instantiate_at_version(&first_path, false, Some(1), "5.24.0").await?;
    expect_steps(&applied, &[])?;
    expect_steps(
        &first.bootstrap(false, "5.25.0").await?,
        &[WrappingKeyIdBackfill],
    )?;
    expect_steps(
        &first.bootstrap(false, TARGET).await?,
        &[CertificateSerialTagBackfill],
    )?;
    let (second, applied) =
        SqlitePool::instantiate_at_version(&second_path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    db_ensure!(
        complete_data(&first_path)? == complete_data(&second_path)?,
        "Every row in objects, tags, read_access, and parameters must match"
    );
    assert_ready(&first, TARGET).await?;
    assert_ready(&second, TARGET).await?;
    assert_markers(&first, &BOTH_STEPS).await?;
    assert_markers(&second, &BOTH_STEPS).await?;
    assert_fixture_preserved(&first, &first_path, &original).await?;
    assert_fixture_preserved(&second, &second_path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_5_24_fixture() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.24.0")?;
    let original = preserved_data(&path)?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_5_28_fixture() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.28.0")?;
    let original = preserved_data(&path)?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &[CertificateSerialTagBackfill])?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_5_29_fixture() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.29.0")?;
    let original = preserved_data(&path)?;
    let [objects, tags, access, _] = complete_data(&path)?;
    let parameters = query_rows(
        &path,
        "SELECT name, value FROM parameters WHERE name NOT IN ('db_version', 'db_state') ORDER BY name",
    )?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(&pool, &path, &original).await?;
    let [after_objects, after_tags, after_access, _] = complete_data(&path)?;
    db_ensure!(
        objects == after_objects && tags == after_tags && access == after_access,
        "Opening a 5.29.0 fixture changed object, tag, or permission data"
    );
    db_ensure!(
        parameters
            == query_rows(
                &path,
                "SELECT name, value FROM parameters WHERE name NOT IN ('db_version', 'db_state') ORDER BY name",
            )?,
        "Opening a 5.29.0 fixture changed existing migration parameters"
    );
    Ok(())
}

#[tokio::test]
async fn test_sqlite_migration_markers_already_set() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    seed_parameters(
        &path,
        &[
            (WRAPPING_KEY_BACKFILL_PARAM, "true"),
            (CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM, "true"),
        ],
    )?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_serial_tag(&pool, false).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_newer_database_leaves_schema_untouched() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    seed_parameters(&path, &[("db_version", "99.0.0")])?;
    let schema = query_rows(&path, "SELECT * FROM sqlite_master ORDER BY type, name")?;
    let original_file = fs::read(&path)?;
    let wal = path.with_file_name("kms.db-wal");
    let shm = path.with_file_name("kms.db-shm");
    db_ensure!(
        !wal.try_exists()? && !shm.try_exists()?,
        "The original fixture must not have WAL sidecars"
    );
    let error = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET)
        .await
        .err()
        .ok_or_else(|| db_error!("A newer database must be refused"))?;
    db_ensure!(
        error.to_string()
            == "Database Error: Database version 99.0.0 is newer than this KMS server version \
         5.29.0: refusing to start. Upgrade the KMS server to 99.0.0 or later.",
        "Unexpected newer-version error: {error}"
    );
    db_ensure!(
        fs::read(&path)? == original_file,
        "Refusal changed the database file"
    );
    db_ensure!(
        !wal.try_exists()? && !shm.try_exists()?,
        "Refusal created WAL sidecars"
    );
    db_ensure!(
        schema == query_rows(&path, "SELECT * FROM sqlite_master ORDER BY type, name")?,
        "Refusal changed schema"
    );
    db_ensure!(
        original == preserved_data(&path)?,
        "Refusal changed fixture data"
    );
    assert_lock_released(&path)?;
    db_ensure!(
        query_rows(
            &path,
            "SELECT name FROM pragma_table_info('objects') WHERE name = 'wrapping_key_id'"
        )?
        .is_empty(),
        "Refusal added the wrapping_key_id column"
    );
    Ok(())
}

#[tokio::test]
async fn test_sqlite_migration_interrupted_run_resumes() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    seed_parameters(
        &path,
        &[("db_version", "5.24.0"), ("db_state", "\"upgrading\"")],
    )?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_below_baseline() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    seed_parameters(&path, &[("db_version", "5.14.0")])?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_clear_database() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    seed_parameters(&path, &[("db_version", "99.0.0")])?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, true, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(!pool.has_data().await?, "Clear left stored objects");
    db_ensure!(
        query_rows(&path, "SELECT * FROM objects")?.is_empty(),
        "Clear left objects"
    );
    db_ensure!(
        query_rows(&path, "SELECT * FROM tags")?.is_empty(),
        "Clear left tags"
    );
    db_ensure!(
        query_rows(&path, "SELECT * FROM read_access")?.is_empty(),
        "Clear left grants"
    );
    assert_ready(&pool, TARGET).await
}

#[tokio::test]
async fn test_sqlite_migration_concurrent_startup() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    let (first, second) = tokio::join!(
        SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET),
        SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET)
    );
    let (first, first_applied) = first?;
    let (second, second_applied) = second?;
    db_ensure!(
        (first_applied == BOTH_STEPS && second_applied.is_empty())
            || (second_applied == BOTH_STEPS && first_applied.is_empty()),
        "Exactly one pool must apply both steps: {first_applied:?}, {second_applied:?}"
    );
    assert_ready(&first, TARGET).await?;
    assert_ready(&second, TARGET).await?;
    assert_markers(&first, &BOTH_STEPS).await?;
    assert_markers(&second, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&first).await?;
    assert_serial_tag(&second, true).await?;
    assert_fixture_preserved(&first, &path, &original).await?;
    assert_fixture_preserved(&second, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_reopen_is_noop() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    let migrated = complete_data(&path)?;
    drop(pool);
    let (pool, applied) = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        migrated == complete_data(&path)?,
        "Reopening changed migrated rows"
    );
    assert_ready(&pool, TARGET).await?;
    assert_fixture_preserved(&pool, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_lock_blocks_second_pool() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    let (first, first_applied) =
        SqlitePool::instantiate_at_version(&path, false, Some(1), "5.24.0").await?;
    let (second, second_applied) =
        SqlitePool::instantiate_at_version(&path, false, Some(1), "5.24.0").await?;
    expect_steps(&first_applied, &[])?;
    expect_steps(&second_applied, &[])?;
    let held = first.acquire_migration_lock().await?;
    let error = tokio::time::timeout(Duration::from_millis(100), second.bootstrap(false, TARGET))
        .await
        .err()
        .ok_or_else(|| db_error!("A second pool must wait for the migration lock"))?;
    db_ensure!(
        error.to_string().contains("deadline has elapsed"),
        "Unexpected lock timeout: {error}"
    );
    drop(held);
    expect_steps(&second.bootstrap(false, TARGET).await?, &BOTH_STEPS)?;
    assert_ready(&second, TARGET).await?;
    assert_markers(&second, &BOTH_STEPS).await?;
    assert_fixture_preserved(&second, &path, &original).await
}

#[tokio::test]
async fn test_sqlite_migration_invalid_version_leaves_schema_untouched() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    seed_parameters(&path, &[("db_version", "not-a-version")])?;
    let schema = query_rows(&path, "SELECT * FROM sqlite_master ORDER BY type, name")?;
    let error = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET)
        .await
        .err()
        .ok_or_else(|| db_error!("An invalid database version must be refused"))?;
    db_ensure!(
        error.to_string().contains("not-a-version"),
        "Unexpected version error: {error}"
    );
    db_ensure!(
        schema == query_rows(&path, "SELECT * FROM sqlite_master ORDER BY type, name")?,
        "Invalid version changed schema"
    );
    db_ensure!(
        original == preserved_data(&path)?,
        "Invalid version changed data"
    );
    assert_lock_released(&path)?;
    Ok(())
}
