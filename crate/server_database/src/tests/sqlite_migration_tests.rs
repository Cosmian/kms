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
            DbParameters, DbState, Migrate,
            MigrationStep::{self, CertificateSerialTagBackfill, WrappingKeyIdBackfill},
        },
    },
};

const TARGET: &str = "5.29.0";
const BOTH_STEPS: [MigrationStep; 2] = [WrappingKeyIdBackfill, CertificateSerialTagBackfill];
type TableRows = Vec<Vec<Value>>;

fn copy_fixture(version: &str) -> DbResult<(TempDir, PathBuf)> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));
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
        query_rows(
            path,
            "SELECT id, object, attributes, state, owner, wrapping_key_id \
             FROM objects ORDER BY id",
        )?,
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

fn expected_state(id: &str) -> State {
    match id {
        "mig_revoked" => State::Deactivated,
        "bulk_preactive" => State::PreActive,
        "bulk_compromised" => State::Compromised,
        "bulk_destroyed" => State::Destroyed,
        _ => State::Active,
    }
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
        objects.len() == 32,
        "Expected 32 fixture objects, got {}",
        objects.len()
    );
    for (id, state) in objects {
        let want_state = expected_state(&id);
        db_ensure!(
            state == want_state.to_string(),
            "Unexpected stored state for {id}: {state}"
        );
        let tags = pool.retrieve_tags(&id).await?;
        if id == "junk_bad_json" || id == "junk_wrong_shape_json" {
            db_ensure!(
                pool.retrieve(&id).await.is_err(),
                "Corrupt fixture object {id} unexpectedly deserialized"
            );
            db_ensure!(tags.contains("junk"), "Junk object {id} lost its junk tag");
            continue;
        }
        let object = pool
            .retrieve(&id)
            .await?
            .ok_or_else(|| db_error!("Fixture object {id} could not be retrieved"))?;
        db_ensure!(
            object.owner() == "admin",
            "Fixture object {id} changed owner"
        );
        db_ensure!(
            object.state() == want_state,
            "Unexpected retrieved state for {id}: {:?}",
            object.state()
        );
        let expected_tag = if id.starts_with("junk_") {
            "junk"
        } else if id.starts_with("mig_") {
            "mig"
        } else if id.starts_with("bulk_") {
            "bulk"
        } else if tags.contains("mig") {
            "mig"
        } else {
            "bulk"
        };
        db_ensure!(
            tags.contains(expected_tag),
            "Fixture object {id} lost its {expected_tag} tag"
        );
    }
    let aes_256_tags = pool.retrieve_tags("bulk_aes_256").await?;
    for tag in ["bulk", "env:prod/eu", "émoji-🔐"] {
        db_ensure!(
            aes_256_tags.contains(tag),
            "bulk_aes_256 lost tag {tag}: {aes_256_tags:?}"
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
    let bulk_grants = pool.list_object_operations_granted("bulk_aes_256").await?;
    db_ensure!(
        bulk_grants.get("mig_user")
            == Some(&HashSet::from([
                KmipOperation::Encrypt,
                KmipOperation::Decrypt,
            ])),
        "The mig_user grant on bulk_aes_256 changed"
    );
    db_ensure!(
        bulk_grants.get("bulk_auditor")
            == Some(&HashSet::from([KmipOperation::Get, KmipOperation::Locate])),
        "The bulk_auditor grant on bulk_aes_256 changed"
    );
    Ok(())
}

async fn assert_wrapped_key_found(pool: &SqlitePool) -> DbResult<()> {
    for (kek, expected) in [
        ("mig_kek", &["bulk_sym_wrapped", "mig_wrapped"][..]),
        ("bulk_aes_256", &["bulk_wrapped_2"][..]),
        ("junk_missing_kek", &["junk_dangling_wrapped"][..]),
    ] {
        let found = pool.find_wrapped_by(kek, &UserId::from("admin")).await?;
        let mut ids: Vec<_> = found.iter().map(|(id, _, _)| id.as_str()).collect();
        ids.sort_unstable();
        db_ensure!(
            ids == expected,
            "For {kek}: expected {expected:?}, got {ids:?}"
        );
    }
    Ok(())
}

async fn assert_serial_tag(pool: &SqlitePool, present: bool) -> DbResult<()> {
    let mut seen_serials = HashSet::new();
    for cert_id in ["mig_cert", "bulk_cert_2"] {
        let tags = pool.retrieve_tags(cert_id).await?;
        let serial_tags: Vec<_> = tags
            .iter()
            .filter(|tag| tag.starts_with("_serial="))
            .collect();
        db_ensure!(
            serial_tags.len() == usize::from(present),
            "For {cert_id}: expected serial tag present={present}, got {serial_tags:?}"
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
                "Expected a nonempty uppercase hexadecimal serial tag for {cert_id}"
            );
            db_ensure!(
                seen_serials.insert(serial.to_owned()),
                "Duplicate certificate serial tag across fixture certificates: {serial}"
            );
        }
    }
    for junk_cert in [
        "junk_bad_json",
        "junk_bad_cert_der",
        "junk_non_cert_tagged_cert",
    ] {
        let tags = pool.retrieve_tags(junk_cert).await?;
        db_ensure!(
            !tags.iter().any(|tag| tag.starts_with("_serial=")),
            "Junk row {junk_cert} must not receive a _serial= tag: {tags:?}"
        );
    }
    Ok(())
}

/// A new database is stamped at once; an empty schema that lost its version is stamped again.
#[tokio::test]
async fn test_sqlite_migration_empty_database_is_stamped() -> DbResult<()> {
    let directory = TempDir::new()?;
    let path = directory.path().join("kms.db");
    let (pool, applied) =
        SqlitePool::instantiate_at_version(&path, false, Some(1), env!("CARGO_PKG_VERSION"))
            .await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        !pool.has_data().await?,
        "A fresh database must have no objects"
    );
    assert_lock_released(&path)?;
    assert_ready(&pool, env!("CARGO_PKG_VERSION")).await?;
    assert_markers(&pool, &[]).await?;

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

/// One 5.20.0 database, migrated step by step and directly, must end identical; reopening is a no-op.
#[tokio::test]
async fn test_sqlite_migration_5_20_step_by_step_matches_direct_and_reopens_clean() -> DbResult<()>
{
    let (_step_directory, step_path) = copy_fixture("5.20.0")?;
    let (_direct_directory, direct_path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&step_path)?;

    let (step, applied) =
        SqlitePool::instantiate_at_version(&step_path, false, Some(1), "5.24.0").await?;
    expect_steps(&applied, &[])?;
    assert_ready(&step, "5.24.0").await?;
    assert_markers(&step, &[]).await?;
    db_ensure!(
        step.find_wrapped_by("mig_kek", &UserId::from("admin"))
            .await?
            .is_empty(),
        "The wrapping-key backfill must not run before 5.25.0"
    );
    assert_serial_tag(&step, false).await?;
    assert_fixture_preserved(&step, &step_path, &original).await?;

    expect_steps(
        &step.bootstrap(false, "5.25.0").await?,
        &[WrappingKeyIdBackfill],
    )?;
    assert_ready(&step, "5.25.0").await?;
    assert_markers(&step, &[WrappingKeyIdBackfill]).await?;
    assert_wrapped_key_found(&step).await?;
    assert_serial_tag(&step, false).await?;
    assert_fixture_preserved(&step, &step_path, &original).await?;

    expect_steps(
        &step.bootstrap(false, TARGET).await?,
        &[CertificateSerialTagBackfill],
    )?;
    assert_ready(&step, TARGET).await?;
    assert_markers(&step, &BOTH_STEPS).await?;
    assert_serial_tag(&step, true).await?;
    assert_fixture_preserved(&step, &step_path, &original).await?;

    let (direct, applied) =
        SqlitePool::instantiate_at_version(&direct_path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&direct, TARGET).await?;
    assert_markers(&direct, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&direct).await?;
    assert_serial_tag(&direct, true).await?;
    assert_fixture_preserved(&direct, &direct_path, &original).await?;
    let migrated = complete_data(&direct_path)?;
    db_ensure!(
        complete_data(&step_path)? == migrated,
        "Every row in objects, tags, read_access, and parameters must match"
    );

    drop(direct);
    let (direct, applied) =
        SqlitePool::instantiate_at_version(&direct_path, false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        migrated == complete_data(&direct_path)?,
        "Reopening changed migrated rows"
    );
    assert_ready(&direct, TARGET).await?;
    assert_fixture_preserved(&direct, &direct_path, &original).await
}

/// The later released databases migrate to the target, or are left alone when already there.
#[tokio::test]
async fn test_sqlite_migration_released_fixtures() -> DbResult<()> {
    const MIGRATION_PARAMETERS: &str = "SELECT name, value FROM parameters \
         WHERE name NOT IN ('db_version', 'db_state') ORDER BY name";
    let fixtures: [(&str, &[MigrationStep]); 3] = [
        ("5.24.0", &BOTH_STEPS),
        ("5.28.0", &[CertificateSerialTagBackfill]),
        ("5.29.0", &[]),
    ];
    for (version, expected) in fixtures {
        let (_directory, path) = copy_fixture(version)?;
        let original = preserved_data(&path)?;
        // Only a database already at the target has the final schema to snapshot before opening.
        let before = if expected.is_empty() {
            Some((
                complete_data(&path)?,
                query_rows(&path, MIGRATION_PARAMETERS)?,
            ))
        } else {
            None
        };
        let (pool, applied) =
            SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET).await?;
        expect_steps(&applied, expected)
            .map_err(|error| db_error!("Fixture {version}: {error}"))?;
        assert_ready(&pool, TARGET).await?;
        assert_markers(&pool, &BOTH_STEPS).await?;
        assert_wrapped_key_found(&pool).await?;
        assert_serial_tag(&pool, true).await?;
        assert_fixture_preserved(&pool, &path, &original).await?;
        if let Some((rows, parameters)) = before {
            let [objects, tags, access, _] = rows;
            let [after_objects, after_tags, after_access, _] = complete_data(&path)?;
            db_ensure!(
                objects == after_objects && tags == after_tags && access == after_access,
                "Opening a {version} fixture already at the target changed object, tag, or permission data"
            );
            db_ensure!(
                parameters == query_rows(&path, MIGRATION_PARAMETERS)?,
                "Opening a {version} fixture already at the target changed migration parameters"
            );
        }
    }
    Ok(())
}

/// A database that cannot be opened safely is refused without a single byte written.
#[tokio::test]
async fn test_sqlite_migration_refuses_newer_or_invalid_version_untouched() -> DbResult<()> {
    let cases = [
        (
            "99.0.0",
            "Database Error: Database version 99.0.0 is newer than this KMS server version \
             5.29.0: refusing to start. Upgrade the KMS server to 99.0.0 or later.",
        ),
        ("not-a-version", "not-a-version"),
    ];
    for (recorded, expected_error) in cases {
        let (_directory, path) = copy_fixture("5.20.0")?;
        seed_parameters(&path, &[("db_version", recorded)])?;
        let original_file = fs::read(&path)?;
        let wal = path.with_file_name("kms.db-wal");
        let shm = path.with_file_name("kms.db-shm");
        let error = SqlitePool::instantiate_at_version(&path, false, Some(1), TARGET)
            .await
            .err()
            .ok_or_else(|| db_error!("Version {recorded} must be refused"))?;
        db_ensure!(
            error.to_string().contains(expected_error),
            "Unexpected error for {recorded}: {error}"
        );
        // Identical bytes and no sidecars leave no way for schema or data to have changed.
        db_ensure!(
            fs::read(&path)? == original_file,
            "Refusing {recorded} changed the database file"
        );
        db_ensure!(
            !wal.try_exists()? && !shm.try_exists()?,
            "Refusing {recorded} created WAL sidecars"
        );
        assert_lock_released(&path)?;
    }
    Ok(())
}

/// `--clear-database` overrides the newer-version refusal and wipes object data.
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

/// A second instance waits for the held lock, then exactly one of two racing instances migrates.
#[tokio::test]
async fn test_sqlite_migration_lock_serializes_instances() -> DbResult<()> {
    let (_directory, path) = copy_fixture("5.20.0")?;
    let original = preserved_data(&path)?;
    let (first, first_applied) =
        SqlitePool::instantiate_at_version(&path, false, Some(1), "5.24.0").await?;
    let (second, second_applied) =
        SqlitePool::instantiate_at_version(&path, false, Some(1), "5.24.0").await?;
    expect_steps(&first_applied, &[])?;
    expect_steps(&second_applied, &[])?;
    let held = first.acquire_migration_lock().await?;
    // Real elapsed time: the lock is polled every 500 ms, so 100 ms proves the wait without a race.
    let error = tokio::time::timeout(Duration::from_millis(100), second.bootstrap(false, TARGET))
        .await
        .err()
        .ok_or_else(|| db_error!("A second pool must wait for the migration lock"))?;
    db_ensure!(
        error.to_string().contains("deadline has elapsed"),
        "Unexpected lock timeout: {error}"
    );
    drop(held);
    let (first_applied, second_applied) = tokio::join!(
        first.bootstrap(false, TARGET),
        second.bootstrap(false, TARGET)
    );
    let (first_applied, second_applied) = (first_applied?, second_applied?);
    db_ensure!(
        (first_applied == BOTH_STEPS && second_applied.is_empty())
            || (second_applied == BOTH_STEPS && first_applied.is_empty()),
        "Exactly one pool must apply both steps: {first_applied:?}, {second_applied:?}"
    );
    for pool in [&first, &second] {
        assert_ready(pool, TARGET).await?;
        assert_markers(pool, &BOTH_STEPS).await?;
    }
    assert_wrapped_key_found(&first).await?;
    assert_serial_tag(&second, true).await?;
    assert_fixture_preserved(&first, &path, &original).await?;
    assert_fixture_preserved(&second, &path, &original).await
}
