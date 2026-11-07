use std::{fs, path::Path, time::Duration};

use async_trait::async_trait;
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore, UserId};
use mysql_async::{Conn, Opts, Row, prelude::Queryable};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};
use url::Url;
use uuid::Uuid;

use super::sqlite_migration_tests::{
    assert_ready, assert_serial_tag, assert_store_objects_and_grants, assert_wrapped_key_found,
    expect_steps,
};
use crate::{
    db_ensure, db_error,
    error::DbResult,
    stores::{
        MySqlPool, PgPool,
        migrate::{
            DbParameters, MIGRATION_STEPS, Migrate,
            MigrationStep::{self, CertificateSerialTagBackfill, WrappingKeyIdBackfill},
        },
    },
};

const TARGET: &str = "5.29.0";
const BOTH_STEPS: [MigrationStep; 2] = [WrappingKeyIdBackfill, CertificateSerialTagBackfill];
const POSTGRES_URL: &str = match option_env!("KMS_POSTGRES_URL") {
    Some(url) => url,
    None => concat!("postgresql://kms:", "kms@127.0.0.1:5432/kms"),
};
const MYSQL_URL: &str = match option_env!("KMS_MYSQL_URL") {
    Some(url) => url,
    None => concat!("mysql://kms:", "kms@localhost:3306/kms"),
};
type TableRows = Vec<Vec<Option<String>>>;

async fn postgres_client(url: &str) -> DbResult<Client> {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            cosmian_logger::error!("PostgreSQL migration-test connection failed: {error}");
        }
    });
    Ok(client)
}

#[async_trait(?Send)]
trait MigrationFixture {
    type Pool: Migrate + ObjectsStore + PermissionsStore;

    const DUMP_DIR: &'static str;
    const ATTRIBUTES_TEXT: &'static str;

    async fn open(
        &self,
        clear_database: bool,
        max_connections: Option<u32>,
        target: &str,
    ) -> DbResult<(Self::Pool, Vec<MigrationStep>)>;

    async fn execute(&self, sql: &str) -> DbResult<()>;

    async fn rows(&self, sql: &str) -> DbResult<TableRows>;

    async fn reset(&self) -> DbResult<()> {
        self.execute(
            "DROP TABLE IF EXISTS read_access; \
             DROP TABLE IF EXISTS tags; \
             DROP TABLE IF EXISTS objects; \
             DROP TABLE IF EXISTS parameters; \
             DROP TABLE IF EXISTS crypto_officer_activations; \
             DROP TABLE IF EXISTS crls;",
        )
        .await
    }

    async fn restore(&self, version: &str) -> DbResult<()> {
        self.reset().await?;
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_data/db_migration"
        ))
        .join(version)
        .join(Self::DUMP_DIR)
        .join("dump.sql");
        let dump = fs::read_to_string(path)?;
        self.execute(&dump).await
    }

    async fn seed_parameters(&self, parameters: &[(&str, &str)]) -> DbResult<()> {
        for (name, value) in parameters {
            let sql = format!(
                "DELETE FROM parameters WHERE name = '{name}'; \
                 INSERT INTO parameters (name, value) VALUES ('{name}', '{value}');"
            );
            self.execute(&sql).await?;
        }
        Ok(())
    }

    async fn preserved_data(&self) -> DbResult<[TableRows; 3]> {
        Ok([
            self.rows(&format!(
                "SELECT id, object, {}, state, owner FROM objects ORDER BY id",
                Self::ATTRIBUTES_TEXT
            ))
            .await?,
            self.rows("SELECT id, tag FROM tags WHERE tag NOT LIKE '_serial=%' ORDER BY id, tag")
                .await?,
            self.rows("SELECT id, userid, permissions FROM read_access ORDER BY id, userid")
                .await?,
        ])
    }

    async fn complete_data(&self) -> DbResult<[TableRows; 4]> {
        Ok([
            self.rows(&format!(
                "SELECT id, object, {}, state, owner, wrapping_key_id \
                 FROM objects ORDER BY id",
                Self::ATTRIBUTES_TEXT
            ))
            .await?,
            self.rows("SELECT id, tag FROM tags ORDER BY id, tag")
                .await?,
            self.rows("SELECT id, userid, permissions FROM read_access ORDER BY id, userid")
                .await?,
            self.rows("SELECT name, value FROM parameters ORDER BY name")
                .await?,
        ])
    }

    async fn wrapping_key_column_exists(&self) -> DbResult<bool>;

    async fn schema_signature(&self) -> DbResult<TableRows>;
}

struct PostgresFixture {
    url: String,
}

#[async_trait(?Send)]
impl MigrationFixture for PostgresFixture {
    type Pool = PgPool;

    const ATTRIBUTES_TEXT: &'static str = "attributes::text";
    const DUMP_DIR: &'static str = "postgresql";

    async fn open(
        &self,
        clear_database: bool,
        max_connections: Option<u32>,
        target: &str,
    ) -> DbResult<(Self::Pool, Vec<MigrationStep>)> {
        PgPool::instantiate_at_version(&self.url, clear_database, max_connections, target).await
    }

    async fn execute(&self, sql: &str) -> DbResult<()> {
        postgres_client(&self.url).await?.batch_execute(sql).await?;
        Ok(())
    }

    async fn rows(&self, sql: &str) -> DbResult<TableRows> {
        let messages = postgres_client(&self.url).await?.simple_query(sql).await?;
        let mut rows = Vec::new();
        for message in messages {
            if let SimpleQueryMessage::Row(row) = message {
                rows.push(
                    (0..row.len())
                        .map(|column| row.get(column).map(str::to_owned))
                        .collect(),
                );
            }
        }
        Ok(rows)
    }

    async fn wrapping_key_column_exists(&self) -> DbResult<bool> {
        Ok(!self
            .rows(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = 'objects' \
                 AND column_name = 'wrapping_key_id'",
            )
            .await?
            .is_empty())
    }

    async fn schema_signature(&self) -> DbResult<TableRows> {
        self.rows(
            "SELECT table_name, column_name, data_type \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             ORDER BY table_name, ordinal_position",
        )
        .await
    }
}

struct MySqlFixture {
    url: &'static str,
}

#[async_trait(?Send)]
impl MigrationFixture for MySqlFixture {
    type Pool = MySqlPool;

    const ATTRIBUTES_TEXT: &'static str = "CAST(attributes AS CHAR)";
    const DUMP_DIR: &'static str = "mysql";

    async fn open(
        &self,
        clear_database: bool,
        max_connections: Option<u32>,
        target: &str,
    ) -> DbResult<(Self::Pool, Vec<MigrationStep>)> {
        MySqlPool::instantiate_at_version(self.url, clear_database, max_connections, target).await
    }

    async fn execute(&self, sql: &str) -> DbResult<()> {
        let opts = Opts::from_url(self.url)?;
        let mut conn = Conn::new(opts).await?;
        conn.query_drop(sql).await?;
        conn.disconnect().await?;
        Ok(())
    }

    async fn rows(&self, sql: &str) -> DbResult<TableRows> {
        let opts = Opts::from_url(self.url)?;
        let mut conn = Conn::new(opts).await?;
        let query_rows: Vec<Row> = conn.query(sql).await?;
        let mut rows = Vec::with_capacity(query_rows.len());
        for mut row in query_rows {
            let mut values = Vec::with_capacity(row.len());
            for column in 0..row.len() {
                let value = row
                    .take_opt::<Option<String>, _>(column)
                    .ok_or_else(|| db_error!("Missing MySQL result column {column}"))?
                    .map_err(|error| db_error!("Invalid MySQL result value: {error}"))?;
                values.push(value);
            }
            rows.push(values);
        }
        conn.disconnect().await?;
        Ok(rows)
    }

    async fn wrapping_key_column_exists(&self) -> DbResult<bool> {
        Ok(!self
            .rows(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = 'objects' \
                 AND column_name = 'wrapping_key_id'",
            )
            .await?
            .is_empty())
    }

    async fn schema_signature(&self) -> DbResult<TableRows> {
        self.rows(
            "SELECT table_name, column_name, data_type \
             FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name <> 'kms_migration_lock' \
             ORDER BY table_name, ordinal_position",
        )
        .await
    }
}

async fn assert_markers<P: DbParameters>(pool: &P, completed: &[MigrationStep]) -> DbResult<()> {
    for step in MIGRATION_STEPS {
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

async fn assert_fixture_preserved<F: MigrationFixture>(
    fixture: &F,
    pool: &F::Pool,
    original: &[TableRows; 3],
) -> DbResult<()> {
    db_ensure!(
        &fixture.preserved_data().await? == original,
        "Object payloads, states, original tags, or permissions changed"
    );
    let rows = fixture
        .rows("SELECT id, state FROM objects ORDER BY id")
        .await?;
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row
            .first()
            .and_then(Option::as_deref)
            .ok_or_else(|| db_error!("Fixture object row has no identifier"))?
            .to_owned();
        let state = row
            .get(1)
            .and_then(Option::as_deref)
            .ok_or_else(|| db_error!("Fixture object {id} has no state"))?
            .to_owned();
        objects.push((id, state));
    }
    assert_store_objects_and_grants(pool, &objects).await
}

async fn fresh_and_one_connection<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.reset().await?;
    let (pool, applied) = fixture
        .open(false, Some(1), env!("CARGO_PKG_VERSION"))
        .await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        !pool.has_data().await?,
        "A fresh database must have no objects"
    );
    assert_ready(&pool, env!("CARGO_PKG_VERSION")).await?;
    assert_markers(&pool, &[]).await
}

async fn unversioned_empty<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.reset().await?;
    let (pool, applied) = fixture.open(true, Some(1), "5.20.0").await?;
    expect_steps(&applied, &[])?;
    drop(pool);
    fixture
        .execute("DELETE FROM parameters WHERE name = 'db_version'")
        .await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        !pool.has_data().await?,
        "Schema-only database must remain empty"
    );
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &[]).await
}

async fn unversioned_with_data<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn step_by_step_matches_all_at_once<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    let (pool, applied) = fixture.open(false, Some(1), "5.24.0").await?;
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

    expect_steps(
        &pool.bootstrap(false, "5.25.0").await?,
        &[WrappingKeyIdBackfill],
    )?;
    assert_ready(&pool, "5.25.0").await?;
    assert_markers(&pool, &[WrappingKeyIdBackfill]).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, false).await?;

    expect_steps(
        &pool.bootstrap(false, TARGET).await?,
        &[CertificateSerialTagBackfill],
    )?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await?;
    let stepwise = fixture.complete_data().await?;
    drop(pool);

    fixture.restore("5.20.0").await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    db_ensure!(
        fixture.complete_data().await? == stepwise,
        "Step-by-step and direct upgrades produced different rows"
    );
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn released_fixture<F: MigrationFixture>(
    fixture: &F,
    version: &str,
    expected: &[MigrationStep],
) -> DbResult<()> {
    fixture.restore(version).await?;
    let original = fixture.preserved_data().await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, expected)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn markers_already_set<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    fixture
        .seed_parameters(&[
            (WrappingKeyIdBackfill.marker(), "true"),
            (CertificateSerialTagBackfill.marker(), "true"),
        ])
        .await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_serial_tag(&pool, false).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn newer_database_is_refused<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    fixture.seed_parameters(&[("db_version", "99.0.0")]).await?;
    let schema = fixture.schema_signature().await?;
    let error = fixture
        .open(false, Some(1), TARGET)
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
        fixture.schema_signature().await? == schema,
        "Newer-version refusal changed the schema"
    );
    db_ensure!(
        !fixture.wrapping_key_column_exists().await?,
        "Newer-version refusal added the wrapping_key_id column"
    );
    db_ensure!(
        fixture.preserved_data().await? == original,
        "Newer-version refusal changed fixture data"
    );
    Ok(())
}

async fn interrupted_run_resumes<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    fixture
        .seed_parameters(&[("db_version", "5.24.0"), ("db_state", "\"upgrading\"")])
        .await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn below_baseline<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    fixture.seed_parameters(&[("db_version", "5.14.0")]).await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &MIGRATION_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &MIGRATION_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn clear_database<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    fixture.seed_parameters(&[("db_version", "99.0.0")]).await?;
    let (pool, applied) = fixture.open(true, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(!pool.has_data().await?, "Clear left stored objects");
    db_ensure!(
        fixture.rows("SELECT id FROM objects").await?.is_empty(),
        "Clear left objects"
    );
    db_ensure!(
        fixture.rows("SELECT id FROM tags").await?.is_empty(),
        "Clear left tags"
    );
    db_ensure!(
        fixture.rows("SELECT id FROM read_access").await?.is_empty(),
        "Clear left grants"
    );
    assert_ready(&pool, TARGET).await
}

async fn concurrent_startup<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    let (first, second) = tokio::join!(
        fixture.open(false, Some(1), TARGET),
        fixture.open(false, Some(1), TARGET)
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
    assert_fixture_preserved(fixture, &first, &original).await?;
    assert_fixture_preserved(fixture, &second, &original).await
}

async fn migration_lock_blocks_second_pool<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    let (first, first_applied) = fixture.open(false, Some(1), "5.24.0").await?;
    let (second, second_applied) = fixture.open(false, Some(1), "5.24.0").await?;
    expect_steps(&first_applied, &[])?;
    expect_steps(&second_applied, &[])?;
    let held = first.acquire_migration_lock().await?;
    let error = tokio::time::timeout(Duration::from_secs(2), second.bootstrap(false, TARGET))
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
    assert_fixture_preserved(fixture, &second, &original).await
}

async fn reopen_is_noop<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_data().await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    let migrated = fixture.complete_data().await?;
    drop(pool);
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        fixture.complete_data().await? == migrated,
        "Reopening changed migrated rows"
    );
    assert_ready(&pool, TARGET).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn shared_migration_scenarios<F: MigrationFixture>(fixture: &F) -> DbResult<()> {
    fresh_and_one_connection(fixture).await?;
    unversioned_empty(fixture).await?;
    unversioned_with_data(fixture).await?;
    step_by_step_matches_all_at_once(fixture).await?;
    released_fixture(fixture, "5.24.0", &BOTH_STEPS).await?;
    released_fixture(fixture, "5.28.0", &[CertificateSerialTagBackfill]).await?;
    markers_already_set(fixture).await?;
    newer_database_is_refused(fixture).await?;
    interrupted_run_resumes(fixture).await?;
    below_baseline(fixture).await?;
    clear_database(fixture).await?;
    concurrent_startup(fixture).await?;
    migration_lock_blocks_second_pool(fixture).await?;
    reopen_is_noop(fixture).await
}

fn first_value(rows: &TableRows, description: &str) -> DbResult<String> {
    rows.first()
        .and_then(|row| row.first())
        .and_then(Option::as_ref)
        .cloned()
        .ok_or_else(|| db_error!("Missing {description}"))
}

async fn postgresql_5_14_fixture(fixture: &PostgresFixture) -> DbResult<()> {
    fixture.restore("5.14.0").await?;
    let original = fixture.preserved_data().await?;
    let before = fixture
        .rows(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'objects' \
             AND column_name = 'attributes'",
        )
        .await?;
    db_ensure!(
        first_value(&before, "PostgreSQL attributes type")? == "json",
        "The 5.14.0 fixture must start with a json attributes column"
    );
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &MIGRATION_STEPS)?;
    let after = fixture
        .rows(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'objects' \
             AND column_name = 'attributes'",
        )
        .await?;
    db_ensure!(
        first_value(&after, "PostgreSQL converted attributes type")? == "jsonb",
        "The 5.14.0 fixture attributes column was not converted to jsonb"
    );
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &MIGRATION_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn postgresql_reopen_does_not_rebuild_index(fixture: &PostgresFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    let before = fixture
        .rows("SELECT pg_relation_filenode('idx_objects_type_state'::regclass)::text")
        .await?;
    expect_steps(&pool.bootstrap(false, TARGET).await?, &[])?;
    let after = fixture
        .rows("SELECT pg_relation_filenode('idx_objects_type_state'::regclass)::text")
        .await?;
    db_ensure!(
        first_value(&before, "PostgreSQL index filenode before reopen")?
            == first_value(&after, "PostgreSQL index filenode after reopen")?,
        "Reopening rebuilt idx_objects_type_state"
    );
    Ok(())
}

async fn mysql_lock_released_on_disconnect(fixture: &MySqlFixture) -> DbResult<()> {
    fixture.reset().await?;
    let (pool, applied) = fixture.open(false, Some(1), TARGET).await?;
    expect_steps(&applied, &[])?;
    let held = pool.acquire_migration_lock().await?;
    drop(held);
    let reacquired = tokio::time::timeout(Duration::from_secs(5), pool.acquire_migration_lock())
        .await
        .map_err(|error| db_error!("MySQL migration lock was not released: {error}"))??;
    drop(reacquired);
    Ok(())
}

#[ignore = "Requires a running PostgreSQL instance"]
#[tokio::test]
async fn test_db_postgresql_migration() -> DbResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));
    let database = format!("kms_mig_{}", Uuid::new_v4().simple());
    let admin = postgres_client(POSTGRES_URL).await?;
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await?;
    drop(admin);

    let mut url = Url::parse(POSTGRES_URL)
        .map_err(|error| db_error!("Invalid PostgreSQL migration-test URL: {error}"))?;
    url.set_path(&format!("/{database}"));
    let fixture = PostgresFixture {
        url: url.to_string(),
    };
    let result = async {
        shared_migration_scenarios(&fixture).await?;
        postgresql_5_14_fixture(&fixture).await?;
        postgresql_reopen_does_not_rebuild_index(&fixture).await
    }
    .await;

    let admin = postgres_client(POSTGRES_URL).await?;
    let dropped = admin
        .batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .await
        .map_err(Into::into);
    result.and(dropped)
}

pub(super) async fn mysql_migration_scenarios() -> DbResult<()> {
    let fixture = MySqlFixture { url: MYSQL_URL };
    let result = async {
        shared_migration_scenarios(&fixture).await?;
        mysql_lock_released_on_disconnect(&fixture).await
    }
    .await;
    let cleanup = MySqlPool::instantiate(MYSQL_URL, true, None)
        .await
        .map(drop);
    result.and(cleanup)
}
