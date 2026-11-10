use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::File,
    io::{BufReader, Read},
    path::Path,
    time::Duration,
};

use cosmian_kms_interfaces::{ObjectsStore, UserId};
use redis::aio::ConnectionManager;

use super::{
    get_redis_url,
    sql_migration_tests::assert_markers,
    sqlite_migration_tests::{
        assert_ready, assert_serial_tag, assert_store_objects_and_grants, assert_wrapped_key_found,
        expect_steps,
    },
};
use crate::{
    db_ensure, db_error,
    error::{DbError, DbResult},
    redis_master_key_from_password,
    stores::{
        REDIS_WITH_FINDEX_MASTER_KEY_LENGTH, RedisWithFindex,
        migrate::{
            MIGRATION_STEPS, Migrate,
            MigrationStep::{self, CertificateSerialTagBackfill, WrappingKeyIdBackfill},
        },
        redis::{
            migrations::{REDIS_MIGRATION_LOCK_KEY, REDIS_MIGRATION_LOCK_LEASE_MS},
            objects_db::{ACTIVE_KEY_COUNT_KEY, LIVE_COUNT_KEY},
        },
    },
};

const TARGET: &str = "5.29.0";
const BOTH_STEPS: [MigrationStep; 2] = [WrappingKeyIdBackfill, CertificateSerialTagBackfill];
const FIXTURE_REDIS_DB: u8 = 14;
const FIXTURE_PASSWORD: &str = "kms-fixture";

type PreservedSnapshot = (
    BTreeMap<String, Vec<u8>>,
    BTreeMap<String, (String, BTreeSet<String>)>,
);

struct RedisFixture {
    url: String,
}

impl RedisFixture {
    fn new() -> Self {
        Self {
            url: format!("{}/{FIXTURE_REDIS_DB}", get_redis_url()),
        }
    }

    async fn connection(&self) -> DbResult<ConnectionManager> {
        let client = redis::Client::open(self.url.as_str())?;
        Ok(ConnectionManager::new(client).await?)
    }

    fn master_key() -> DbResult<
        cosmian_kms_crypto::reexport::cosmian_crypto_core::Secret<
            REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
        >,
    > {
        let mut key = *redis_master_key_from_password(FIXTURE_PASSWORD)?;
        Ok(
            cosmian_kms_crypto::reexport::cosmian_crypto_core::Secret::from_unprotected_bytes(
                &mut key,
            ),
        )
    }

    async fn open(
        &self,
        clear_database: bool,
        target: &str,
    ) -> DbResult<(RedisWithFindex, Vec<MigrationStep>)> {
        RedisWithFindex::instantiate_at_version(
            &self.url,
            Self::master_key()?,
            clear_database,
            target,
        )
        .await
    }

    async fn reset(&self) -> DbResult<()> {
        let mut mgr = self.connection().await?;
        redis::cmd("FLUSHDB").query_async::<()>(&mut mgr).await?;
        Ok(())
    }

    async fn restore(&self, version: &str) -> DbResult<()> {
        self.reset().await?;
        let mut mgr = self.connection().await?;
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_data/db_migration"
        ))
        .join(version)
        .join("redis/dump.bin");
        let mut reader = BufReader::new(File::open(path)?);
        loop {
            let mut len_buf = [0_u8; 8];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(DbError::from(error)),
            }
            let key_len = usize::try_from(u64::from_le_bytes(len_buf))
                .map_err(|error| db_error!("Invalid Redis dump key length: {error}"))?;
            let mut key = vec![0_u8; key_len];
            reader.read_exact(&mut key)?;
            reader.read_exact(&mut len_buf)?;
            let val_len = usize::try_from(u64::from_le_bytes(len_buf))
                .map_err(|error| db_error!("Invalid Redis dump value length: {error}"))?;
            let mut val = vec![0_u8; val_len];
            reader.read_exact(&mut val)?;
            redis::cmd("RESTORE")
                .arg(&key)
                .arg(0)
                .arg(&val)
                .query_async::<()>(&mut mgr)
                .await?;
        }
        Ok(())
    }

    async fn seed_parameters(&self, parameters: &[(&str, &str)]) -> DbResult<()> {
        let mut mgr = self.connection().await?;
        for (name, value) in parameters {
            redis::cmd("SET")
                .arg(*name)
                .arg(*value)
                .query_async::<()>(&mut mgr)
                .await?;
        }
        Ok(())
    }

    async fn delete_keys(&self, keys: &[&str]) -> DbResult<()> {
        let mut mgr = self.connection().await?;
        for key in keys {
            redis::cmd("DEL")
                .arg(*key)
                .query_async::<()>(&mut mgr)
                .await?;
        }
        Ok(())
    }

    async fn assert_lock_released(&self) -> DbResult<()> {
        let mut mgr = self.connection().await?;
        let exists: bool = redis::cmd("EXISTS")
            .arg(REDIS_MIGRATION_LOCK_KEY)
            .query_async(&mut mgr)
            .await?;
        db_ensure!(
            !exists,
            "Redis migration lock '{REDIS_MIGRATION_LOCK_KEY}' was left behind"
        );
        Ok(())
    }

    async fn raw_do_blobs(&self) -> DbResult<BTreeMap<String, Vec<u8>>> {
        let mut mgr = self.connection().await?;
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("do::*")
                .arg("COUNT")
                .arg(200)
                .query_async(&mut mgr)
                .await?;
            keys.extend(batch);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        keys.sort();
        let mut out = BTreeMap::new();
        for key in keys {
            let raw: Vec<u8> = redis::cmd("GET").arg(&key).query_async(&mut mgr).await?;
            let uid = key.strip_prefix("do::").unwrap_or(&key).to_owned();
            out.insert(uid, raw);
        }
        Ok(out)
    }

    async fn preserved_snapshot(&self) -> DbResult<PreservedSnapshot> {
        let mut raw = self.raw_do_blobs().await?;
        let mut certs = BTreeMap::new();
        let mut db_key =
            cosmian_kms_crypto::reexport::cosmian_crypto_core::SymmetricKey::<32>::default();
        let master_key = Self::master_key()?;
        cosmian_kms_crypto::reexport::cosmian_crypto_core::kdf256!(
            &mut *db_key,
            b"db",
            &*master_key
        );
        let objects_db =
            crate::stores::redis::objects_db::ObjectsDB::new(self.connection().await?, &db_key);
        for cert_id in ["mig_cert", "bulk_cert_2"] {
            if let Some(bytes) = raw.remove(cert_id) {
                let dbo = objects_db.decrypt_object(cert_id, &bytes)?;
                let payload = serde_json::to_string(&(
                    &dbo.object,
                    &dbo.object_type,
                    &dbo.owner,
                    &dbo.state,
                    &dbo.attributes,
                ))?;
                let non_serial_tags: BTreeSet<String> = dbo
                    .tags
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|tag| !tag.starts_with("_serial="))
                    .collect();
                certs.insert(cert_id.to_owned(), (payload, non_serial_tags));
            }
        }
        Ok((raw, certs))
    }

    async fn stored_objects_with_state(
        &self,
        pool: &RedisWithFindex,
    ) -> DbResult<Vec<(String, String)>> {
        let raw = self.raw_do_blobs().await?;
        let mut out = Vec::with_capacity(raw.len());
        for (uid, bytes) in raw {
            let state = match pool.objects_db().decrypt_object(&uid, &bytes) {
                Ok(dbo) => dbo.state.to_string(),
                Err(_) => "Active".to_owned(),
            };
            out.push((uid, state));
        }
        Ok(out)
    }
}

async fn assert_fixture_preserved(
    fixture: &RedisFixture,
    pool: &RedisWithFindex,
    original: &PreservedSnapshot,
) -> DbResult<()> {
    fixture.assert_lock_released().await?;
    db_ensure!(
        &fixture.preserved_snapshot().await? == original,
        "Non-certificate object ciphertexts or certificate payloads/tags changed"
    );
    let objects = fixture.stored_objects_with_state(pool).await?;
    assert_store_objects_and_grants(pool, &objects, true).await
}

async fn assert_serial_findex_lookup(pool: &RedisWithFindex, present: bool) -> DbResult<()> {
    for cert_id in ["mig_cert", "bulk_cert_2"] {
        let tags = pool.retrieve_tags(cert_id).await?;
        let serial_tag = tags.iter().find(|tag| tag.starts_with("_serial=")).cloned();
        db_ensure!(
            serial_tag.is_some() == present,
            "For {cert_id}: expected serial tag present={present}, got {tags:?}"
        );
        if let Some(tag) = serial_tag {
            let found = pool.list_uids_for_tags(&HashSet::from([tag])).await?;
            db_ensure!(
                found == HashSet::from([cert_id.to_owned()]),
                "Findex serial lookup for {cert_id} returned {found:?}"
            );
        }
    }
    Ok(())
}

async fn fresh_and_unversioned_empty(fixture: &RedisFixture) -> DbResult<()> {
    fixture.reset().await?;
    let (pool, applied) = fixture.open(false, env!("CARGO_PKG_VERSION")).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        !pool.has_data().await?,
        "A fresh Redis database must have no data"
    );
    fixture.assert_lock_released().await?;
    assert_ready(&pool, env!("CARGO_PKG_VERSION")).await?;
    assert_markers(&pool, &[]).await?;
    drop(pool);

    fixture.delete_keys(&["db_version"]).await?;
    fixture
        .seed_parameters(&[(LIVE_COUNT_KEY, "0"), (ACTIVE_KEY_COUNT_KEY, "0")])
        .await?;
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        !pool.has_data().await?,
        "Metadata-only Redis database must remain empty"
    );
    fixture.assert_lock_released().await?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &[]).await
}

async fn unversioned_with_data_is_refused(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    fixture.delete_keys(&["db_version", "db_state"]).await?;
    let original = fixture.raw_do_blobs().await?;
    let error = fixture
        .open(false, TARGET)
        .await
        .err()
        .ok_or_else(|| db_error!("An unversioned populated Redis database must be refused"))?;
    db_ensure!(
        error.to_string().contains("Legacy database")
            && error.to_string().contains("pre-5.12.0")
            && error.to_string().contains("export and re-import"),
        "Unexpected unversioned Redis error: {error}"
    );
    fixture.assert_lock_released().await?;
    db_ensure!(
        fixture.raw_do_blobs().await? == original,
        "Refusing an unversioned Redis database modified stored objects"
    );
    Ok(())
}

async fn below_minimum_version_is_refused(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    fixture.seed_parameters(&[("db_version", "5.11.0")]).await?;
    let original = fixture.raw_do_blobs().await?;
    let error = fixture
        .open(false, TARGET)
        .await
        .err()
        .ok_or_else(|| db_error!("A pre-5.12.0 Redis database must be refused"))?;
    db_ensure!(
        error.to_string().contains("Legacy database")
            && error.to_string().contains("5.11.0")
            && error.to_string().contains("5.12.0"),
        "Unexpected pre-5.12.0 Redis error: {error}"
    );
    fixture.assert_lock_released().await?;
    db_ensure!(
        fixture.raw_do_blobs().await? == original,
        "Refusing a 5.11.0 Redis database modified stored objects"
    );
    Ok(())
}

async fn step_by_step_matches_all_at_once(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_snapshot().await?;
    let (pool, applied) = fixture.open(false, "5.24.0").await?;
    expect_steps(&applied, &[])?;
    assert_ready(&pool, "5.24.0").await?;
    assert_markers(&pool, &[]).await?;
    db_ensure!(
        pool.find_wrapped_by("mig_kek", &UserId::from("admin"))
            .await?
            .is_empty(),
        "The wrapping-key backfill must not run before 5.25.0"
    );
    assert_serial_tag(&pool, false, true).await?;
    assert_serial_findex_lookup(&pool, false).await?;

    expect_steps(
        &pool.bootstrap(false, "5.25.0").await?,
        &[WrappingKeyIdBackfill],
    )?;
    assert_ready(&pool, "5.25.0").await?;
    assert_markers(&pool, &[WrappingKeyIdBackfill]).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, false, true).await?;

    expect_steps(
        &pool.bootstrap(false, TARGET).await?,
        &[CertificateSerialTagBackfill],
    )?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_serial_tag(&pool, true, true).await?;
    assert_serial_findex_lookup(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await?;
    let stepwise_snapshot = fixture.preserved_snapshot().await?;
    let stepwise_mig_tags = pool.retrieve_tags("mig_cert").await?;
    let stepwise_bulk_tags = pool.retrieve_tags("bulk_cert_2").await?;
    drop(pool);

    fixture.restore("5.20.0").await?;
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true, true).await?;
    assert_serial_findex_lookup(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await?;
    db_ensure!(
        fixture.preserved_snapshot().await? == stepwise_snapshot
            && pool.retrieve_tags("mig_cert").await? == stepwise_mig_tags
            && pool.retrieve_tags("bulk_cert_2").await? == stepwise_bulk_tags,
        "Step-by-step and direct upgrades produced different logical state"
    );
    Ok(())
}

async fn released_fixture(
    fixture: &RedisFixture,
    version: &str,
    expected: &[MigrationStep],
) -> DbResult<()> {
    fixture.restore(version).await?;
    let original = fixture.preserved_snapshot().await?;
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, expected)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true, true).await?;
    assert_serial_findex_lookup(&pool, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn markers_already_set(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_snapshot().await?;
    fixture
        .seed_parameters(&[
            (WrappingKeyIdBackfill.marker(), "true"),
            (CertificateSerialTagBackfill.marker(), "true"),
        ])
        .await?;
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, &[])?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_serial_tag(&pool, false, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn newer_and_invalid_versions_are_refused(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.raw_do_blobs().await?;
    fixture.seed_parameters(&[("db_version", "99.0.0")]).await?;
    let error = fixture
        .open(false, TARGET)
        .await
        .err()
        .ok_or_else(|| db_error!("A newer Redis database must be refused"))?;
    db_ensure!(
        error.to_string()
            == "Database Error: Database version 99.0.0 is newer than this KMS server version \
                5.29.0: refusing to start. Upgrade the KMS server to 99.0.0 or later.",
        "Unexpected newer-version error: {error}"
    );
    fixture.assert_lock_released().await?;
    db_ensure!(
        fixture.raw_do_blobs().await? == original,
        "Newer-version refusal changed Redis objects"
    );

    fixture
        .seed_parameters(&[("db_version", "not-a-version")])
        .await?;
    let error = fixture
        .open(false, TARGET)
        .await
        .err()
        .ok_or_else(|| db_error!("An invalid Redis database version must be refused"))?;
    db_ensure!(
        error.to_string().contains("not-a-version"),
        "Unexpected invalid-version error: {error}"
    );
    fixture.assert_lock_released().await?;
    db_ensure!(
        fixture.raw_do_blobs().await? == original,
        "Invalid-version refusal changed Redis objects"
    );
    Ok(())
}

async fn interrupted_and_below_baseline(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_snapshot().await?;
    fixture
        .seed_parameters(&[("db_version", "5.24.0"), ("db_state", "\"upgrading\"")])
        .await?;
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await?;
    drop(pool);

    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_snapshot().await?;
    fixture.seed_parameters(&[("db_version", "5.16.0")]).await?;
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, &MIGRATION_STEPS)?;
    assert_ready(&pool, TARGET).await?;
    assert_markers(&pool, &MIGRATION_STEPS).await?;
    assert_wrapped_key_found(&pool).await?;
    assert_serial_tag(&pool, true, true).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn clear_and_reopen(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    fixture.seed_parameters(&[("db_version", "99.0.0")]).await?;
    let (pool, applied) = fixture.open(true, TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(!pool.has_data().await?, "Clear left stored Redis objects");
    db_ensure!(
        fixture.raw_do_blobs().await?.is_empty(),
        "Clear left do::* keys"
    );
    fixture.assert_lock_released().await?;
    assert_ready(&pool, TARGET).await?;
    drop(pool);

    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_snapshot().await?;
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, &BOTH_STEPS)?;
    let migrated_blobs = fixture.raw_do_blobs().await?;
    drop(pool);
    let (pool, applied) = fixture.open(false, TARGET).await?;
    expect_steps(&applied, &[])?;
    db_ensure!(
        fixture.raw_do_blobs().await? == migrated_blobs,
        "Reopening a migrated Redis database changed object ciphertexts"
    );
    assert_ready(&pool, TARGET).await?;
    assert_fixture_preserved(fixture, &pool, &original).await
}

async fn concurrent_startup_and_lock_semantics(fixture: &RedisFixture) -> DbResult<()> {
    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_snapshot().await?;
    let (first, second) = tokio::join!(fixture.open(false, TARGET), fixture.open(false, TARGET));
    let (first, first_applied) = first?;
    let (second, second_applied) = second?;
    db_ensure!(
        (first_applied == BOTH_STEPS && second_applied.is_empty())
            || (second_applied == BOTH_STEPS && first_applied.is_empty()),
        "Exactly one Redis instance must apply both steps: {first_applied:?}, {second_applied:?}"
    );
    assert_ready(&first, TARGET).await?;
    assert_ready(&second, TARGET).await?;
    assert_markers(&first, &BOTH_STEPS).await?;
    assert_markers(&second, &BOTH_STEPS).await?;
    assert_wrapped_key_found(&first).await?;
    assert_serial_tag(&second, true, true).await?;
    assert_fixture_preserved(fixture, &first, &original).await?;
    assert_fixture_preserved(fixture, &second, &original).await?;
    drop((first, second));

    fixture.restore("5.20.0").await?;
    let original = fixture.preserved_snapshot().await?;
    let (first, first_applied) = fixture.open(false, "5.24.0").await?;
    let (second, second_applied) = fixture.open(false, "5.24.0").await?;
    expect_steps(&first_applied, &[])?;
    expect_steps(&second_applied, &[])?;
    let held = first.acquire_migration_lock().await?;
    let mut mgr = fixture.connection().await?;
    let pttl: i64 = redis::cmd("PTTL")
        .arg(REDIS_MIGRATION_LOCK_KEY)
        .query_async(&mut mgr)
        .await?;
    db_ensure!(
        pttl > 0 && u64::try_from(pttl).unwrap_or(0) <= REDIS_MIGRATION_LOCK_LEASE_MS,
        "Expected positive PTTL <= {REDIS_MIGRATION_LOCK_LEASE_MS} ms on '{REDIS_MIGRATION_LOCK_KEY}', got {pttl}"
    );
    let error = tokio::time::timeout(Duration::from_millis(600), second.bootstrap(false, TARGET))
        .await
        .err()
        .ok_or_else(|| db_error!("A second Redis instance must wait for the migration lock"))?;
    db_ensure!(
        error.to_string().contains("deadline has elapsed"),
        "Unexpected Redis lock timeout: {error}"
    );
    // Token-checked release: if the lock was replaced by another holder's token, releasing `held`
    // must not delete the other holder's key.
    redis::cmd("SET")
        .arg(REDIS_MIGRATION_LOCK_KEY)
        .arg("other-holder-token")
        .arg("PX")
        .arg(60_000_u64)
        .query_async::<()>(&mut mgr)
        .await?;
    first.release_migration_lock(held).await?;
    let remaining: Option<String> = redis::cmd("GET")
        .arg(REDIS_MIGRATION_LOCK_KEY)
        .query_async(&mut mgr)
        .await?;
    db_ensure!(
        remaining.as_deref() == Some("other-holder-token"),
        "Releasing a stale lock token deleted the replacement holder's lock: {remaining:?}"
    );
    fixture.delete_keys(&[REDIS_MIGRATION_LOCK_KEY]).await?;

    // Drop fallback: dropping a held lock without calling release_migration_lock releases the key
    // so a waiting instance can proceed.
    let held_for_drop = first.acquire_migration_lock().await?;
    drop(held_for_drop);
    expect_steps(&second.bootstrap(false, TARGET).await?, &BOTH_STEPS)?;
    fixture.assert_lock_released().await?;
    assert_ready(&second, TARGET).await?;
    assert_markers(&second, &BOTH_STEPS).await?;
    assert_fixture_preserved(fixture, &second, &original).await
}

pub(super) async fn redis_migration_scenarios() -> DbResult<()> {
    let fixture = RedisFixture::new();
    let result = async {
        fresh_and_unversioned_empty(&fixture).await?;
        unversioned_with_data_is_refused(&fixture).await?;
        below_minimum_version_is_refused(&fixture).await?;
        step_by_step_matches_all_at_once(&fixture).await?;
        released_fixture(&fixture, "5.24.0", &BOTH_STEPS).await?;
        released_fixture(&fixture, "5.28.0", &[CertificateSerialTagBackfill]).await?;
        markers_already_set(&fixture).await?;
        newer_and_invalid_versions_are_refused(&fixture).await?;
        interrupted_and_below_baseline(&fixture).await?;
        clear_and_reopen(&fixture).await?;
        concurrent_startup_and_lock_semantics(&fixture).await
    }
    .await;
    let cleanup = fixture.reset().await;
    result.and(cleanup)
}
