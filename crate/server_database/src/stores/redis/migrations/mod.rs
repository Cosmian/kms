//! Redis migration metadata, lease lock, and runner wiring.

use std::sync::LazyLock;

use async_trait::async_trait;
use cosmian_logger::reexport::tracing;
use redis::Script;
use uuid::Uuid;

use crate::{
    DbError,
    error::DbResult,
    stores::{
        RedisWithFindex,
        migrate::{
            DbParameters, MIGRATION_LOCK_TIMEOUT, MIGRATION_STEPS, Migrate, MigrationStep,
            wait_for_migration_lock,
        },
        redis::objects_db::{ACTIVE_KEY_COUNT_KEY, LIVE_COUNT_KEY},
    },
};

/// Redis key that serializes concurrent startup migrations across KMS instances.
pub(crate) const REDIS_MIGRATION_LOCK_KEY: &str = "kms_db_migration_lock";

/// Lease duration (30 minutes) for [`REDIS_MIGRATION_LOCK_KEY`].
///
/// The lease is not renewed; this limit is safe because every registered migration step is
/// idempotent and gated by a completion marker.
pub(crate) const REDIS_MIGRATION_LOCK_LEASE_MS: u64 = 1_800_000;

static RELEASE_MIGRATION_LOCK_SCRIPT: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"#,
    )
});

static CLEAR_PRESERVING_LOCK_SCRIPT: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local token = redis.call("GET", KEYS[1])
local pttl = redis.call("PTTL", KEYS[1])
redis.call("FLUSHDB")
if token then
    if pttl and pttl > 0 then
        redis.call("SET", KEYS[1], token, "PX", pttl)
    else
        redis.call("SET", KEYS[1], token, "PX", ARGV[1])
    end
end
return 1
"#,
    )
});

/// Guard holding a Redis migration lease token until deterministically released or dropped.
pub(crate) struct RedisMigrationLock {
    mgr: redis::aio::ConnectionManager,
    token: String,
    released: bool,
}

impl Drop for RedisMigrationLock {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let mut mgr = self.mgr.clone();
            let token = std::mem::take(&mut self.token);
            handle.spawn(async move {
                if let Err(error) = RELEASE_MIGRATION_LOCK_SCRIPT
                    .key(REDIS_MIGRATION_LOCK_KEY)
                    .arg(&token)
                    .invoke_async::<i32>(&mut mgr)
                    .await
                {
                    tracing::warn!(%error, "Failed to release Redis migration lock on drop");
                }
            });
        }
    }
}

#[async_trait(?Send)]
impl DbParameters for RedisWithFindex {
    async fn get_parameter(&self, name: &str) -> DbResult<Option<String>> {
        redis::cmd("GET")
            .arg(name)
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!("Failed to get database parameter '{name}': {e}"))
            })
    }

    async fn set_parameter(&self, name: &str, value: &str) -> DbResult<()> {
        redis::cmd("SET")
            .arg(name)
            .arg(value)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!("Failed to set database parameter '{name}': {e}"))
            })?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl Migrate for RedisWithFindex {
    type MigrationLock = RedisMigrationLock;

    const MIN_RECORDED_VERSION: Option<&'static str> = Some("5.12.0");
    const UNVERSIONED_BASELINE: Option<&'static str> = None;

    async fn has_data(&self) -> DbResult<bool> {
        let mut mgr = self.mgr.clone();
        let dbsize: usize = redis::cmd("DBSIZE")
            .query_async(&mut mgr)
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get Redis DB size: {e}")))?;
        if dbsize == 0 {
            return Ok(false);
        }
        let mut exists_cmd = redis::cmd("EXISTS");
        exists_cmd
            .arg(REDIS_MIGRATION_LOCK_KEY)
            .arg("db_version")
            .arg("db_state")
            .arg(LIVE_COUNT_KEY)
            .arg(ACTIVE_KEY_COUNT_KEY);
        for step in MIGRATION_STEPS {
            exists_cmd.arg(step.marker());
        }
        let metadata_keys: usize = exists_cmd.query_async(&mut mgr).await.map_err(|e| {
            DbError::DatabaseError(format!("Failed to check Redis metadata keys: {e}"))
        })?;
        Ok(dbsize > metadata_keys)
    }

    async fn acquire_migration_lock(&self) -> DbResult<Self::MigrationLock> {
        let token = Uuid::new_v4().to_string();
        let mut mgr = self.mgr.clone();
        wait_for_migration_lock(
            REDIS_MIGRATION_LOCK_KEY,
            MIGRATION_LOCK_TIMEOUT,
            async || {
                let response: Option<String> = redis::cmd("SET")
                    .arg(REDIS_MIGRATION_LOCK_KEY)
                    .arg(&token)
                    .arg("NX")
                    .arg("PX")
                    .arg(REDIS_MIGRATION_LOCK_LEASE_MS)
                    .query_async(&mut mgr)
                    .await
                    .map_err(|e| {
                        DbError::DatabaseError(format!(
                            "Failed to acquire Redis migration lock '{REDIS_MIGRATION_LOCK_KEY}': {e}"
                        ))
                    })?;
                Ok(response.is_some())
            },
        )
        .await?;
        Ok(RedisMigrationLock {
            mgr: self.mgr.clone(),
            token,
            released: false,
        })
    }

    async fn release_migration_lock(&self, mut lock: Self::MigrationLock) -> DbResult<()> {
        let removed: i32 = RELEASE_MIGRATION_LOCK_SCRIPT
            .key(REDIS_MIGRATION_LOCK_KEY)
            .arg(&lock.token)
            .invoke_async(&mut lock.mgr)
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!(
                    "Failed to release Redis migration lock '{REDIS_MIGRATION_LOCK_KEY}': {e}"
                ))
            })?;
        lock.released = true;
        if removed == 0 {
            tracing::warn!(
                lock_key = REDIS_MIGRATION_LOCK_KEY,
                "Redis migration lock was already expired or replaced before release"
            );
        }
        Ok(())
    }

    async fn ensure_schema(&self, clear_database: bool) -> DbResult<()> {
        if clear_database {
            let _: i32 = CLEAR_PRESERVING_LOCK_SCRIPT
                .key(REDIS_MIGRATION_LOCK_KEY)
                .arg(REDIS_MIGRATION_LOCK_LEASE_MS)
                .invoke_async(&mut self.mgr.clone())
                .await
                .map_err(|e| {
                    DbError::DatabaseError(format!("Failed to clear Redis database: {e}"))
                })?;
        }
        Ok(())
    }

    async fn apply_step(&self, step: MigrationStep) -> DbResult<()> {
        match step {
            MigrationStep::AttributesJsonb => Ok(()),
            MigrationStep::WrappingKeyIdBackfill => self.backfill_wrapped_by_index().await,
            MigrationStep::CertificateSerialTagBackfill => {
                Box::pin(self.backfill_certificate_serial_tags()).await
            }
        }
    }
}
