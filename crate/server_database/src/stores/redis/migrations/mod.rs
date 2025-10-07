pub(crate) mod redis_4_5_0_to_5_8_1; // This is *ONLY* marked as pub(crate) to allow auto-converting to/from LegacyDbError in DbError.

use std::{collections::HashSet, str};

use async_trait::async_trait;
use cosmian_kms_interfaces::PermissionsStore;
use cosmian_logger::warn;
use uuid::Uuid;

use crate::{
    DbError,
    error::DbResult,
    stores::{
        RedisWithFindex,
        migrate::{DbState, Migrate, MigrateTo590Parameters, RedisMigrate},
        redis::migrations::redis_4_5_0_to_5_8_1::RedisWithFindex as LegacyRedisWithFindex,
    },
};

#[async_trait(?Send)]
impl Migrate for RedisWithFindex {
    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        let state_str: Option<String> = redis::cmd("GET")
            .arg("db_state")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get DB state: {e}")))?;

        match state_str {
            Some(state) => Ok(Some(serde_json::from_str(&state)?)),
            None => Ok(Some(DbState::Ready)),
        }
    }

    async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        let state_json = serde_json::to_string(&state)?;
        redis::cmd("SET")
            .arg("db_state")
            .arg(state_json)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to set DB state: {e}")))?;

        Ok(())
    }

    async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        let version: Option<String> = redis::cmd("GET")
            .arg("db_version")
            .query_async(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get DB version: {e}")))?;

        Ok(version)
    }

    async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        redis::cmd("SET")
            .arg("db_version")
            .arg(version)
            .query_async::<()>(&mut self.mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to set DB version: {e}")))?;

        Ok(())
    }
}

impl RedisMigrate for RedisWithFindex {
    async fn migrate_to_5_9_0(&self, parameters: MigrateTo590Parameters<'_>) -> DbResult<()> {
        // we fetch all object uids from the keys in redis
        fn is_valid_uuid(s: &str) -> bool {
            Uuid::try_parse(s).is_ok()
        }
        let mut conn = self.mgr.clone();

        let all_obj_keys: Vec<String> = redis::cmd("KEYS")
            .arg("do::*")
            .query_async(&mut conn)
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed upon get_object_uids: {e}")))?;

        let all_object_uids = all_obj_keys
            .into_iter()
            .filter_map(|key| {
                key.strip_prefix("do::").and_then(|uid_str| {
                    if is_valid_uuid(uid_str) {
                        Some(uid_str.to_owned())
                    } else {
                        warn!("Invalid UUID found in key: {}", uid_str);
                        None
                    }
                })
            })
            .collect::<HashSet<String>>();

        // now, we need the old RedisWithFindex to read the permissions "as they were"
        let legacy_findex_redis_store = LegacyRedisWithFindex::instantiate(
            &parameters.redis_url,
            parameters.findex_key, // TODO: this clone is pretty much debatable
            &parameters.label,
            false,
        )
        .await?;

        // Strategy: for each object, we list the users that have permissions on it to get the full permissions Triplet
        // then, we store them back using the new version.
        for obj_uid in all_object_uids {
            let per_user = legacy_findex_redis_store
                .list_object_operations_granted(&obj_uid, None)
                .await?;
            for (user_id, operations) in per_user {
                let _ = self.grant_operations(&obj_uid, &user_id, operations, None);
            }
        }

        // Now, same things for tags

        Ok(())
    }
}
