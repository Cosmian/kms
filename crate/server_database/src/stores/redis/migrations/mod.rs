//! This  module contains the bare necessary code required for reading the data written with any deprecated format that we still support migrating (ie. upgrading) from.
//! Once support for a certain version is dropped, the KMS should document a double upgrade strategy before aborting.
pub(crate) mod legacy_cloudproof_redis_findex;

use std::{collections::HashSet, str, sync::Arc};

use async_trait::async_trait;
use cosmian_findex::IndexADT;
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore};
use redis::{Commands, aio::ConnectionManager};

use crate::{
    DbError,
    error::DbResult,
    stores::{
        RedisWithFindex,
        migrate::{DbState, Migrate, MigrateTo5_12_0Parameters, RedisMigrate},
        redis::{
            findex::{FindexRedis, IndexedValue, Keyword},
            init_findex_redis,
            migrations::legacy_cloudproof_redis_findex::RedisWithFindex as LegacyRedisWithFindex,
            objects_db::keywords_from_attributes,
            permissions::{ObjectUid, PermissionDB, UserId},
        },
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
            None => Ok(None),
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
    async fn migrate_to_5_12_0(&self, parameters: MigrateTo5_12_0Parameters<'_>) -> DbResult<()> {
        // step 0: initialize two redis connections, one for DB 0 and one for DB 1, and two findex instances
        // one legacy for reading permissions from DB 0, and one new for writing permissions to DB 1
        let db_0_url = format!("{}/0", parameters.redis_url);
        let db_1_url = format!("{}/1", parameters.redis_url);

        let client_0 = redis::Client::open(db_0_url.clone())?;
        let mut mgr_0 = ConnectionManager::new(client_0).await?;

        // the old RedisWithFindex to read the permissions "as they were". This store will read from DB 0
        let legacy_findex_redis_store = LegacyRedisWithFindex::instantiate(
            &format!("{}/0", parameters.redis_url),
            parameters.master_key,
            &parameters.label,
        )
        .await?;

        // we also create a findex_v8 instance that will write to DB 1
        let findex_v8_db1: Arc<FindexRedis> =
            Arc::new(init_findex_redis(parameters.master_key, &db_1_url).await?);
        let migration_perm_db = PermissionDB::new(findex_v8_db1.clone());

        // step 1: retrieve all object UIDs from DB 0
        // this is a potentially long operation, depending on the number of objects in the DB
        // If this becomes a problem, we can always do the migration in chunks
        let all_obj_keys: Vec<String> = redis::cmd("KEYS")
            .arg("do::*")
            .query_async(&mut mgr_0)
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed upon get_object_uids: {e}")))?;

        let all_object_uids = all_obj_keys
            .iter()
            .filter_map(|key| key.strip_prefix("do::").map(str::to_owned))
            .collect::<HashSet<String>>();

        // step 2: permissions triplets migration
        for obj_uid in all_object_uids.clone() {
            // List permission using the old version.
            let per_user = legacy_findex_redis_store
                .list_object_operations_granted(&obj_uid, None)
                .await?;

            let obj_uid = ObjectUid(obj_uid);
            for (user_id, operations) in per_user {
                // Re-grant them using the new version, this needs to be performed on db 1.
                let user_id = UserId(user_id);
                for operation in operations {
                    let _: () = migration_perm_db.add(&obj_uid, &user_id, operation).await?;
                }
            }
        }

        // step 2: indexed keywords migration
        for obj_uid in all_object_uids {
            // In the previous versions, permissions were not the only data indexed using findex.
            // Before each object was upserted to the DB, its tags and some attributes were indexed as keywords.
            // In this step, we will re-perform this indexing using the new findex instance pointing to DB 1.
            // We do not need to read back the previously indexed keywords, instead we will re-generate them from the object
            // metadata the same way as it was done previously done (see the `keywords` method in objects_db.rs, around line 100).
            let object_with_metadata = self.retrieve(&obj_uid, None).await?.ok_or_else(|| {
                DbError::Default(format!(
                    "Failed to retrieve object {obj_uid} during migration"
                ))
            })?;
            let object = object_with_metadata.object();

            let tags = self.retrieve_tags(&obj_uid, None).await?;
            let mut keywords_to_be_indexed = tags
                .into_iter()
                .map(|tag| Keyword::from(tag.as_bytes()))
                .collect::<HashSet<Keyword>>();
            // index some of the attributes
            if let Ok(attributes) = object.attributes() {
                keywords_to_be_indexed.extend(keywords_from_attributes(attributes));
            }
            // index the owner too
            keywords_to_be_indexed.insert(Keyword::from(object_with_metadata.owner().as_bytes()));

            // finally, insert the new keywords
            let indexed_uid = IndexedValue::from(obj_uid.as_bytes());
            for keyword in keywords_to_be_indexed {
                findex_v8_db1.insert(keyword, [indexed_uid.clone()]).await?;
            }
        }

        // step 3: Move the object keys (do::*) and metadata keys to DB1
        // NOTICE!: this can also be batched if needed
        let metadata_keys = vec!["db_state", "db_version"];

        for key in &metadata_keys {
            let _: () = redis::cmd("MOVE")
                .arg(key)
                .arg(1)
                .query_async(&mut mgr_0)
                .await
                .map_err(|e| DbError::DatabaseError(format!("Failed to move key {key}: {e}")))?;
        }
        for key in &all_obj_keys {
            let _: () = redis::cmd("MOVE")
                .arg(key)
                .arg(1)
                .query_async(&mut mgr_0)
                .await
                .map_err(|e| DbError::DatabaseError(format!("Failed to move key {key}: {e}")))?;
        }

        // O(1) swap - all clients using DB 0 will now use DB 1
        // Notice!: in theory can set the db_state to Ready starting from here, as the cleanup (see below) will be performed in an ASYNC manner on DB 1 without blocking the main thread
        // unless a bottleneck is detected, keep this code as is
        let _: () = redis::cmd("SWAPDB")
            .arg(0)
            .arg(1)
            .exec(&mut redis::Client::open(db_0_url)?.get_connection()?)?;
        let _: () = redis::Client::open(db_1_url)?
            .get_connection()?
            .flushdb_options(&redis::FlushAllOptions { blocking: false })?;

        Ok(())
    }
}
