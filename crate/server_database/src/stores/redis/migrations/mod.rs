#![allow(
    dead_code,
    clippy::unwrap_used,
    unused_imports,
    unused_variables,
    clippy::all
)] // TODO: del this later

pub(crate) mod redis_4_5_0_to_5_8_1; // This is *ONLY* marked as pub(crate) to allow auto-converting to/from LegacyDbError in DbError.

use async_trait::async_trait;
use cosmian_findex::IndexADT;
use cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore};
use redis::aio::{ConnectionLike, ConnectionManager};
use std::{collections::HashSet, str, sync::Arc};
use strum::EnumCount;
// use cosmian_kms_interfaces::PermissionsStore;
use cosmian_logger::warn;
use uuid::Uuid;

use crate::{
    DbError,
    error::DbResult,
    stores::{
        RedisWithFindex,
        migrate::{DbState, Migrate, MigrateTo590Parameters, RedisMigrate},
        redis::{
            findex::{FindexRedis, IndexedValue, Keyword},
            init_findex_redis,
            migrations::redis_4_5_0_to_5_8_1::RedisWithFindex as LegacyRedisWithFindex,
            objects_db::keywords_from_attributes,
            permissions::{ObjectUid, PermissionsDB, UserId},
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
        const fn is_valid_uuid(s: &str) -> bool {
            Uuid::try_parse(s).is_ok()
        }
        let db_0_url = format!("{}/0", parameters.redis_url);
        let db_1_url = format!("{}/1", parameters.redis_url);

        let client_0 = redis::Client::open(db_0_url.clone())?;
        let mut mgr_0 = ConnectionManager::new(client_0).await?;

        let all_obj_keys: Vec<String> = redis::cmd("KEYS")
            .arg("do::*")
            .query_async(&mut mgr_0)
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
        // this store will read from DB 0
        let legacy_findex_redis_store = LegacyRedisWithFindex::instantiate(
            &db_0_url,
            parameters.findex_key, // TODO: this clone is pretty much debatable
            &parameters.label,
            false,
        )
        .await?;

        // we will also create a findex_v8 instance that will write to DB 1
        let findex_arc: Arc<FindexRedis> =
            Arc::new(init_findex_redis(&parameters.findex_key, &db_1_url).await?);
        let migration_perm_db = PermissionsDB::new(findex_arc.clone());

        // step: perm triplets migration

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

        // Now, same things for tags
        for obj_uid in all_object_uids {
            // NOTICE: it can tempting to do tags = self.retrieve_tags(&obj_uid, None).await?; and stop there.
            // However, the `keywords` method of the ObjectDb, we can noticed (line 100) that tags are not the only data
            // being indexed
            let object_with_metadata = self.retrieve(&obj_uid, None).await?.unwrap(); // TODO: no unwrap
            let object = object_with_metadata.object().clone();

            let tags = self.retrieve_tags(&obj_uid, None).await?;
            let mut keywords = tags
                .into_iter()
                .map(|tag| Keyword::from(tag.as_bytes()))
                .collect::<HashSet<Keyword>>();
            // index some of the attributes
            if let Ok(attributes) = object.attributes() {
                keywords.extend(keywords_from_attributes(attributes));
            }
            // index the owner
            keywords.insert(Keyword::from(object_with_metadata.owner().as_bytes()));

            // insert the new keywords
            let indexed_uid = IndexedValue::from(obj_uid.as_bytes());

            for keyword in keywords {
                findex_arc.insert(keyword, [indexed_uid.clone()]).await?;
            }
        }

        // tag deletion flow

        Ok(())
    }
}
