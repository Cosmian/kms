use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof::reexport::{
    crypto_core::{kdf256, FixedSizeCBytes, RandomFixedSizeCBytes, SymmetricKey},
    findex::{
        implementations::redis::FindexRedis, parameters::MASTER_KEY_LENGTH, IndexedValue, Keyword,
        Location,
    },
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, IsWrapped, ObjectOperationType},
    tagging::get_tags,
};
use redis::aio::ConnectionManager;
use uuid::Uuid;

use super::{
    objects_db::{keywords_from_attributes, ObjectsDB, RedisDbObject, DB_KEY_LENGTH},
    permissions::PermissionsDB,
};
use crate::{
    database::{object_with_metadata::ObjectWithMetadata, Database},
    kms_error,
    result::{KResult, KResultHelper},
};

pub const REDIS_WITH_FINDEX_MASTER_KEY_LENGTH: usize = 32;

/// Find the intersection of all the sets
fn intersect_all<I: IntoIterator<Item = HashSet<Location>>>(sets: I) -> HashSet<Location> {
    let mut iter = sets.into_iter();
    let first = iter.next().unwrap_or_default();
    iter.fold(first, |acc, set| acc.intersection(&set).cloned().collect())
}

pub struct RedisWithFindex {
    objects_db: Arc<ObjectsDB>,
    permissions_db: PermissionsDB,
    //TODO this Mutex should not be here; Findex needs to be changed to be thread-safe and not take &mut self
    findex: Arc<FindexRedis>,
    findex_key: SymmetricKey<MASTER_KEY_LENGTH>,
    label: Vec<u8>,
    _db_key: SymmetricKey<DB_KEY_LENGTH>,
}

impl RedisWithFindex {
    pub async fn instantiate(
        redis_url: &str,
        master_key: SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        label: &[u8],
    ) -> KResult<RedisWithFindex> {
        // derive a Findex Key
        let mut findex_key_bytes = [0; MASTER_KEY_LENGTH];
        kdf256!(&mut findex_key_bytes, b"findex", master_key.as_bytes());
        let findex_key = SymmetricKey::<MASTER_KEY_LENGTH>::try_from_bytes(findex_key_bytes)?;
        // derive a DB Key
        let mut db_key_bytes = [0; DB_KEY_LENGTH];
        kdf256!(&mut db_key_bytes, b"db", master_key.as_bytes());
        let _db_key = SymmetricKey::<DB_KEY_LENGTH>::try_from_bytes(db_key_bytes)?;

        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;
        let objects_db = Arc::new(ObjectsDB::new(mgr.clone()).await?);
        let findex =
            Arc::new(FindexRedis::connect_with_manager(mgr.clone(), objects_db.clone()).await?);
        let permissions_db = PermissionsDB::new(findex.clone(), label).await?;
        Ok(Self {
            objects_db,
            permissions_db,
            findex,
            findex_key,
            _db_key,
            label: label.to_vec(),
        })
    }
}

#[async_trait]
impl Database for RedisWithFindex {
    /// Return the filename of the database if supported
    fn filename(&self, _group_id: u128) -> PathBuf {
        PathBuf::from("")
    }

    /// Insert the given Object in the database.
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        tags: &HashSet<String>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier> {
        // If the uid is not provided, generate a new one
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        let indexed_value = IndexedValue::Location(Location::from(uid.as_bytes()));

        // the database object to index and store
        let db_object = RedisDbObject::new(
            object.clone(),
            owner.to_string(),
            StateEnumeration::Active,
            tags.clone(),
        );

        // extract the keywords
        let keywords = db_object.keywords();

        // additions to the index
        let mut additions = HashMap::new();
        additions.insert(indexed_value, keywords);

        //upsert the index
        self.findex
            .upsert(
                &self.findex_key.to_bytes(),
                &self.label,
                additions,
                HashMap::new(),
            )
            .await?;

        // upsert the object
        self.objects_db
            .object_upsert(
                &uid,
                &RedisDbObject::new(
                    object.clone(),
                    owner.to_string(),
                    StateEnumeration::Active,
                    tags.clone(),
                ),
            )
            .await?;

        Ok(UniqueIdentifier::from(uid))
    }

    /// Insert the provided Objects in the database in a transaction
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create_objects(
        &self,
        owner: &str,
        objects: &[(Option<String>, Object, &HashSet<String>)],
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>> {
        // If the uid is not provided, generate a new one
        let mut uids = vec![];
        let mut additions = HashMap::new();
        let mut db_objects = HashMap::new();
        for (uid, object, tags) in objects.iter() {
            let uid = uid.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
            let indexed_value = IndexedValue::Location(Location::from(uid.as_bytes()));

            // the database object to index and store
            let db_object = RedisDbObject::new(
                object.clone(),
                owner.to_string(),
                StateEnumeration::Active,
                (*tags).clone(),
            );

            // extract the keywords
            let keywords = db_object.keywords();

            // additions to the index
            additions.insert(indexed_value, keywords);

            //upsert the object
            db_objects.insert(uid.clone(), db_object);
            uids.push(uid);
        }

        //upsert the indexes
        self.findex
            .upsert(
                &self.findex_key.to_bytes(),
                &self.label,
                additions,
                HashMap::new(),
            )
            .await?;

        // upsert the objects
        self.objects_db.objects_upsert(&db_objects).await?;

        Ok(uids.into_iter().map(UniqueIdentifier::from).collect())
    }

    /// Retrieve objects from the database.
    ///
    /// The `uid_or_tags` parameter can be either a `uid` or a comma-separated list of tags
    /// in a JSON array.
    ///
    /// The `query_access_grant` allows additional filtering in the `access` table to see
    /// if a `user`, that is not a owner, has the corresponding access granted
    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        query_access_grant: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectWithMetadata>> {
        let uids = if uid_or_tags.starts_with('[') {
            let tags: HashSet<String> = serde_json::from_str(uid_or_tags)
                .with_context(|| format!("Invalid tags: {uid_or_tags}"))?;
            let keywords = tags
                .iter()
                .map(|tag| Keyword::from(tag.as_bytes()))
                .collect::<HashSet<Keyword>>();
            // find the locations that match at least one of the tags
            let res = self
                .findex
                .search(&self.findex_key.to_bytes(), &self.label, keywords)
                .await?;
            // we want the intersection of all the locations
            let locations = intersect_all(res.values().cloned());
            locations
                .into_iter()
                .map(|location| {
                    String::from_utf8(location.to_vec()).map_err(|_| kms_error!("Invalid uid"))
                })
                .collect::<KResult<HashSet<String>>>()?
        } else {
            // it is an UID
            HashSet::from([uid_or_tags.to_string()])
        };

        // now retrieve the object
        let results = self.objects_db.objects_get(&uids).await?;
        let mut objects: Vec<ObjectWithMetadata> = vec![];
        for (uid, redis_db_object) in results {
            // if the user is the owner, return it
            if redis_db_object.owner == user {
                objects.push(ObjectWithMetadata {
                    id: uid,
                    object: redis_db_object.object,
                    owner: redis_db_object.owner,
                    state: redis_db_object.state,
                    permissions: vec![],
                });
                continue
            }

            // fetch the permissions for the user
            let permissions = self
                .permissions_db
                .get(&self.findex_key, &uid, user)
                .await
                .unwrap_or_default();
            if permissions.contains(&query_access_grant) {
                objects.push(ObjectWithMetadata {
                    id: uid,
                    object: redis_db_object.object,
                    owner: redis_db_object.owner,
                    state: redis_db_object.state,
                    permissions: permissions.into_iter().collect(),
                });
            }
        }
        Ok(objects)
    }

    /// Retrieve the ags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        let redis_db_object = self.objects_db.object_get(uid).await?;
        Ok(redis_db_object.tags)
    }

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        tags: Option<&HashSet<String>>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut db_object = self.objects_db.object_get(uid).await?;
        db_object.object = object.clone();
        if let Some(tags) = tags {
            db_object.tags = tags.clone();
        }
        self.objects_db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut db_object = self.objects_db.object_get(uid).await?;
        db_object.state = state;
        self.objects_db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    /// upsert (update or create if not exists)
    async fn upsert(
        &self,
        uid: &str,
        owner: &str,
        object: &Object,
        tags: &HashSet<String>,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.create(Some(uid.to_owned()), owner, object, tags, params)
            .await?;
        if state != StateEnumeration::Active {
            self.update_state(uid, state, params).await?;
        }
        Ok(())
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db_object = self.objects_db.object_get(uid).await?;
        if db_object.owner != user {
            return Err(kms_error!("User is not the owner of the object"))
        }
        self.objects_db.object_delete(uid).await?;
        Ok(())
    }

    async fn list_access_rights_obtained(
        &self,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<
        Vec<(
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationType>,
            IsWrapped,
        )>,
    > {
        let permissions = self
            .permissions_db
            .list_user_permissions(&self.findex_key, user)
            .await?;
        let redis_db_objects = self
            .objects_db
            .objects_get(
                &permissions
                    .keys()
                    .map(|uid| uid.to_owned())
                    .collect::<HashSet<String>>(),
            )
            .await?;
        Ok(permissions
            .into_iter()
            .zip(redis_db_objects)
            .map(|((uid, permissions), (_, redis_db_object))| {
                (
                    UniqueIdentifier::from(uid),
                    redis_db_object.owner,
                    redis_db_object.state,
                    permissions
                        .into_iter()
                        .collect::<Vec<ObjectOperationType>>(),
                    false, // TODO: de-hardcode this value by updating the query. See issue: http://gitlab.cosmian.com/core/kms/-/issues/15
                )
            })
            .collect())
    }

    /// List all the accessed granted per `user`
    /// This is called by the owner only
    async fn list_accesses(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, Vec<ObjectOperationType>)>> {
        let permissions = self
            .permissions_db
            .list_object_permissions(&self.findex_key, uid)
            .await?;
        Ok(permissions
            .into_iter()
            .map(|(user, permissions)| (user, permissions.into_iter().collect()))
            .collect())
    }

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_access(
        &self,
        uid: &str,
        user: &str,
        operation_type: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.permissions_db
            .add(&self.findex_key, uid, user, operation_type)
            .await?;
        Ok(())
    }

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_access(
        &self,
        uid: &str,
        user: &str,
        operation_type: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.permissions_db
            .remove(&self.findex_key, uid, user, operation_type)
            .await?;
        Ok(())
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        self.objects_db
            .object_get(uid)
            .await
            .map(|object| object.owner == owner)
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>> {
        let mut keywords = {
            if let Some(attributes) = researched_attributes {
                let tags = get_tags(attributes);
                let mut keywords = tags
                    .iter()
                    .map(|tag| Keyword::from(tag.as_bytes()))
                    .collect::<HashSet<Keyword>>();
                // index some of the attributes
                keywords.extend(keywords_from_attributes(attributes));
                keywords
            } else {
                HashSet::new()
            }
        };
        if user_must_be_owner {
            keywords.insert(Keyword::from(user.as_bytes()));
        }
        // if there are now keywords, we return an empty list
        if keywords.is_empty() {
            return Ok(vec![])
        }
        // search the keywords in the index
        let res = self
            .findex
            .search(&self.findex_key.to_bytes(), &self.label, keywords)
            .await?;
        // we want the intersection of all the locations
        let locations = intersect_all(res.values().cloned());
        let uids = locations
            .into_iter()
            .map(|location| {
                String::from_utf8(location.to_vec()).map_err(|_| kms_error!("Invalid uid"))
            })
            .collect::<KResult<HashSet<String>>>()?;
        // if the user is not the owner, we need to check the permissions
        let uids = if !user_must_be_owner {
            let permissions = self
                .permissions_db
                .list_user_permissions(&self.findex_key, user)
                .await?;
            uids.into_iter()
                .filter(|uid| permissions.contains_key(uid))
                .collect::<HashSet<String>>()
        } else {
            uids
        };

        // fetch the corresponding objects
        let redis_db_objects = self.objects_db.objects_get(&uids).await?;
        Ok(redis_db_objects
            .into_iter()
            .filter(|(_uid, redis_db_object)| {
                if let Some(state) = state {
                    redis_db_object.state == state
                } else {
                    true
                }
            })
            .map(|(uid, redis_db_object)| {
                (
                    UniqueIdentifier::from(uid),
                    redis_db_object.state,
                    redis_db_object
                        .object
                        .attributes()
                        .cloned()
                        .unwrap_or_else(|_| Attributes::new(redis_db_object.object.object_type())),
                    false, // TODO: de-hardcode this value by updating the query. See issue: http://gitlab.cosmian.com/core/kms/-/issues/15
                )
            })
            .collect())
    }

    #[cfg(test)]
    async fn perms(
        &self,
        uid: &str,
        userid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectOperationType>> {
        Ok(self
            .permissions_db
            .get(&self.findex_key, uid, userid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cloudproof::reexport::findex::Location;

    #[test]
    fn test_intersect() {
        let set1: HashSet<_> = vec![
            Location::from(b"1".as_slice()),
            Location::from(b"2".as_slice()),
            Location::from(b"3".as_slice()),
            Location::from(b"4".as_slice()),
        ]
        .into_iter()
        .collect();
        let set2: HashSet<_> = vec![
            Location::from(b"2".as_slice()),
            Location::from(b"3".as_slice()),
            Location::from(b"4".as_slice()),
            Location::from(b"5".as_slice()),
        ]
        .into_iter()
        .collect();
        let set3: HashSet<_> = vec![
            Location::from(b"3".as_slice()),
            Location::from(b"4".as_slice()),
            Location::from(b"5".as_slice()),
            Location::from(b"6".as_slice()),
        ]
        .into_iter()
        .collect();

        let sets = vec![set1, set2, set3];
        let res = super::intersect_all(sets);
        assert_eq!(res.len(), 2);
        assert!(res.contains(&Location::from(b"3".as_slice())));
        assert!(res.contains(&Location::from(b"4".as_slice())));
    }
}
