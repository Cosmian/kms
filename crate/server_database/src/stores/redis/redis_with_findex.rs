use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
#[cfg(feature = "non-fips")]
use cloudproof_findex::{
    IndexedValue, Keyword, Label, Location, implementations::redis::FindexRedis,
    parameters::MASTER_KEY_LENGTH,
};
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_crypto::{
    crypto::password_derivation::derive_key_from_password,
    reexport::cosmian_crypto_core::{FixedSizeCBytes, Secret, SymmetricKey, kdf256},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceResult, ObjectWithMetadata, ObjectsStore, PermissionsStore,
    SessionParams,
};
use cosmian_logger::trace;
use redis::aio::ConnectionManager;
use uuid::Uuid;

use super::{
    objects_db::{DB_KEY_LENGTH, ObjectsDB, RedisDbObject, keywords_from_attributes},
    permissions::PermissionsDB,
};
use crate::{
    db_error,
    error::{DbError, DbResult},
    stores::{migrate::DbState, redis::objects_db::RedisOperation},
};

pub(crate) const REDIS_WITH_FINDEX_MASTER_KEY_LENGTH: usize = 32;
const REDIS_WITH_FINDEX_MASTER_KEY_DERIVATION_SALT: &[u8; 16] = b"rediswithfindex_";
pub(crate) const REDIS_WITH_FINDEX_MASTER_FINDEX_KEY_DERIVATION_SALT: &[u8; 6] = b"findex";
pub(crate) const REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT: &[u8; 2] = b"db";

/// Derive a Redis Master Key from a password
pub fn redis_master_key_from_password(
    master_password: &str,
) -> DbResult<SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>> {
    let output_key_material = derive_key_from_password::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>(
        REDIS_WITH_FINDEX_MASTER_KEY_DERIVATION_SALT,
        master_password.as_bytes(),
    )?;

    let master_secret_key: SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH> =
        SymmetricKey::try_from_slice(&output_key_material)?;

    Ok(master_secret_key)
}

/// Find the intersection of all the sets
fn intersect_all<I: IntoIterator<Item = HashSet<Location>>>(sets: I) -> HashSet<Location> {
    let mut iter = sets.into_iter();
    let first = iter.next().unwrap_or_default();
    iter.fold(first, |acc, set| acc.intersection(&set).cloned().collect())
}

#[derive(Clone)]
pub(crate) struct RedisWithFindex {
    pub(crate) mgr: ConnectionManager,
    objects_db: Arc<ObjectsDB>,
    permissions_db: PermissionsDB,
    findex: Arc<FindexRedis>,
    findex_key: SymmetricKey<MASTER_KEY_LENGTH>,
    label: Label,
}

impl RedisWithFindex {
    pub(crate) async fn instantiate(
        redis_url: &str,
        master_key: Secret<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        label: &[u8],
        clear_database: bool,
    ) -> DbResult<Self> {
        // derive an Findex Key
        let mut findex_key = SymmetricKey::<MASTER_KEY_LENGTH>::default();
        kdf256!(
            &mut *findex_key,
            REDIS_WITH_FINDEX_MASTER_FINDEX_KEY_DERIVATION_SALT,
            &*master_key
        );
        // derive a DB Key
        let mut db_key = SymmetricKey::<DB_KEY_LENGTH>::default();
        kdf256!(
            &mut *db_key,
            REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT,
            &*master_key
        );

        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;
        let objects_db = Arc::new(ObjectsDB::new(mgr.clone(), &db_key));
        let findex =
            Arc::new(FindexRedis::connect_with_manager(mgr.clone(), objects_db.clone()).await?);
        let permissions_db = PermissionsDB::new(findex.clone(), label);

        if clear_database {
            redis::cmd("FLUSHDB")
                .query_async::<_, ()>(&mut mgr.clone())
                .await?;
        }

        let count: usize = redis::cmd("DBSIZE")
            .query_async(&mut mgr.clone())
            .await
            .map_err(|e| DbError::DatabaseError(format!("Failed to get Redis DB size: {e}")))?;
        trace!("Redis DB size: {count}");

        let redis_with_findex = Self {
            mgr,
            objects_db,
            permissions_db,
            findex,
            findex_key,
            label: Label::from(label),
        };

        if count == 0 {
            redis_with_findex
                .set_current_db_version(env!("CARGO_PKG_VERSION"))
                .await?;
            redis_with_findex.set_db_state(DbState::Ready).await?;
        } else {
            redis_with_findex.migrate().await?;
        }

        Ok(redis_with_findex)
    }

    /// Prepare an object for upsert
    /// Note: Findex indexes are upserted even if the object is not upserted later on
    #[allow(clippy::too_many_arguments)]
    async fn prepare_object_for_upsert(
        &self,
        uid: &str,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        state: State,
        params: Option<Arc<dyn SessionParams>>,
    ) -> Result<RedisDbObject, DbError> {
        // additions to the index
        let mut index_additions = HashMap::new();

        //replace the existing tags (if any) with the new ones (if provided)
        let tags = if let Some(tags) = tags {
            tags.clone()
        } else {
            self.retrieve_tags(uid, params).await?
        };
        // the database object to index and store
        let db_object = RedisDbObject::new(
            object.clone(),
            owner.to_owned(),
            state,
            Some(tags.clone()),
            attributes.clone(),
        );
        // extract the keywords
        index_additions.insert(
            IndexedValue::Location(Location::from(uid.as_bytes())),
            db_object.keywords(),
        );

        // upsert the index
        self.findex
            .upsert(
                &self.findex_key.to_bytes(),
                &self.label,
                index_additions,
                HashMap::new(),
            )
            .await?;
        Ok(db_object)
    }

    async fn prepare_object_for_create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> Result<(String, RedisDbObject), DbError> {
        // If the uid is not provided, generate a new one
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        let db_object = self
            .prepare_object_for_upsert(
                &uid,
                owner,
                object,
                attributes,
                Some(tags),
                State::Active,
                None,
            )
            .await?;
        Ok((uid, db_object))
    }

    async fn prepare_object_for_update(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> Result<RedisDbObject, DbError> {
        let mut db_object = self
            .objects_db
            .object_get(uid)
            .await?
            .ok_or_else(|| DbError::ItemNotFound(uid.to_owned()))?;
        db_object.object = object.clone();
        if tags.is_some() {
            db_object.tags = tags.cloned();
        }
        db_object.attributes = Some(attributes.clone());

        // updates to the index;
        // note: these are additions so some entries will be doubled but shat should not break the index
        // and will be removed during compaction
        let mut index_additions = HashMap::new();
        // extract the keywords
        index_additions.insert(
            IndexedValue::Location(Location::from(uid.as_bytes())),
            db_object.keywords(),
        );
        // upsert the index
        self.findex
            .upsert(
                &self.findex_key.to_bytes(),
                &self.label,
                index_additions,
                HashMap::new(),
            )
            .await?;
        Ok(db_object)
    }

    async fn prepare_object_for_state_update(
        &self,
        uid: &str,
        state: State,
    ) -> Result<RedisDbObject, DbError> {
        let mut db_object = self
            .objects_db
            .object_get(uid)
            .await?
            .ok_or_else(|| DbError::ItemNotFound(uid.to_owned()))?;
        db_object.state = state;
        // The state is not indexed, so no updates there
        Ok(db_object)
    }
}

#[async_trait(?Send)]
impl ObjectsStore for RedisWithFindex {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
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
        attributes: &Attributes,
        tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<String> {
        let (uid, db_object) = self
            .prepare_object_for_create(uid, owner, object, attributes, tags)
            .await?;

        // create the object
        self.objects_db.object_create(&uid, &db_object).await?;

        Ok(uid)
    }

    /// Retrieve objects from the database.
    ///
    /// The `uid_or_tags` parameter can be either a `uid` or a comma-separated list of tags
    /// in a JSON array.
    async fn retrieve(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Option<ObjectWithMetadata>> {
        Ok(self.objects_db.object_get(uid).await.map(|o| {
            o.map(|o| {
                ObjectWithMetadata::new(
                    uid.to_owned(),
                    o.object,
                    o.owner,
                    o.state,
                    o.attributes.unwrap_or_default(),
                )
            })
        })?)
    }

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        Ok(self
            .objects_db
            .object_get(uid)
            .await?
            .map(|o| o.tags.unwrap_or_default())
            .unwrap_or_default())
    }

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let db_object = self
            .prepare_object_for_update(uid, object, attributes, tags)
            .await?;
        self.objects_db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    async fn update_state(
        &self,
        uid: &str,
        state: State,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let db_object = self.prepare_object_for_state_update(uid, state).await?;
        self.objects_db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    async fn delete(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        if let Some(_db_object) = self.objects_db.object_get(uid).await? {
            self.objects_db.object_delete(uid).await?;
        }
        Ok(())
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<String>> {
        let mut redis_operations: Vec<RedisOperation> = Vec::with_capacity(operations.len());
        for operation in operations {
            match operation {
                AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                    //TODO: this operation contains a non atomic retrieve_tags. It will be hard to make this whole method atomic
                    let db_object = self
                        .prepare_object_for_upsert(
                            uid,
                            user,
                            object,
                            attributes,
                            tags.as_ref(),
                            *state,
                            params.clone(),
                        )
                        .await?;
                    redis_operations.push(RedisOperation::Upsert(uid.clone(), db_object));
                }
                AtomicOperation::Create((uid, object, attributes, tags)) => {
                    let (uid, db_object) = self
                        .prepare_object_for_create(
                            Some(uid.clone()),
                            user,
                            object,
                            attributes,
                            tags,
                        )
                        .await?;
                    redis_operations.push(RedisOperation::Create(uid, db_object));
                }
                AtomicOperation::Delete(uid) => {
                    redis_operations.push(RedisOperation::Delete(uid.clone()));
                }
                AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                    //TODO: this operation contains a non atomic retrieve_object. It will be hard to make this whole method atomic
                    let db_object = self
                        .prepare_object_for_update(uid, object, attributes, tags.as_ref())
                        .await?;
                    redis_operations.push(RedisOperation::Upsert(uid.clone(), db_object));
                }
                AtomicOperation::UpdateState((uid, state)) => {
                    //TODO: this operation contains a non atomic retrieve_object. It will be hard to make this whole method atomic
                    let db_object = self.prepare_object_for_state_update(uid, *state).await?;
                    redis_operations.push(RedisOperation::Upsert(uid.clone(), db_object));
                }
            }
        }
        Ok(self.objects_db.atomic(&redis_operations).await?)
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<bool> {
        let object = self
            .objects_db
            .object_get(uid)
            .await?
            .ok_or_else(|| DbError::ItemNotFound(uid.to_owned()))?;
        Ok(object.owner == owner)
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        let keywords = tags
            .iter()
            .map(|tag| Keyword::from(tag.as_bytes()))
            .collect::<HashSet<Keyword>>();
        // find the locations that match at least one of the tags
        let res = self
            .findex
            .search(&self.findex_key.to_bytes(), &self.label, keywords)
            .await
            .map_err(|e| db_error!(format!("Error while searching for tags: {e:?}")))?;
        // we want the intersection of all the locations
        let locations = intersect_all(res.values().cloned());
        Ok(locations
            .into_iter()
            .map(|location| {
                String::from_utf8(location.to_vec())
                    .map_err(|e| db_error!(format!("Invalid uid. Error: {e:?}")))
            })
            .collect::<DbResult<HashSet<String>>>()?)
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let mut keywords = {
            researched_attributes.map_or_else(HashSet::new, |attributes| {
                let tags = attributes.get_tags();
                trace!("find: tags: {tags:?}");
                let mut keywords = tags
                    .iter()
                    .map(|tag| Keyword::from(tag.as_bytes()))
                    .collect::<HashSet<Keyword>>();
                // index some of the attributes
                keywords.extend(keywords_from_attributes(attributes));
                keywords
            })
        };
        if user_must_be_owner {
            trace!("find: user must be owner");
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
            .await
            .map_err(|e| db_error!(format!("Error while searching for attributes: {e:?}")))?;
        trace!("find: res: {:?}", res);
        // we want the intersection of all the locations
        let locations = intersect_all(res.values().cloned());
        let uids = locations
            .into_iter()
            .map(|location| {
                String::from_utf8(location.to_vec())
                    .map_err(|e| db_error!(format!("Invalid uid. Error: {e:?}")))
            })
            .collect::<DbResult<HashSet<String>>>()?;
        trace!("find: uids before permissions: {:?}", uids);
        // if the user is not the owner, we need to check the permissions
        let permissions = if user_must_be_owner {
            HashMap::new()
        } else {
            self.permissions_db
                .list_user_permissions(&self.findex_key, user)
                .await?
        };

        // fetch the corresponding objects
        let redis_db_objects = self.objects_db.objects_get(&uids).await?;
        Ok(redis_db_objects
            .into_iter()
            .filter(|(uid, redis_db_object)| {
                state.is_none_or(|state| redis_db_object.state == state)
                    && (if redis_db_object.owner == user {
                        true
                    } else {
                        permissions.contains_key(uid)
                    })
            })
            .map(|(uid, redis_db_object)| {
                (
                    uid,
                    redis_db_object.state,
                    redis_db_object
                        .object
                        .attributes()
                        .cloned()
                        .unwrap_or_else(|_| Attributes {
                            object_type: Some(redis_db_object.object.object_type()),
                            ..Default::default()
                        }),
                )
            })
            .collect())
    }
}

#[async_trait(?Send)]
impl PermissionsStore for RedisWithFindex {
    async fn list_user_operations_granted(
        &self,
        user: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        let permissions = self
            .permissions_db
            .list_user_permissions(&self.findex_key, user)
            .await?;
        let redis_db_objects = self
            .objects_db
            .objects_get(&permissions.keys().cloned().collect::<HashSet<String>>())
            .await?;
        Ok(permissions
            .into_iter()
            .zip(redis_db_objects)
            .map(|((uid, permissions), (_, redis_db_object))| {
                (
                    uid,
                    (
                        redis_db_object.owner,
                        redis_db_object.state,
                        permissions.into_iter().collect::<HashSet<KmipOperation>>(),
                    ),
                )
            })
            .collect())
    }

    /// List all the accessed granted per `user`
    /// This is called by the owner only
    async fn list_object_operations_granted(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(self
            .permissions_db
            .list_object_permissions(&self.findex_key, uid)
            .await?)
    }

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        for operation in &operation_types {
            self.permissions_db
                .add(&self.findex_key, uid, user, *operation)
                .await?;
        }
        Ok(())
    }

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        for operation in &operation_types {
            self.permissions_db
                .remove(&self.findex_key, uid, user, *operation)
                .await?;
        }
        Ok(())
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        Ok(self
            .permissions_db
            .get(&self.findex_key, uid, user, no_inherited_access)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cloudproof_findex::Location;

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
