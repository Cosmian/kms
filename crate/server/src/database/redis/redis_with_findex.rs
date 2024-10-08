use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof::reexport::crypto_core::{kdf256, FixedSizeCBytes, SymmetricKey};
use cloudproof_findex::{
    implementations::redis::FindexRedis, parameters::MASTER_KEY_LENGTH, IndexedValue, Keyword,
    Label, Location,
};
use cosmian_kmip::{
    crypto::{password_derivation::derive_key_from_password, secret::Secret},
    kmip::{
        kmip_objects::Object,
        kmip_types::{Attributes, StateEnumeration},
    },
};
use cosmian_kms_client::access::{IsWrapped, ObjectOperationType};
use redis::aio::ConnectionManager;
use tracing::trace;
use uuid::Uuid;

use super::{
    objects_db::{keywords_from_attributes, ObjectsDB, RedisDbObject, DB_KEY_LENGTH},
    permissions::PermissionsDB,
};
use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{
        database_trait::AtomicOperation, object_with_metadata::ObjectWithMetadata,
        redis::objects_db::RedisOperation, Database,
    },
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

pub(crate) const REDIS_WITH_FINDEX_MASTER_KEY_LENGTH: usize = 32;
pub(crate) const REDIS_WITH_FINDEX_MASTER_KEY_DERIVATION_SALT: &[u8; 16] = b"rediswithfindex_";
pub(crate) const REDIS_WITH_FINDEX_MASTER_FINDEX_KEY_DERIVATION_SALT: &[u8; 6] = b"findex";
pub(crate) const REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT: &[u8; 2] = b"db";

/// Find the intersection of all the sets
fn intersect_all<I: IntoIterator<Item = HashSet<Location>>>(sets: I) -> HashSet<Location> {
    let mut iter = sets.into_iter();
    let first = iter.next().unwrap_or_default();
    iter.fold(first, |acc, set| acc.intersection(&set).cloned().collect())
}

pub(crate) struct RedisWithFindex {
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
    ) -> KResult<Self> {
        // derive a Findex Key
        let mut findex_key = SymmetricKey::<MASTER_KEY_LENGTH>::default();
        kdf256!(
            &mut findex_key,
            REDIS_WITH_FINDEX_MASTER_FINDEX_KEY_DERIVATION_SALT,
            &*master_key
        );
        // derive a DB Key
        let mut db_key = SymmetricKey::<DB_KEY_LENGTH>::default();
        kdf256!(
            &mut db_key,
            REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT,
            &*master_key
        );

        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;
        let objects_db = Arc::new(ObjectsDB::new(mgr.clone(), &db_key));
        let findex =
            Arc::new(FindexRedis::connect_with_manager(mgr.clone(), objects_db.clone()).await?);
        let permissions_db = PermissionsDB::new(findex.clone(), label);
        Ok(Self {
            objects_db,
            permissions_db,
            findex,
            findex_key,
            label: Label::from(label),
        })
    }

    pub(crate) fn master_key_from_password(
        master_password: &str,
    ) -> KResult<SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>> {
        let output_key_material = derive_key_from_password::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>(
            REDIS_WITH_FINDEX_MASTER_KEY_DERIVATION_SALT,
            master_password.as_bytes(),
        )?;

        let master_secret_key: SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH> =
            SymmetricKey::try_from_slice(&output_key_material)?;

        Ok(master_secret_key)
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
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> Result<RedisDbObject, KmsError> {
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
    ) -> Result<(String, RedisDbObject), KmsError> {
        // If the uid is not provided, generate a new one
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        let db_object = self
            .prepare_object_for_upsert(
                &uid,
                owner,
                object,
                attributes,
                Some(tags),
                StateEnumeration::Active,
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
    ) -> Result<RedisDbObject, KmsError> {
        let mut db_object = self
            .objects_db
            .object_get(uid)
            .await?
            .ok_or_else(|| KmsError::ItemNotFound(uid.to_owned()))?;
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
        state: StateEnumeration,
    ) -> Result<RedisDbObject, KmsError> {
        let mut db_object = self
            .objects_db
            .object_get(uid)
            .await?
            .ok_or_else(|| KmsError::ItemNotFound(uid.to_owned()))?;
        db_object.state = state;
        // The state is not indexed, so no updates there
        Ok(db_object)
    }
}

#[async_trait(?Send)]
impl Database for RedisWithFindex {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn migrate(&self, _params: Option<&ExtraDatabaseParams>) -> KResult<()> {
        unimplemented!("Redis-with-Findex does not support migrate operation");
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
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<String> {
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
    ///
    /// The `query_access_grant` allows additional filtering in the `access` table to see
    /// if a `user`, that is not a owner, has the corresponding access granted
    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        query_access_grant: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, ObjectWithMetadata>> {
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
                    String::from_utf8(location.to_vec())
                        .map_err(|e| kms_error!(format!("Invalid uid. Error: {e:?}")))
                })
                .collect::<KResult<HashSet<String>>>()?
        } else {
            // it is an UID
            HashSet::from([uid_or_tags.to_owned()])
        };

        // now retrieve the object
        let results = self.objects_db.objects_get(&uids).await?;
        let mut objects: HashMap<String, ObjectWithMetadata> = HashMap::new();
        for (uid, redis_db_object) in results {
            // if the user is the owner, return it
            if redis_db_object.owner == user {
                objects.insert(
                    uid.clone(),
                    ObjectWithMetadata {
                        id: uid,
                        object: redis_db_object.object,
                        owner: redis_db_object.owner,
                        state: redis_db_object.state,
                        permissions: vec![],
                        attributes: redis_db_object.attributes.unwrap_or_default(),
                    },
                );
                continue
            }

            // fetch the permissions for the user and the wildcard user
            let permissions: HashSet<ObjectOperationType> = self
                .permissions_db
                .get(&self.findex_key, &uid, user, false)
                .await
                .unwrap_or_default();
            if permissions.contains(&query_access_grant) {
                objects.insert(
                    uid.clone(),
                    ObjectWithMetadata {
                        id: uid,
                        object: redis_db_object.object,
                        owner: redis_db_object.owner,
                        state: redis_db_object.state,
                        permissions: permissions.into_iter().collect(),
                        attributes: redis_db_object.attributes.unwrap_or_default(),
                    },
                );
            }
        }
        Ok(objects)
    }

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
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
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db_object = self
            .prepare_object_for_update(uid, object, attributes, tags)
            .await?;
        self.objects_db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db_object = self.prepare_object_for_state_update(uid, state).await?;
        self.objects_db.object_upsert(uid, &db_object).await?;
        Ok(())
    }

    /// Upsert (update or create if does not exist)
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db_object = self
            .prepare_object_for_upsert(uid, user, object, attributes, tags, state, params)
            .await?;

        // upsert the object
        self.objects_db.object_upsert(uid, &db_object).await?;

        Ok(())
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(db_object) = self.objects_db.object_get(uid).await? {
            if db_object.owner != user {
                kms_bail!("User is not the owner of the object");
            }
            self.objects_db.object_delete(uid).await?;
        }
        Ok(())
    }

    async fn list_user_granted_access_rights(
        &self,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, (String, StateEnumeration, HashSet<ObjectOperationType>)>> {
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
                        permissions
                            .into_iter()
                            .collect::<HashSet<ObjectOperationType>>(),
                    ),
                )
            })
            .collect())
    }

    /// List all the accessed granted per `user`
    /// This is called by the owner only
    async fn list_object_accesses_granted(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>> {
        self.permissions_db
            .list_object_permissions(&self.findex_key, uid)
            .await
    }

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        for operation in &operation_types {
            self.permissions_db
                .add(&self.findex_key, uid, user, *operation)
                .await?;
        }
        Ok(())
    }

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        for operation in &operation_types {
            self.permissions_db
                .remove(&self.findex_key, uid, user, *operation)
                .await?;
        }
        Ok(())
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        let object = self
            .objects_db
            .object_get(uid)
            .await?
            .ok_or_else(|| KmsError::ItemNotFound(uid.to_owned()))?;
        Ok(object.owner == owner)
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
    ) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>> {
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
            .await?;
        trace!("find: res: {:?}", res);
        // we want the intersection of all the locations
        let locations = intersect_all(res.values().cloned());
        let uids = locations
            .into_iter()
            .map(|location| {
                String::from_utf8(location.to_vec())
                    .map_err(|e| kms_error!(format!("Invalid uid. Error: {e:?}")))
            })
            .collect::<KResult<HashSet<String>>>()?;
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
                state.map_or(true, |state| redis_db_object.state == state)
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
                    false, // TODO: de-hardcode this value by updating the query. See issue: http://gitlab.cosmian.com/core/kms/-/issues/15
                )
            })
            .collect())
    }

    async fn list_user_access_rights_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<ObjectOperationType>> {
        Ok(self
            .permissions_db
            .get(&self.findex_key, uid, user, no_inherited_access)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect())
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
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
                            params,
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
        self.objects_db.atomic(&redis_operations).await
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
