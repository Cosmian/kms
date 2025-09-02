use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof_findex::{
    Location,
    implementations::redis::{FindexRedisError, RemovedLocationsFinder},
};
use cosmian_kmip::kmip_2_1::KmipOperation;
use serde::{Deserialize, Serialize};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{FixedSizeCBytes, SymmetricKey};

use crate::{
    DbError,
    error::DbResult,
    stores::{
        REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
        redis::{
            findex::{IndexedValue, Keyword},
            redis_with_findex::FindexRedis,
        },
    },
};

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub(crate) struct ObjectUid(String);

impl From<&ObjectUid> for Keyword {
    fn from(uid: &ObjectUid) -> Self {
        Keyword::from(format!("p:o:{}", uid.0).as_bytes())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub(crate) struct UserId(String);

impl From<&UserId> for Keyword {
    fn from(uid: &UserId) -> Self {
        Keyword::from(format!("p:u:{}", uid.0).as_bytes())
    }
}
/// TODO: delete the docs below
/// The new structure will be a dual index in order to be able to make efficient O(1)
/// reverse lookups for the objects and the users
/// Basically we will store :
/// User Index: user_id → HashSet<Triple>
/// Object Index: obj_uid → HashSet<Triple>
///
/// In order to be able to reverse lookup
/// The struct we store for each permission.
/// We store the permission itself as a Location.
/// Keeping the object uid and user id is necessary to be able to query
/// the database for all permissions for a given object or user because
/// there is no convenient access to the callback for a search
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub(crate) struct Triple {
    obj_uid: ObjectUid,
    user_id: UserId,
    permission: KmipOperation,
}

impl Triple {
    pub(crate) fn new(obj_uid: &str, user_id: &str, permission: KmipOperation) -> Self {
        Self {
            obj_uid: ObjectUid(obj_uid.to_owned()),
            user_id: UserId(user_id.to_owned()),
            permission,
        }
    }

    pub(crate) fn permissions_per_user(
        list: HashSet<Self>,
    ) -> HashMap<UserId, HashSet<KmipOperation>> {
        let mut map = HashMap::new();
        for triple in list {
            let entry = map.entry(triple.user_id).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }

    pub(crate) fn permissions_per_object(
        list: HashSet<Self>,
    ) -> HashMap<ObjectUid, HashSet<KmipOperation>> {
        let mut map = HashMap::new();
        for triple in list {
            let entry = map.entry(triple.obj_uid).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }
}

impl TryFrom<&IndexedValue> for Triple {
    type Error = DbError;

    fn try_from(value: &IndexedValue) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|e| DbError::ConversionError(e.to_string()))
    }
}

impl TryFrom<&Triple> for IndexedValue {
    // TODO: this should be From as it cannot fail...?
    type Error = DbError;

    fn try_from(value: &Triple) -> Result<Self, Self::Error> {
        Ok(Self::from(serde_json::to_vec(value)?))
    }
}

/// PermissionsDB is a database entirely built on top of Findex that stores the permissions
/// using a dual index pattern for efficient lookups as there is no wildcard support.
/// For each permission triple (user_id, obj_uid, permission), we store it twice under:
/// - The user id: `u::{user_id}` → (user_id, obj_uid, permission)
/// - The object uid: `o::{obj_uid}` → (user_id, obj_uid, permission)
///
/// By explicitly maintaining both indexes, we avoid the need for wildcard searches
/// which are not supported by Findex yet needed if we want to list all permissions
/// for a given user OR object in a same `PermissionsDB`.
#[derive(Clone)]
pub(crate) struct PermissionsDB {
    findex: Arc<FindexRedis>,
}

impl PermissionsDB {
    pub(crate) fn new(findex: Arc<FindexRedis>) -> Self {
        Self { findex }
    }

    /// Search for a keyword
    async fn search_one_keyword(&self, keyword: Keyword) -> DbResult<HashSet<Triple>> {
        self.findex
            .search(&keyword)
            .await?
            .iter()
            .map(Triple::try_from)
            .collect::<DbResult<HashSet<Triple>>>()
    }

    /// List all the permissions granted to an user
    /// per object uid
    pub(crate) async fn list_user_permissions(
        &self,
        user_id: &UserId,
    ) -> DbResult<HashMap<ObjectUid, HashSet<KmipOperation>>> {
        let all_user_permissions = self.search_one_keyword(Keyword::from(user_id)).await?;
        Ok(Triple::permissions_per_object(all_user_permissions))
    }

    /// List all the permissions granted on an object
    /// per user id
    pub(crate) async fn list_object_permissions(
        &self,
        obj_uid: &ObjectUid,
    ) -> DbResult<HashMap<UserId, HashSet<KmipOperation>>> {
        let all_object_permissions = self.search_one_keyword(Keyword::from(obj_uid)).await?;
        Ok(Triple::permissions_per_user(all_object_permissions))
    }

    /// List all the permissions granted to the user on an object
    pub(crate) async fn get(
        &self,
        findex_key: &SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        obj_uid: &str,
        user_id: &str,
        no_inherited_access: bool,
    ) -> DbResult<HashSet<KmipOperation>> {
        let mut user_perms = self
            .search_one_keyword(findex_key, &Triple::build_key(obj_uid, user_id))
            .await?
            .into_iter()
            .map(|triple| triple.permission)
            .collect::<HashSet<KmipOperation>>();
        if no_inherited_access {
            return Ok(user_perms)
        }
        let wildcard_user_perms = self
            .search_one_keyword(findex_key, &Triple::build_key(obj_uid, "*"))
            .await?
            .into_iter()
            .map(|triple| triple.permission)
            .collect::<HashSet<KmipOperation>>();
        user_perms.extend(wildcard_user_perms);
        Ok(user_perms)
    }

    /// Add a permission to the user on an object
    pub(crate) async fn add(
        &self,
        findex_key: &SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        obj_uid: &str,
        user_id: &str,
        permission: KmipOperation,
    ) -> DbResult<()> {
        // The strategy is the following:
        // 1. We add the userid::obj_uid --> Location(Triple) to the index
        // 2. if userid::obj_uid is not in the index, we add
        //      the userid --> NextKeyword(userid::obj_uid)
        //      and obj_obj_uid --> NextKeyword(userid::obj_uid)
        // else we assume there are already there and we do nothing

        let triple = Triple::new(obj_uid, user_id, permission);
        let indexed_value = IndexedValue::from(Location::try_from(&triple)?);
        let keyword = Keyword::from(format!("p::{}", triple.key()).as_bytes());

        // addition of the keyword to the index
        let mut additions = HashMap::new();
        additions.insert(indexed_value, HashSet::from([keyword.clone()]));

        //upsert the index
        let new_keywords = self
            .findex
            .upsert(&findex_key.to_bytes(), additions, HashMap::new())
            .await?;
        let is_already_present = !new_keywords.contains(&keyword);
        if is_already_present {
            // we assume that the other two keywords are already present
            return Ok(())
        }

        // we need to add the other two keywords
        let mut additions = HashMap::new();
        additions.insert(
            IndexedValue::from(keyword),
            HashSet::from([
                Keyword::from(format!("p::{obj_uid}").as_bytes()),
                Keyword::from(format!("p::{user_id}").as_bytes()),
            ]),
        );
        self.findex
            .upsert(&findex_key.to_bytes(), additions, HashMap::new())
            .await?;

        Ok(())
    }

    /// Remove a permission to the user on an object
    pub(crate) async fn remove(
        &self,
        findex_key: &SymmetricKey<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        obj_uid: &str,
        user_id: &str,
        permission: KmipOperation,
    ) -> DbResult<()> {
        // A delete in Findex is done by adding  a new entry with the same key bu stale

        let triple = Triple::new(obj_uid, user_id, permission);
        let indexed_value = IndexedValue::from(Location::try_from(&triple)?);
        let keyword = Keyword::from(format!("p::{}", triple.key()).as_bytes());

        // deletions of the keyword in the index
        let mut deletions = HashMap::new();
        deletions.insert(indexed_value, HashSet::from([keyword.clone()]));

        //upsert the deletions in the index
        let new_keywords = self
            .findex
            .upsert(
                &findex_key.to_bytes(),
                &self.label,
                HashMap::new(),
                deletions,
            )
            .await?;
        let is_new = new_keywords.contains(&keyword);

        // we need to handle a corner case where the first addition of the keyword
        // to the index is actually a deletion. An entry will be created anyway and
        // the keyword will show as present on the next addition. Since we are not
        // going to create the other two keywords on the next addition,
        // we need to do it now
        if is_new {
            // we need to add the other two keywords
            let mut additions = HashMap::new();
            additions.insert(
                IndexedValue::from(keyword),
                HashSet::from([
                    Keyword::from(format!("p::{obj_uid}").as_bytes()),
                    Keyword::from(format!("p::{user_id}").as_bytes()),
                ]),
            );
            self.findex
                .upsert(
                    &findex_key.to_bytes(),
                    &self.label,
                    additions,
                    HashMap::new(),
                )
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl RemovedLocationsFinder for PermissionsDB {
    async fn find_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexRedisError> {
        Ok(HashSet::new())
    }
}
