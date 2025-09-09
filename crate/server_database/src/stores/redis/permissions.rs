use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use cosmian_findex::IndexADT;
use cosmian_kmip::kmip_2_1::KmipOperation;
use serde::{Deserialize, Serialize};

use crate::{
    DbError,
    error::DbResult,
    stores::redis::{
        findex::{IndexedValue, Keyword},
        redis_with_findex::FindexRedis,
    },
};

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub(crate) struct ObjectUid(pub(crate) String);

impl From<&ObjectUid> for Keyword {
    fn from(uid: &ObjectUid) -> Self {
        Keyword::from(format!("p:o:{}", uid.0).as_bytes())
    }
}

impl From<&str> for ObjectUid {
    fn from(s: &str) -> Self {
        ObjectUid(s.to_string())
    }
}

impl From<String> for ObjectUid {
    fn from(s: String) -> Self {
        ObjectUid(s)
    }
}

impl From<ObjectUid> for String {
    fn from(s: ObjectUid) -> Self {
        s.0
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub(crate) struct UserId(pub(crate) String);

impl From<&UserId> for Keyword {
    fn from(uid: &UserId) -> Self {
        Keyword::from(format!("p:u:{}", uid.0).as_bytes())
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        UserId(s.to_string())
    }
}

impl From<UserId> for String {
    fn from(s: UserId) -> Self {
        s.0
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
    pub(crate) fn new(obj_uid: ObjectUid, user_id: UserId, permission: KmipOperation) -> Self {
        Self {
            obj_uid,
            user_id,
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
/// TODO: calculate size
///
/// By explicitly maintaining both indexes, we avoid the need for wildcard searches
/// which are not supported by Findex yet needed if we want to list all permissions
/// for a given user OR object in a same `PermissionsDB`.
/// The permission field takes (post serialization) 18 bytes at worst (`signature_verify` variant).
/// While this isn't a lot, this store is sub-optimal and can be optimized if needed. Unless
/// there are business requirements that require less storage consumption, there is no need to over-optimize prematurely.
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
        obj_uid: &ObjectUid,
        user_id: &UserId,
        no_inherited_access: bool,
    ) -> DbResult<HashSet<KmipOperation>> {
        let user_perms = self
            .search_one_keyword(Keyword::from(obj_uid))
            .await?
            .into_iter()
            .filter(|triple| {
                // Include permissions for the specific user and optionally include
                // wildcard permissions (user="*") if inherited access is allowed
                &triple.user_id == user_id
                    || (!no_inherited_access && triple.user_id == UserId("*".to_string()))
            })
            .map(|triple| triple.permission)
            .collect::<HashSet<KmipOperation>>();
        Ok(user_perms)
    }

    /// Add a permission to the user on an object
    pub(crate) async fn add(
        &self,
        obj_uid: &ObjectUid,
        user_id: &UserId,
        permission: KmipOperation,
    ) -> DbResult<()> {
        let triple = Triple::new(obj_uid.clone(), user_id.clone(), permission);
        let indexed_triple = IndexedValue::try_from(&triple)?;

        // Create both keywords for dual indexing:
        let user_keyword = Keyword::from(user_id);
        let obj_keyword = Keyword::from(obj_uid);

        // Finally, insert the indexed value under both keywords
        self.findex
            .insert(user_keyword, indexed_triple.clone())
            .await?;
        self.findex.insert(obj_keyword, indexed_triple).await?;

        Ok(())
    }

    /// Remove a permission to the user on an object
    pub(crate) async fn remove(
        &self,
        obj_uid: &ObjectUid,
        user_id: &UserId,
        permission: KmipOperation,
    ) -> DbResult<()> {
        let triple = Triple::new(obj_uid.clone(), user_id.clone(), permission);
        let indexed_triple = IndexedValue::try_from(&triple)?;

        // Create both keywords for dual indexing:
        let user_keyword = Keyword::from(user_id);
        let obj_keyword = Keyword::from(obj_uid);

        // Finally, insert the indexed value under both keywords
        self.findex
            .delete(user_keyword, indexed_triple.clone())
            .await?;
        self.findex.delete(obj_keyword, indexed_triple).await?;

        Ok(())
    }
}
