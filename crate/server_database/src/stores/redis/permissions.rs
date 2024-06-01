use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof::reexport::crypto_core::{FixedSizeCBytes, SymmetricKey};
use cloudproof_findex::{
    implementations::redis::{FindexRedis, FindexRedisError, RemovedLocationsFinder},
    parameters::MASTER_KEY_LENGTH,
    IndexedValue, Keyword, Location,
};
use cosmian_kmip::kmip::KmipOperation;

use crate::{DbError, DbResult};

/// The struct we store for each permission
/// We store the permission itself as a Location
/// Keeping the object uid and user id is necessary to be able to query
/// the database for all permissions for a given object or user because
/// there is no convenient access to the callback for a search
#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) struct Triple {
    obj_uid: String,
    user_id: String,
    permission: KmipOperation,
}

impl Triple {
    pub(crate) fn new(obj_uid: &str, user_id: &str, permission: KmipOperation) -> Self {
        Self {
            obj_uid: obj_uid.to_owned(),
            user_id: user_id.to_owned(),
            permission,
        }
    }

    pub(crate) fn key(&self) -> String {
        Self::build_key(&self.obj_uid, &self.user_id)
    }

    pub(crate) fn build_key(obj_uid: &str, user_id: &str) -> String {
        format!("{obj_uid}::{user_id}")
    }

    pub(crate) fn permissions_per_user(
        list: HashSet<Self>,
    ) -> HashMap<String, HashSet<KmipOperation>> {
        let mut map = HashMap::new();
        for triple in list {
            let entry = map.entry(triple.user_id).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }

    pub(crate) fn permissions_per_object(
        list: HashSet<Self>,
    ) -> HashMap<String, HashSet<KmipOperation>> {
        let mut map = HashMap::new();
        for triple in list {
            let entry = map.entry(triple.obj_uid).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }
}

impl TryFrom<&Location> for Triple {
    type Error = DbError;

    fn try_from(value: &Location) -> Result<Self, Self::Error> {
        let value = String::from_utf8((value).to_vec())?;
        let mut parts = value.split("::");
        let uid = parts.next().ok_or_else(|| {
            DbError::ConversionError(format!("invalid permissions triple: {parts:?}"))
        })?;
        let user_id = parts.next().ok_or_else(|| {
            DbError::ConversionError(format!("invalid permissions triple: {parts:?}"))
        })?;
        let permission = parts.next().ok_or_else(|| {
            DbError::ConversionError(format!("invalid permissions triple: {parts:?}"))
        })?;
        Ok(Self {
            obj_uid: uid.to_owned(),
            user_id: user_id.to_owned(),
            permission: serde_json::from_str(permission)?,
        })
    }
}

impl TryFrom<&Triple> for Location {
    type Error = DbError;

    fn try_from(value: &Triple) -> Result<Self, Self::Error> {
        Ok(Self::from(
            format!(
                "{}::{}::{}",
                value.obj_uid,
                value.user_id,
                serde_json::to_string(&value.permission)?
            )
            .into_bytes(),
        ))
    }
}

/// `PermissionsDB` is a database entirely built on top of Findex that stores the permissions
/// We "abuse" Location to store data i.e. the actual permission
///     `userid::obj_uid` --> Location(permission)
///     userid --> `NextKeyword(userid::obj_uid`)
///     `obj_uid` --> `NextKeyword(userid::obj_uid`)
///
/// The problem is that the search function does not return the `userid::obj_uid` when
/// searching for either a userid or a uid, so wee need to store a triplet
/// rather than just the permission
#[derive(Clone)]
pub(crate) struct PermissionsDB {
    findex: Arc<FindexRedis>,
    label: Vec<u8>,
}

impl PermissionsDB {
    pub(crate) fn new(findex: Arc<FindexRedis>, label: &[u8]) -> Self {
        Self {
            findex,
            label: label.to_vec(),
        }
    }

    /// Search for a keyword
    async fn search_one_keyword(
        &self,
        findex_key: &SymmetricKey<MASTER_KEY_LENGTH>,
        keyword: &str,
    ) -> DbResult<HashSet<Triple>> {
        let keyword = Keyword::from(format!("p::{keyword}").as_bytes());
        self.findex
            .search(
                &findex_key.to_bytes(),
                &self.label,
                HashSet::from([keyword.clone()]),
            )
            .await?
            .into_iter()
            .next()
            .unwrap_or((keyword, HashSet::new()))
            .1
            .iter()
            .map(Triple::try_from)
            .collect::<DbResult<HashSet<Triple>>>()
    }

    /// List all the permissions granted to the user
    /// per object uid
    pub(crate) async fn list_user_permissions(
        &self,
        findex_key: &SymmetricKey<MASTER_KEY_LENGTH>,
        user_id: &str,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(Triple::permissions_per_object(
            self.search_one_keyword(findex_key, user_id).await?,
        ))
    }

    /// List all the permissions granted on an object
    /// per user id
    pub(crate) async fn list_object_permissions(
        &self,
        findex_key: &SymmetricKey<MASTER_KEY_LENGTH>,
        obj_uid: &str,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(Triple::permissions_per_user(
            self.search_one_keyword(findex_key, obj_uid).await?,
        ))
    }

    /// List all the permissions granted to the user on an object
    pub(crate) async fn get(
        &self,
        findex_key: &SymmetricKey<MASTER_KEY_LENGTH>,
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
        findex_key: &SymmetricKey<MASTER_KEY_LENGTH>,
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
            .upsert(
                &findex_key.to_bytes(),
                &self.label,
                additions,
                HashMap::new(),
            )
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
            .upsert(
                &findex_key.to_bytes(),
                &self.label,
                additions,
                HashMap::new(),
            )
            .await?;

        Ok(())
    }

    /// Remove a permission to the user on an object
    pub(crate) async fn remove(
        &self,
        findex_key: &SymmetricKey<MASTER_KEY_LENGTH>,
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
