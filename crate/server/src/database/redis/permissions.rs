use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof::reexport::crypto_core::{symmetric_crypto::key::Key, KeyTrait};
use cosmian_findex_redis::{
    FindexError, FindexRedis, IndexedValue, Keyword, Location, RemovedLocationsFinder,
    MASTER_KEY_LENGTH,
};
use cosmian_kms_utils::access::ObjectOperationType;

use crate::{error::KmsError, result::KResult};

/// The struct we store for each permission
/// We store the permission itself as a Location
/// Keeping the object uid and user id is necessary to be able to query
/// the database for all permissions for a given object or user because
/// there is no convenient access to the callback for a search
#[derive(Clone, Eq, PartialEq, Debug, Hash)]
struct Triple {
    obj_uid: String,
    user_id: String,
    permission: ObjectOperationType,
}

impl Triple {
    pub fn new(obj_uid: &str, user_id: &str, permission: ObjectOperationType) -> Self {
        Self {
            obj_uid: obj_uid.to_string(),
            user_id: user_id.to_string(),
            permission,
        }
    }

    pub fn key(&self) -> String {
        Self::build_key(&self.obj_uid, &self.user_id)
    }
}

impl Triple {
    pub fn build_key(obj_uid: &str, user_id: &str) -> String {
        format!("{}::{}", obj_uid, user_id)
    }

    pub fn permissions_per_user(
        list: HashSet<Triple>,
    ) -> HashMap<String, HashSet<ObjectOperationType>> {
        let mut map = HashMap::new();
        for triple in list {
            let entry = map.entry(triple.user_id).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }

    pub fn permissions_per_object(
        list: HashSet<Triple>,
    ) -> HashMap<String, HashSet<ObjectOperationType>> {
        let mut map = HashMap::new();
        for triple in list {
            let entry = map.entry(triple.obj_uid).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }
}

impl TryFrom<&Location> for Triple {
    type Error = KmsError;

    fn try_from(value: &Location) -> Result<Self, Self::Error> {
        let value = String::from_utf8((value).to_vec())?;
        let mut parts = value.split("::");
        let uid = parts.next().ok_or_else(|| {
            KmsError::ConversionError(format!("invalid permissions triple: {:?}", parts))
        })?;
        let user_id = parts.next().ok_or_else(|| {
            KmsError::ConversionError(format!("invalid permissions triple: {:?}", parts))
        })?;
        let permission = parts.next().ok_or_else(|| {
            KmsError::ConversionError(format!("invalid permissions triple: {:?}", parts))
        })?;
        Ok(Self {
            obj_uid: uid.to_string(),
            user_id: user_id.to_string(),
            permission: serde_json::from_str(permission)?,
        })
    }
}

impl TryFrom<&Triple> for Location {
    type Error = KmsError;

    fn try_from(value: &Triple) -> Result<Self, Self::Error> {
        Ok(Location::from(
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

/// PermissionsDB is a database entirely built on top of Findex that stores the permissions
/// We "abuse" Location to store data i.e. the actual permission
///     userid::obj_uid --> Location(permission)
///     userid --> NextKeyword(userid::obj_uid)
///     obj_uid --> NextKeyword(userid::obj_uid)
///
/// The problem is that the search function does not return the userid::obj_uid when
/// searching for either a userid or a uid, so wee need to store a triplet
/// rather than just the permission
pub(crate) struct PermissionsDB {
    findex: Arc<FindexRedis>,
    findex_key: Key<MASTER_KEY_LENGTH>,
    label: Vec<u8>,
}

impl PermissionsDB {
    pub async fn new(
        findex: Arc<FindexRedis>,
        findex_key: Key<MASTER_KEY_LENGTH>,
        label: &[u8],
    ) -> KResult<Self> {
        Ok(Self {
            findex,
            findex_key,
            label: label.to_vec(),
        })
    }

    /// Search for a keyword
    async fn search_one_keyword(&self, keyword: &str) -> KResult<HashSet<Triple>> {
        let keyword = Keyword::from(format!("p::{keyword}").as_bytes());
        self.findex
            .search(
                &self.findex_key.to_bytes(),
                &self.label,
                HashSet::from([keyword.clone()]),
            )
            .await?
            .into_iter()
            .next()
            .unwrap_or((keyword, HashSet::new()))
            .1
            .into_iter()
            .map(|l| Triple::try_from(&l))
            .collect::<KResult<HashSet<Triple>>>()
    }

    /// List all the permissions granted to the user
    /// per object uid
    pub async fn list_user_permissions(
        &self,
        user_id: &str,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>> {
        Ok(Triple::permissions_per_object(
            self.search_one_keyword(user_id).await?,
        ))
    }

    /// List all the permissions granted on an object
    /// per user id
    pub async fn list_object_permissions(
        &self,
        obj_uid: &str,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>> {
        Ok(Triple::permissions_per_user(
            self.search_one_keyword(obj_uid).await?,
        ))
    }

    /// List all the permissions granted to the user on an object
    pub async fn get(&self, obj_uid: &str, user_id: &str) -> KResult<HashSet<ObjectOperationType>> {
        Ok(self
            .search_one_keyword(&Triple::build_key(obj_uid, user_id))
            .await?
            .into_iter()
            .map(|triple| triple.permission)
            .collect::<HashSet<ObjectOperationType>>())
    }

    /// Add a permission to the user on an object
    pub async fn add(
        &self,
        obj_uid: &str,
        user_id: &str,
        permission: ObjectOperationType,
    ) -> KResult<()> {
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
        let already_present = self
            .findex
            .upsert(
                &self.findex_key.to_bytes(),
                &self.label,
                additions,
                HashMap::new(),
            )
            .await?;
        let already_present = match already_present.get(&keyword) {
            Some(already_present) => *already_present,
            None => {
                return Err(KmsError::Findex(
                    "Unexpected error: keyword not found in the return call of upsert".to_string(),
                ))
            }
        };

        if already_present {
            // we assume that the other two keywords are already present
            return Ok(())
        }

        // we need to add the other two keywords
        let mut additions = HashMap::new();
        additions.insert(
            IndexedValue::from(keyword),
            HashSet::from([
                Keyword::from(format!("p::{}", obj_uid).as_bytes()),
                Keyword::from(format!("p::{}", user_id).as_bytes()),
            ]),
        );
        self.findex
            .upsert(
                &self.findex_key.to_bytes(),
                &self.label,
                additions,
                HashMap::new(),
            )
            .await?;

        Ok(())
    }

    /// Remove a permission to the user on an object
    pub async fn remove(
        &self,
        obj_uid: &str,
        user_id: &str,
        permission: ObjectOperationType,
    ) -> KResult<()> {
        // A delete in Findex is done by adding  a new entry with the same key bu stale

        let triple = Triple::new(obj_uid, user_id, permission);
        let indexed_value = IndexedValue::from(Location::try_from(&triple)?);
        let keyword = Keyword::from(format!("p::{}", triple.key()).as_bytes());

        // deletions of the keyword in the index
        let mut deletions = HashMap::new();
        deletions.insert(indexed_value, HashSet::from([keyword.clone()]));

        //upsert the deletions in the index
        let already_present = self
            .findex
            .upsert(
                &self.findex_key.to_bytes(),
                &self.label,
                HashMap::new(),
                deletions,
            )
            .await?;
        let already_present = match already_present.get(&keyword) {
            Some(already_present) => *already_present,
            None => {
                return Err(KmsError::Findex(
                    "Unexpected error: keyword not found in the return call of upsert".to_string(),
                ))
            }
        };

        // we need to handle a corner case where the first addition of the keyword
        // to the index is actually a deletion. An entry will be created anyway and
        // the keyword will show as present on the next addition. Since we are not
        // going to create the other two keywords on the next addition,
        // we need to do it now
        if !already_present {
            // we need to add the other two keywords
            let mut additions = HashMap::new();
            additions.insert(
                IndexedValue::from(keyword),
                HashSet::from([
                    Keyword::from(format!("p::{}", obj_uid).as_bytes()),
                    Keyword::from(format!("p::{}", user_id).as_bytes()),
                ]),
            );
            self.findex
                .upsert(
                    &self.findex_key.to_bytes(),
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
    ) -> Result<HashSet<Location>, FindexError> {
        Ok(HashSet::new())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use async_trait::async_trait;
    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::SeedableRng, symmetric_crypto::key::Key, CsRng, KeyTrait,
    };
    use cosmian_findex_redis::{FindexError, FindexRedis, Location, RemovedLocationsFinder};
    use cosmian_kms_utils::access::ObjectOperationType;
    use redis::aio::ConnectionManager;
    use serial_test::serial;

    use crate::{database::redis::permissions::PermissionsDB, result::KResult};

    const REDIS_URL: &str = "redis://localhost:6379";

    struct DummyDB {}
    #[async_trait]
    impl RemovedLocationsFinder for DummyDB {
        async fn find_removed_locations(
            &self,
            _locations: HashSet<Location>,
        ) -> Result<HashSet<Location>, FindexError> {
            Ok(HashSet::new())
        }
    }

    async fn clear_all(mgr: &mut ConnectionManager) -> KResult<()> {
        redis::cmd("FLUSHDB").query_async(mgr).await?;
        Ok(())
    }

    #[actix_web::test]
    #[serial]
    pub async fn test_permissions_db() -> KResult<()> {
        // generate the findex key
        let mut rng = CsRng::from_entropy();
        let findex_key = Key::new(&mut rng);

        // the findex label
        let label = b"label";

        let client = redis::Client::open(REDIS_URL)?;
        let mut mgr = ConnectionManager::new(client).await?;
        // clear the DB
        clear_all(&mut mgr).await?;
        // create the findex
        let findex =
            Arc::new(FindexRedis::connect_with_manager(mgr.clone(), Arc::new(DummyDB {})).await?);
        let permissions_db = PermissionsDB::new(findex, findex_key, label).await?;

        // let us add the permission Encrypt on object O1 for user U1
        permissions_db
            .add("O1", "U1", ObjectOperationType::Encrypt)
            .await?;

        // verify that the permission is present
        let permissions = permissions_db.get("O1", "U1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains(&ObjectOperationType::Encrypt));

        // find the permissions for user U1
        let permissions = permissions_db.list_user_permissions("U1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("O1"));
        assert_eq!(
            permissions.get("O1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        //find the permission for the object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("U1"));
        assert_eq!(
            permissions.get("U1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        // add the permission Decrypt to user U1 for object O1
        permissions_db
            .add("O1", "U1", ObjectOperationType::Decrypt)
            .await?;

        // assert the permission is present
        let permissions = permissions_db.get("O1", "U1").await?;
        assert_eq!(permissions.len(), 2);
        assert!(permissions.contains(&ObjectOperationType::Encrypt));
        assert!(permissions.contains(&ObjectOperationType::Decrypt));

        // find the permissions for user U1
        let permissions = permissions_db.list_user_permissions("U1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("O1"));
        assert_eq!(
            permissions.get("O1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt, ObjectOperationType::Decrypt])
        );

        //find the permission for the object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("U1"));
        assert_eq!(
            permissions.get("U1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt, ObjectOperationType::Decrypt])
        );

        // the situation now is that we have
        // O1 -> U1 -> Encrypt, Decrypt

        // let us add the permission Encrypt on object O1 for user U2
        permissions_db
            .add("O1", "U2", ObjectOperationType::Encrypt)
            .await?;
        // assert the permission is present
        let permissions = permissions_db.get("O1", "U2").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains(&ObjectOperationType::Encrypt));

        // find the permissions for user U2
        let permissions = permissions_db.list_user_permissions("U2").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("O1"));
        assert_eq!(
            permissions.get("O1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        //find the permission for the object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 2);
        assert!(permissions.contains_key("U1"));
        assert_eq!(
            permissions.get("U1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt, ObjectOperationType::Decrypt])
        );
        assert!(permissions.contains_key("U2"));
        assert_eq!(
            permissions.get("U2").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        // the situation now is that we have
        // O1 -> U1 -> Encrypt, Decrypt
        // O1 -> U2 -> Encrypt

        // let us add the permission Encrypt on object O2 for user U2
        permissions_db
            .add("O2", "U2", ObjectOperationType::Encrypt)
            .await?;
        // assert the permission is present
        let permissions = permissions_db.get("O2", "U2").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains(&ObjectOperationType::Encrypt));

        // find the permissions for user U2
        let permissions = permissions_db.list_user_permissions("U2").await?;
        assert_eq!(permissions.len(), 2);
        assert!(permissions.contains_key("O1"));
        assert_eq!(
            permissions.get("O1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );
        assert!(permissions.contains_key("O2"));
        assert_eq!(
            permissions.get("O2").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        //find the permission for the object O2
        let permissions = permissions_db.list_object_permissions("O2").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("U2"));
        assert_eq!(
            permissions.get("U2").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        // the situation now is that we have
        // O1 -> U1 -> Encrypt, Decrypt
        // O1 -> U2 -> Encrypt
        // O2 -> U2 -> Encrypt

        // let us remove the permission Decrypt on object O1 for user U1
        permissions_db
            .remove("O1", "U1", ObjectOperationType::Decrypt)
            .await?;
        // assert the permission Encrypt is present and Decrypt is not
        let permissions = permissions_db.get("O1", "U1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains(&ObjectOperationType::Encrypt));

        // find the permissions for user U1
        let permissions = permissions_db.list_user_permissions("U1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("O1"));
        assert_eq!(
            permissions.get("O1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        //find the permission for the object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 2);
        assert!(permissions.contains_key("U1"));
        assert_eq!(
            permissions.get("U1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );
        assert!(permissions.contains_key("U2"));
        assert_eq!(
            permissions.get("U2").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        // let us remove the permission Encrypt on object O1 for user U1
        permissions_db
            .remove("O1", "U1", ObjectOperationType::Encrypt)
            .await?;
        // assert the permission is not present
        let permissions = permissions_db.get("O1", "U1").await?;
        assert_eq!(permissions.len(), 0);

        // find the permissions for user U1
        let permissions = permissions_db.list_user_permissions("U1").await?;
        assert_eq!(permissions.len(), 0);

        //find the permission for the object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("U2"));
        assert_eq!(
            permissions.get("U2").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        // let us remove the permission Encrypt on object O1 for user U2
        permissions_db
            .remove("O1", "U2", ObjectOperationType::Encrypt)
            .await?;
        // assert the permission is not present
        let permissions = permissions_db.get("O1", "U2").await?;
        assert_eq!(permissions.len(), 0);

        // find the permissions for user U2
        let permissions = permissions_db.list_user_permissions("U2").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("O2"));
        assert_eq!(
            permissions.get("O2").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        //find the permission for the object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 0);

        Ok(())
    }

    #[actix_web::test]
    #[serial]
    pub async fn test_corner_case() -> KResult<()> {
        // generate the findex key
        let mut rng = CsRng::from_entropy();
        let findex_key = Key::new(&mut rng);

        // the findex label
        let label = b"label";

        let client = redis::Client::open(REDIS_URL)?;
        let mut mgr = ConnectionManager::new(client).await?;
        // clear the DB
        clear_all(&mut mgr).await?;
        // create the findex
        let findex =
            Arc::new(FindexRedis::connect_with_manager(mgr.clone(), Arc::new(DummyDB {})).await?);
        let permissions_db = PermissionsDB::new(findex, findex_key, label).await?;

        // remove a permission that does not exist
        permissions_db
            .remove("O1", "U1", ObjectOperationType::Encrypt)
            .await?;

        // test that it does not exist
        let permissions = permissions_db.get("O1", "U1").await?;
        assert_eq!(permissions.len(), 0);

        // test there are no permissions for user U1
        let permissions = permissions_db.list_user_permissions("U1").await?;
        assert_eq!(permissions.len(), 0);

        // test there are no permissions for object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 0);

        //add the permission Encrypt on object O1 for user U1
        permissions_db
            .add("O1", "U1", ObjectOperationType::Encrypt)
            .await?;

        // test there is one permission for user U1
        let permissions = permissions_db.list_user_permissions("U1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("O1"));
        assert_eq!(
            permissions.get("O1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        // test there is one permission for object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("U1"));
        assert_eq!(
            permissions.get("U1").unwrap(),
            &HashSet::from([ObjectOperationType::Encrypt])
        );

        // remove the permission again
        permissions_db
            .remove("O1", "U1", ObjectOperationType::Encrypt)
            .await?;

        // test there are no permissions for user U1
        let permissions = permissions_db.list_user_permissions("U1").await?;
        assert_eq!(permissions.len(), 0);

        // test there are no permissions for object O1
        let permissions = permissions_db.list_object_permissions("O1").await?;
        assert_eq!(permissions.len(), 0);

        Ok(())
    }
}
