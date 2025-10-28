use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use super::permissions::PermissionsDB;
use crate::stores::redis::{
    migrations::legacy_redis_with_findex_pre_5_9_0::error::LegacyDbResult,
    objects_db::DB_KEY_LENGTH,
};
use async_trait::async_trait;
use cloudproof_findex::{
    Label, Location,
    implementations::redis::{FindexRedis, FindexRedisError, RemovedLocationsFinder},
    parameters::MASTER_KEY_LENGTH,
};
use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{Secret, SymmetricKey, kdf256};
use cosmian_kms_interfaces::{InterfaceResult, PermissionsStore, SessionParams};
use redis_for_migrations::aio::ConnectionManager;

pub(crate) const REDIS_WITH_FINDEX_MASTER_KEY_LENGTH: usize = 32;
pub(crate) const REDIS_WITH_FINDEX_MASTER_FINDEX_KEY_DERIVATION_SALT: &[u8; 6] = b"findex";
pub(crate) const REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT: &[u8; 2] = b"db";

// object_db attribute as well as all its related methods have been deleted
#[derive(Clone)]
pub(crate) struct RedisWithFindex {
    pub(crate) _mgr: ConnectionManager,
    permissions_db: PermissionsDB,
    _findex: Arc<FindexRedis>,
    findex_key: SymmetricKey<MASTER_KEY_LENGTH>,
    _label: Label,
}

struct RemovedLocationDbStub;

#[async_trait]
impl RemovedLocationsFinder for RemovedLocationDbStub {
    async fn find_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexRedisError> {
        Ok(HashSet::new())
    }
}

fn map_kms_interface_error_stub<E>(err: E) -> cosmian_kms_interfaces::InterfaceError
where
    E: std::error::Error,
{
    use cosmian_kms_interfaces::InterfaceError;
    InterfaceError::Db(format!(
        "redis-findex legacy error during migration : {err}"
    ))
}

#[allow(dead_code)] // this isn't dead.
impl RedisWithFindex {
    #[allow(clippy::used_underscore_binding)]
    pub(crate) async fn instantiate(
        redis_url: &str,
        master_key: &Secret<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>,
        label: &[u8],
        _clear_database: bool,
    ) -> LegacyDbResult<Self> {
        // derive an Findex Key
        let mut findex_key = SymmetricKey::<MASTER_KEY_LENGTH>::default();
        kdf256!(
            &mut *findex_key,
            REDIS_WITH_FINDEX_MASTER_FINDEX_KEY_DERIVATION_SALT,
            &**master_key
        );
        // derive a DB Key
        let mut db_key = SymmetricKey::<DB_KEY_LENGTH>::default();
        kdf256!(
            &mut *db_key,
            REDIS_WITH_FINDEX_MASTER_DB_KEY_DERIVATION_SALT,
            &**master_key
        );

        let client = redis_for_migrations::Client::open(redis_url)?;
        let _mgr = ConnectionManager::new(client).await?;
        let _findex = Arc::new(
            FindexRedis::connect_with_manager(_mgr.clone(), Arc::new(RemovedLocationDbStub {}))
                .await?,
        );
        let permissions_db = PermissionsDB::new(_findex.clone(), label);

        let redis_with_findex = Self {
            _mgr,
            permissions_db,
            _findex,
            findex_key,
            _label: Label::from(label),
        };

        Ok(redis_with_findex)
    }
}

#[async_trait(?Send)]
impl PermissionsStore for RedisWithFindex {
    #[allow(clippy::unreachable)] // this is a stub that's never called nor needed
    async fn list_user_operations_granted(
        &self,
        _user: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        unreachable!("Not needed - keep unimplemented for now");
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
            .await
            .map_err(map_kms_interface_error_stub)?)
    }

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        for operation in &operations {
            self.permissions_db
                .add(&self.findex_key, uid, user, *operation)
                .await
                .map_err(map_kms_interface_error_stub)?;
        }
        Ok(())
    }

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        for operation in &operations {
            self.permissions_db
                .remove(&self.findex_key, uid, user, *operation)
                .await
                .map_err(map_kms_interface_error_stub)?;
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
    use cloudproof_findex::Location;
    use std::collections::HashSet;

    fn intersect_all<I: IntoIterator<Item = HashSet<Location>>>(sets: I) -> HashSet<Location> {
        let mut iter = sets.into_iter();
        let first = iter.next().unwrap_or_default();
        iter.fold(first, |acc, set| acc.intersection(&set).cloned().collect())
    }

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
        let res = intersect_all(sets);
        assert_eq!(res.len(), 2);
        assert!(res.contains(&Location::from(b"3".as_slice())));
        assert!(res.contains(&Location::from(b"4".as_slice())));
    }
}
