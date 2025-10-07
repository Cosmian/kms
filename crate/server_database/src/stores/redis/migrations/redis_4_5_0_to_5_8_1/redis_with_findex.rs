#![allow(dead_code, unused_imports, unused_variables, clippy::all)] // TODO: del this later

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof_findex::{
    IndexedValue, Keyword, Label, Location,
    implementations::redis::{FindexRedis, FindexRedisError, RemovedLocationsFinder},
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
use redis_for_migrations::aio::ConnectionManager;
use uuid::Uuid;

use super::permissions::PermissionsDB;
use crate::{
    error::{DbError, DbResult},
    stores::redis::{
        migrations::redis_4_5_0_to_5_8_1::error::LegacyDbResult,
        objects_db::{DB_KEY_LENGTH, ObjectsDB, RedisOperation},
    },
};

// TODO: I think those three niggas use the wrong redis, Stub them :)
// stores::redis::objects_db::{DB_KEY_LENGTH, ObjectsDB, RedisOperation},

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

// object_db attribute as well as all its related methods have been deleted
#[derive(Clone)]
pub(crate) struct RedisWithFindex {
    pub(crate) mgr: ConnectionManager,
    permissions_db: PermissionsDB,
    findex: Arc<FindexRedis>,
    findex_key: SymmetricKey<MASTER_KEY_LENGTH>,
    label: Label,
}

struct DummyDB; // c.f. redis/additional_redis_findex_tests.rs on legacy kms

#[async_trait]
impl RemovedLocationsFinder for DummyDB {
    async fn find_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexRedisError> {
        Ok(HashSet::new())
    }
}

fn map_kms_interface_error_mock<E>(err: E) -> cosmian_kms_interfaces::InterfaceError
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
        let mgr = ConnectionManager::new(client).await?;
        let findex =
            Arc::new(FindexRedis::connect_with_manager(mgr.clone(), Arc::new(DummyDB {})).await?);
        let permissions_db = PermissionsDB::new(findex.clone(), label);

        let redis_with_findex = Self {
            mgr,
            permissions_db,
            findex,
            findex_key,
            label: Label::from(label),
        };

        Ok(redis_with_findex)
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
            .await
            .map_err(map_kms_interface_error_mock)?;
        todo!("fix me");
        // let redis_db_objects = self
        //     .objects_db
        //     .objects_get(&permissions.keys().cloned().collect::<HashSet<String>>())
        //     .await?;
        // Ok(permissions
        //     .into_iter()
        //     .zip(redis_db_objects)
        //     .map(|((uid, permissions), (_, redis_db_object))| {
        //         (
        //             uid,
        //             (
        //                 redis_db_object.owner,
        //                 redis_db_object.state,
        //                 permissions.into_iter().collect::<HashSet<KmipOperation>>(),
        //             ),
        //         )
        //     })
        //     .collect())
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
            .map_err(map_kms_interface_error_mock)?)
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
                .await
                .map_err(map_kms_interface_error_mock)?;
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
                .await
                .map_err(map_kms_interface_error_mock)?;
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
