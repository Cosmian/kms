use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::types::{ExtraDatabaseParams, IsWrapped, ObjectOperationTypes};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, Pool, Sqlite,
};

use super::{
    cached_sqlite_struct::KMSSqliteCache,
    sqlite::{
        create_, delete_, delete_access_, find_, insert_access_, is_object_owned_by_,
        list_accesses_, list_shared_objects_, retrieve_, update_object_, update_state_, upsert_,
    },
};
use crate::{
    database::{Database, SQLITE_QUERIES},
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};
pub struct CachedSqlCipher {
    path: PathBuf,
    cache: KMSSqliteCache,
}

// We allow 100 opened connection
const KMS_SQLITE_CACHE_SIZE: usize = 100;

impl CachedSqlCipher {
    /// Instantiate a new `CachedSqlCipher`
    /// and create the appropriate table(s) if need be
    pub async fn instantiate(path: &Path) -> KResult<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            cache: KMSSqliteCache::new(KMS_SQLITE_CACHE_SIZE),
        })
    }

    async fn instantiate_group_database(
        &self,
        group_id: u128,
        key: &[u8; 32],
    ) -> KResult<Pool<Sqlite>> {
        let path = self.filename(group_id);
        let options = SqliteConnectOptions::new()
            .pragma("key", format!("\"x'{}'\"", hex::encode(key)))
            .pragma("journal_mode", "OFF")
            .filename(path)
            // Sets a timeout value to wait when the database is locked, before returning a busy timeout error.
            .busy_timeout(Duration::from_secs(120))
            // disable logging of each query
            .disable_statement_logging();

        Ok(SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?)
    }

    async fn create_tables(pool: &Pool<Sqlite>) -> KResult<()> {
        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-objects")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    #[cfg(test)]
    pub async fn perms(
        &self,
        uid: &str,
        userid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectOperationTypes>> {
        use super::sqlite::fetch_permissions_;

        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = fetch_permissions_(uid, userid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    fn post_query(&self, group_id: u128) -> KResult<()> {
        self.cache.release(group_id)
    }

    async fn pre_query(&self, group_id: u128, key: &[u8; 32]) -> KResult<Arc<Pool<Sqlite>>> {
        if !self.cache.exists(group_id) {
            let pool = self.instantiate_group_database(group_id, key).await?;
            Self::create_tables(&pool).await?;
            self.cache.save(group_id, key, pool).await?;
        } else if !self.cache.opened(group_id) {
            let pool = self.instantiate_group_database(group_id, key).await?;
            self.cache.save(group_id, key, pool).await?;
        }

        self.cache.get(group_id, key)
    }
}

#[async_trait]
impl Database for CachedSqlCipher {
    fn filename(&self, group_id: u128) -> PathBuf {
        self.path.join(format!("{group_id}.sqlite"))
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &kmip_objects::Object,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = create_(uid, owner, object, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn create_objects(
        &self,
        owner: &str,
        objects: &[(Option<String>, kmip_objects::Object)],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;

            let mut res = vec![];
            let mut tx = pool.begin().await?;
            for (uid, object) in objects {
                match create_(uid.clone(), owner, object, &mut *tx).await {
                    Ok(uid) => res.push(uid),
                    Err(e) => {
                        tx.rollback().await.context("transaction failed")?;
                        kms_bail!("creation of objects failed: {}", e);
                    }
                };
            }
            tx.commit().await?;
            self.post_query(params.group_id)?;

            return Ok(res)
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn retrieve(
        &self,
        uid: &str,
        owner: &str,
        operation_type: ObjectOperationTypes,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Option<(kmip_objects::Object, StateEnumeration)>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = retrieve_(uid, owner, operation_type, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &kmip_objects::Object,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = update_object_(uid, object, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = update_state_(uid, state, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn upsert(
        &self,
        uid: &str,
        owner: &str,
        object: &kmip_objects::Object,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = upsert_(uid, owner, object, state, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn delete(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = delete_(uid, owner, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_access_rights_obtained(
        &self,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<
        Vec<(
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationTypes>,
            IsWrapped,
        )>,
    > {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_shared_objects_(owner, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn list_accesses(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, Vec<ObjectOperationTypes>)>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = list_accesses_(uid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn insert_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = insert_access_(uid, userid, operation_type, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn delete_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = delete_access_(uid, userid, operation_type, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        userid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = is_object_owned_by_(uid, userid, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>> {
        if let Some(params) = params {
            let pool = self.pre_query(params.group_id, &params.key).await?;
            let ret = find_(researched_attributes, state, owner, &*pool).await;
            self.post_query(params.group_id)?;
            return ret
        }

        kms_bail!("Missing group_id/key for opening SQLCipher")
    }
}

#[cfg(test)]
mod tests {
    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use cosmian_kmip::kmip::{
        kmip_objects::ObjectType,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            StateEnumeration,
        },
    };
    use cosmian_kms_utils::{
        crypto::symmetric::create_symmetric_key,
        types::{ExtraDatabaseParams, ObjectOperationTypes},
    };
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::CachedSqlCipher;
    use crate::{database::Database, kms_bail, log_utils::log_init, result::KResult};

    #[actix_rt::test]
    #[ignore = "Waiting for SqlCipher crate upgrade to handle JSON operators"]
    pub async fn test_owner() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        log_init("info");
        let owner = "eyJhbGciOiJSUzI1Ni";
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let invalid_owner = "invalid_owner";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = CachedSqlCipher::instantiate(&file_path).await?;
        let params = ExtraDatabaseParams {
            group_id: 0,
            key: [3_u8; 32],
        };

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let symmetric_key =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        db.upsert(
            &uid,
            owner,
            &symmetric_key,
            StateEnumeration::Active,
            Some(&params),
        )
        .await?;

        assert!(db.is_object_owned_by(&uid, owner, Some(&params)).await?);

        // Retrieve object with valid owner with `Get` operation type - OK

        match db
            .retrieve(&uid, owner, ObjectOperationTypes::Get, Some(&params))
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Retrieve object with invalid owner with `Get` operation type - ko

        if db
            .retrieve(
                &uid,
                invalid_owner,
                ObjectOperationTypes::Get,
                Some(&params),
            )
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object")
        }

        // Add authorized `userid` to `read_access` table

        db.insert_access(&uid, userid, ObjectOperationTypes::Get, Some(&params))
            .await?;

        // Retrieve object with authorized `userid` with `Create` operation type - ko

        if db
            .retrieve(&uid, userid, ObjectOperationTypes::Create, Some(&params))
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match db
            .retrieve(&uid, userid, ObjectOperationTypes::Get, Some(&params))
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Add authorized `userid2` to `read_access` table

        db.insert_access(&uid, userid2, ObjectOperationTypes::Get, Some(&params))
            .await?;

        // Try to add same access again - OK

        db.insert_access(&uid, userid2, ObjectOperationTypes::Get, Some(&params))
            .await?;

        let objects = db.find(None, None, owner, Some(&params)).await?;
        assert_eq!(objects.len(), 1);
        let (o_uid, o_state, _, _) = &objects[0];
        assert_eq!(o_uid, &uid);
        assert_eq!(o_state, &StateEnumeration::Active);

        let objects = db.find(None, None, userid2, Some(&params)).await?;
        assert!(objects.is_empty());

        let objects = db
            .list_access_rights_obtained(userid2, Some(&params))
            .await?;
        assert_eq!(
            objects,
            vec![(
                uid.clone(),
                String::from(owner),
                StateEnumeration::Active,
                vec![ObjectOperationTypes::Get],
                false
            )]
        );

        // Retrieve object with authorized `userid2` with `Create` operation type - ko

        if db
            .retrieve(&uid, userid2, ObjectOperationTypes::Create, Some(&params))
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match db
            .retrieve(&uid, userid2, ObjectOperationTypes::Get, Some(&params))
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Be sure we can still retrieve object with authorized `userid` with `Get` operation type - OK

        match db
            .retrieve(&uid, userid, ObjectOperationTypes::Get, Some(&params))
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Remove `userid2` authorization

        db.delete_access(&uid, userid2, ObjectOperationTypes::Get, Some(&params))
            .await?;

        // Retrieve object with `userid2` with `Get` operation type - ko

        if db
            .retrieve(&uid, userid2, ObjectOperationTypes::Get, Some(&params))
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object with `Get` request")
        }

        Ok(())
    }

    #[actix_rt::test]
    #[ignore]
    pub async fn test_permissions() -> KResult<()> {
        log_init("info");
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = CachedSqlCipher::instantiate(&file_path).await?;
        let params = ExtraDatabaseParams {
            group_id: 0,
            key: [1_u8; 32],
        };

        let uid = Uuid::new_v4().to_string();

        // simple insert
        db.insert_access(&uid, userid, ObjectOperationTypes::Get, Some(&params))
            .await?;

        let perms = db.perms(&uid, userid, Some(&params)).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // double insert, expect no duplicate
        db.insert_access(&uid, userid, ObjectOperationTypes::Get, Some(&params))
            .await?;

        let perms = db.perms(&uid, userid, Some(&params)).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // insert other operation type
        db.insert_access(&uid, userid, ObjectOperationTypes::Encrypt, Some(&params))
            .await?;

        let perms = db.perms(&uid, userid, Some(&params)).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // insert other `userid2`, check it is ok and it didn't change anything for `userid`
        db.insert_access(&uid, userid2, ObjectOperationTypes::Get, Some(&params))
            .await?;

        let perms = db.perms(&uid, userid2, Some(&params)).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = db.perms(&uid, userid, Some(&params)).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        let accesses = db.list_accesses(&uid, Some(&params)).await?;
        assert_eq!(
            accesses,
            vec![
                (
                    String::from("bar@example.org"),
                    vec![ObjectOperationTypes::Get]
                ),
                (
                    String::from("foo@example.org"),
                    vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
                )
            ]
        );

        // remove `Get` access for `userid`
        db.delete_access(&uid, userid, ObjectOperationTypes::Get, Some(&params))
            .await?;

        let perms = db.perms(&uid, userid2, Some(&params)).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = db.perms(&uid, userid, Some(&params)).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Encrypt]);

        Ok(())
    }

    #[actix_rt::test]
    #[ignore = "Waiting for SqlCipher crate upgrade to handle JSON operators"]
    pub async fn test_json_access() -> KResult<()> {
        log_init("info");
        let mut rng = CsRng::from_entropy();
        let owner = "eyJhbGciOiJSUzI1Ni";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = CachedSqlCipher::instantiate(&file_path).await?;
        let params = ExtraDatabaseParams {
            group_id: 0,
            key: [2_u8; 32],
        };

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let symmetric_key =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        db.upsert(
            &uid,
            owner,
            &symmetric_key,
            StateEnumeration::Active,
            Some(&params),
        )
        .await?;

        assert!(db.is_object_owned_by(&uid, owner, Some(&params)).await?);

        // Retrieve object with valid owner with `Get` operation type - OK

        match db
            .retrieve(&uid, owner, ObjectOperationTypes::Get, Some(&params))
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Find with crypto algo attribute

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                Some(&params),
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with crypto length attribute

        let researched_attributes = Some(Attributes {
            cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                Some(&params),
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with crypto attributes

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                Some(&params),
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with key format type attribute

        let researched_attributes = Some(Attributes {
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                Some(&params),
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with all attributes

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                Some(&params),
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find bad crypto algo

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                Some(&params),
            )
            .await?;
        assert!(found.is_empty());

        // Find bad key format type

        let researched_attributes = Some(Attributes {
            key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                Some(&params),
            )
            .await?;
        assert!(found.is_empty());

        Ok(())
    }
}
