use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    symmetric_crypto::key::Key,
    CsRng, KeyTrait,
};
use cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, StateEnumeration};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationTypes},
    crypto::symmetric::create_symmetric_key,
};
use tempfile::tempdir;
use uuid::Uuid;

use crate::{
    database::{cached_sqlcipher::CachedSqlCipher, sqlite::SqlitePool, Database},
    kms_bail,
    log_utils::log_init,
    result::KResult,
};

#[actix_rt::test]
async fn test_tags_sql_cipher() -> KResult<()> {
    let dir = tempdir()?;

    // generate a database key
    let mut cs_rng = CsRng::from_entropy();
    let db_key = Key::<32>::new(&mut cs_rng);

    // SQLCipher uses a directory
    let dir_path = dir.path().join("test_sqlite_enc.db");
    if dir_path.exists() {
        std::fs::remove_dir_all(&dir_path).unwrap();
    }
    std::fs::create_dir_all(&dir_path).unwrap();

    let db = CachedSqlCipher::instantiate(&dir_path).await?;
    let params = ExtraDatabaseParams {
        group_id: 0,
        key: db_key.clone(),
    };
    tags(db, Some(&params)).await?;
    Ok(())
}

#[actix_rt::test]
#[cfg_attr(feature = "sqlcipher", ignore)]
async fn test_tags_sqlite() -> KResult<()> {
    let dir = tempdir()?;

    let file_path = dir.path().join("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
    }
    let db = SqlitePool::instantiate(&file_path).await?;
    tags(db, None).await?;

    Ok(())
}

async fn tags<DB: Database>(db: DB, db_params: Option<&ExtraDatabaseParams>) -> KResult<()> {
    log_init("debug");
    let mut rng = CsRng::from_entropy();

    // create a symmetric key with tags
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    // create symmetric key
    let symmetric_key = create_symmetric_key(&symmetric_key_bytes, CryptographicAlgorithm::AES);

    // insert into DB

    let owner = "eyJhbGciOiJSUzI1Ni";
    let uid = Uuid::new_v4().to_string();
    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned()]),
            db_params,
        )
        .await?;
    assert_eq!(&uid, &uid_);

    //recover the object from DB and check that the vendor attributes contain the tags
    match db
        .retrieve(&uid, owner, ObjectOperationTypes::Get, db_params)
        .await?
    {
        Some((obj_, state_, tags)) => {
            assert_eq!(StateEnumeration::Active, state_);
            assert_eq!(&symmetric_key, &obj_);
            assert_eq!(tags.len(), 2);
            assert!(tags.contains(&"tag1".to_string()));
            assert!(tags.contains(&"tag2".to_string()));
        }
        None => kms_bail!("There should be an object"),
    }

    // find this object from tags as owner using tag1
    let res = db
        .find_from_tags(&HashSet::from(["tag1".to_owned()]), None, db_params)
        .await?;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, uid);
    assert_eq!(res[0].1, owner);
    assert_eq!(res[0].2, StateEnumeration::Active);
    assert_eq!(res[0].3, vec![]);

    // find this object from tags as owner using tag2
    let res = db
        .find_from_tags(&HashSet::from(["tag2".to_owned()]), None, db_params)
        .await?;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, uid);
    assert_eq!(res[0].1, owner);
    assert_eq!(res[0].2, StateEnumeration::Active);
    assert_eq!(res[0].3, vec![]);

    // find this object from tags as owner using tag1 and tag2
    let res = db
        .find_from_tags(
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned()]),
            None,
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, uid);
    assert_eq!(res[0].1, owner);
    assert_eq!(res[0].2, StateEnumeration::Active);
    assert_eq!(res[0].3, vec![]);

    // should NOT find this object from tags as owner using tag1, tag2 and tag3
    let res = db
        .find_from_tags(
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned(), "tag3".to_owned()]),
            None,
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 0);

    // should NOT find this object from tags as owner using tag3
    let res = db
        .find_from_tags(&HashSet::from(["tag3".to_owned()]), None, db_params)
        .await?;
    assert_eq!(res.len(), 0);

    // grant the Get access right to USER_GET
    const USER_GET: &str = "user_get";
    db.grant_access(&uid, USER_GET, ObjectOperationTypes::Get, db_params)
        .await?;

    // grant the Decrypt access right to USER_DECRYPT
    const USER_DECRYPT: &str = "user_decrypt";
    db.grant_access(&uid, USER_DECRYPT, ObjectOperationTypes::Decrypt, db_params)
        .await?;

    // find this object from tags as USER_GET using tag1
    let res = db
        .find_from_tags(
            &HashSet::from(["tag1".to_owned()]),
            Some(USER_GET.to_owned()),
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, uid);
    assert_eq!(res[0].1, owner);
    assert_eq!(res[0].2, StateEnumeration::Active);
    assert_eq!(res[0].3, vec![ObjectOperationTypes::Get]);

    // find this object from tags as USER_DECRYPT using tag1
    let res = db
        .find_from_tags(
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned()]),
            Some(USER_DECRYPT.to_owned()),
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, uid);
    assert_eq!(res[0].1, owner);
    assert_eq!(res[0].2, StateEnumeration::Active);
    assert_eq!(res[0].3, vec![ObjectOperationTypes::Decrypt]);

    Ok(())
}
