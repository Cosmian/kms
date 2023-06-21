use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    symmetric_crypto::key::Key,
    CsRng, KeyTrait,
};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_types::{Attributes, CryptographicAlgorithm},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams, crypto::symmetric::create_symmetric_key, tagging::set_tag,
};
use tempfile::tempdir;
use uuid::Uuid;

use crate::{
    database::{cached_sqlcipher::CachedSqlCipher, sqlite::SqlitePool, Database},
    log_utils::log_init,
    result::KResult,
};

#[actix_rt::test]
async fn test_sql_cipher() -> KResult<()> {
    let dir = tempdir()?;

    // SQLCipher uses a directory
    let dir_path = dir.path().join("test_sqlite_enc.db");
    if dir_path.exists() {
        std::fs::remove_dir_all(&dir_path).unwrap();
    }
    std::fs::create_dir_all(&dir_path).unwrap();

    // instantiate the database
    let db = CachedSqlCipher::instantiate(&dir_path).await?;

    // generate a database key
    let mut cs_rng = CsRng::from_entropy();
    let db_key = Key::<32>::new(&mut cs_rng);
    let params = ExtraDatabaseParams {
        group_id: 0,
        key: db_key,
    };

    // run the tests
    let _uid = create(db, Some(&params)).await?;
    Ok(())
}

// SQLite test
#[actix_rt::test]
#[cfg_attr(feature = "sqlcipher", ignore)]
async fn test_sqlite() -> KResult<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
    }
    let db = SqlitePool::instantiate(&file_path).await?;

    let _uid = create(db, None).await?;

    Ok(())
}

async fn create<DB: Database>(db: DB, db_params: Option<&ExtraDatabaseParams>) -> KResult<String> {
    log_init("info");
    let mut rng = CsRng::from_entropy();

    // create a symmetric key with tags
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    // insert tags
    let mut attributes = Attributes::new(ObjectType::SymmetricKey);
    set_tag(&mut attributes, "tag1")?;
    set_tag(&mut attributes, "tag2")?;
    // create symmetric key
    let symmetric_key = create_symmetric_key(
        &symmetric_key_bytes,
        CryptographicAlgorithm::AES,
        attributes.vendor_attributes,
    );

    // insert into DB
    let owner = "eyJhbGciOiJSUzI1Ni";
    let uid = Uuid::new_v4().to_string();
    let uid_ = db
        .create(Some(uid.clone()), owner, &symmetric_key, db_params)
        .await?;
    assert_eq!(&uid, &uid_);

    Ok(uid)
}
