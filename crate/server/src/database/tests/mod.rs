use std::path::PathBuf;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, symmetric_crypto::key::Key, CsRng, KeyTrait,
};
use cosmian_kms_utils::access::ExtraDatabaseParams;

use super::{cached_sqlcipher::CachedSqlCipher, sqlite::SqlitePool};
use crate::result::KResult;

mod database_tests;
mod json_access_test;
mod owner_test;
mod permissions_test;
mod tagging_tests;

async fn get_sql_cipher() -> KResult<(CachedSqlCipher, Option<ExtraDatabaseParams>)> {
    let dir = PathBuf::from("/tmp");

    // generate a database key
    let mut cs_rng = CsRng::from_entropy();
    let db_key = Key::<32>::new(&mut cs_rng);

    // SQLCipher uses a directory
    let dir_path = dir.join("test_sqlite_enc.db");
    if dir_path.exists() {
        std::fs::remove_dir_all(&dir_path).unwrap();
    }
    std::fs::create_dir_all(&dir_path).unwrap();

    let db = CachedSqlCipher::instantiate(&dir_path).await?;
    let params = ExtraDatabaseParams {
        group_id: 0,
        key: db_key.clone(),
    };
    Ok((db, Some(params)))
}

async fn get_sqlite() -> KResult<(SqlitePool, Option<ExtraDatabaseParams>)> {
    let dir = PathBuf::from("/tmp");

    let file_path = dir.join("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
    }
    Ok((SqlitePool::instantiate(&file_path).await?, None))
}
