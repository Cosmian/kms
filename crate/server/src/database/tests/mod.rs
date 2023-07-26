use std::path::PathBuf;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, RandomFixedSizeCBytes, SymmetricKey,
};
use cosmian_kms_utils::access::ExtraDatabaseParams;

use self::{
    database_tests::{crud, tx_and_list, upsert},
    find_attributes_test::find_attributes,
    json_access_test::json_access,
    owner_test::owner,
    permissions_test::permissions,
    tagging_tests::tags,
};
use super::{
    cached_sqlcipher::CachedSqlCipher, mysql::MySqlPool, pgsql::PgPool, sqlite::SqlitePool,
};
use crate::result::KResult;

mod database_tests;
mod find_attributes_test;
mod json_access_test;
mod owner_test;
mod permissions_test;
mod tagging_tests;

async fn get_sql_cipher() -> KResult<(CachedSqlCipher, Option<ExtraDatabaseParams>)> {
    let dir = PathBuf::from("/tmp");

    // generate a database key
    let mut cs_rng = CsRng::from_entropy();
    let db_key = SymmetricKey::<32>::new(&mut cs_rng);

    // SQLCipher uses a directory
    let dir_path = dir.join("test_sqlite_enc.db");
    if dir_path.exists() {
        std::fs::remove_dir_all(&dir_path).unwrap();
    }
    std::fs::create_dir_all(&dir_path).unwrap();

    let db = CachedSqlCipher::instantiate(&dir_path, true).await?;
    let params = ExtraDatabaseParams {
        group_id: 0,
        key: db_key,
    };
    Ok((db, Some(params)))
}

async fn get_sqlite() -> KResult<(SqlitePool, Option<ExtraDatabaseParams>)> {
    let dir = PathBuf::from("/tmp");

    let file_path = dir.join("test_sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(&file_path).unwrap();
    }
    Ok((SqlitePool::instantiate(&file_path, true).await?, None))
}

// To run local tests with a Postgres in Docker, run
// docker run --name postgres -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432  -d postgres
async fn get_pgsql() -> KResult<(PgPool, Option<ExtraDatabaseParams>)> {
    let postgres_url =
        std::option_env!("KMS_POSTGRES_URL").unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms");
    let pg = PgPool::instantiate(postgres_url, true).await?;
    Ok((pg, None))
}

// To run local tests with a MariaDB in Docker, run
// docker run --name mariadb --env MARIADB_DATABASE=kms  --env MARIADB_USER=kms --env MARIADB_PASSWORD=kms --env MARIADB_ROOT_PASSWORD=cosmian -p 3306:3306 -d mariadb
async fn get_mysql() -> KResult<(MySqlPool, Option<ExtraDatabaseParams>)> {
    let mysql_url =
        std::option_env!("KMS_MYSQL_URL").unwrap_or("mysql://kms:kms@localhost:3306/kms");
    let my_sql = MySqlPool::instantiate(mysql_url, true).await?;
    Ok((my_sql, None))
}

#[actix_rt::test]
pub async fn test_sql_cipher() -> KResult<()> {
    json_access(&get_sql_cipher().await?).await?;
    find_attributes(&get_sql_cipher().await?).await?;
    owner(&get_sql_cipher().await?).await?;
    permissions(&get_sql_cipher().await?).await?;
    tags(&get_sql_cipher().await?).await?;
    tx_and_list(&get_sql_cipher().await?).await?;
    upsert(&get_sql_cipher().await?).await?;
    crud(&get_sql_cipher().await?).await?;
    Ok(())
}

#[actix_rt::test]
pub async fn test_sqlite() -> KResult<()> {
    find_attributes(&get_sqlite().await?).await?;
    json_access(&get_sqlite().await?).await?;
    owner(&get_sqlite().await?).await?;
    permissions(&get_sqlite().await?).await?;
    tags(&get_sqlite().await?).await?;
    tx_and_list(&get_sqlite().await?).await?;
    upsert(&get_sqlite().await?).await?;
    crud(&get_sqlite().await?).await?;
    Ok(())
}

#[actix_rt::test]
pub async fn test_pgsql() -> KResult<()> {
    json_access(&get_pgsql().await?).await?;
    find_attributes(&get_pgsql().await?).await?;
    owner(&get_pgsql().await?).await?;
    permissions(&get_pgsql().await?).await?;
    tags(&get_pgsql().await?).await?;
    tx_and_list(&get_pgsql().await?).await?;
    upsert(&get_pgsql().await?).await?;
    crud(&get_pgsql().await?).await?;
    Ok(())
}

#[actix_rt::test]
pub async fn test_mysql() -> KResult<()> {
    crud(&get_mysql().await?).await?;
    upsert(&get_mysql().await?).await?;
    tx_and_list(&get_mysql().await?).await?;
    json_access(&get_mysql().await?).await?;
    find_attributes(&get_mysql().await?).await?;
    owner(&get_mysql().await?).await?;
    permissions(&get_mysql().await?).await?;
    tags(&get_mysql().await?).await?;
    Ok(())
}
