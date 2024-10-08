#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use cosmian_kmip::crypto::{secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH};
use cosmian_logger::log_utils::log_init;
use tempfile::TempDir;

use self::{
    additional_redis_findex_tests::{test_corner_case, test_objects_db, test_permissions_db},
    database_tests::{crud, tx_and_list, upsert},
    find_attributes_test::find_attributes,
    json_access_test::json_access,
    owner_test::owner,
    permissions_test::permissions,
    tagging_tests::tags,
};
use super::{
    cached_sqlcipher::CachedSqlCipher,
    mysql::MySqlPool,
    pgsql::PgPool,
    redis::{RedisWithFindex, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH},
    sqlite::SqlitePool,
};
use crate::{
    core::extra_database_params::ExtraDatabaseParams, database::tests::database_tests::atomic,
    result::KResult,
};

mod additional_redis_findex_tests;
mod database_tests;
mod find_attributes_test;
mod json_access_test;
mod owner_test;
mod permissions_test;
mod tagging_tests;

fn get_redis_url() -> String {
    std::env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    )
}

fn get_sql_cipher(
    dir: &Path,
    db_key: &Secret<AES_256_GCM_KEY_LENGTH>,
) -> KResult<(CachedSqlCipher, Option<ExtraDatabaseParams>)> {
    let db = CachedSqlCipher::instantiate(dir, true)?;
    let params = ExtraDatabaseParams {
        group_id: 0,
        key: db_key.clone(),
    };
    Ok((db, Some(params)))
}

async fn get_sqlite(db_file: &Path) -> KResult<(SqlitePool, Option<ExtraDatabaseParams>)> {
    Ok((SqlitePool::instantiate(db_file, true).await?, None))
}

// To run local tests with a Postgres in Docker, run
// docker run --name postgres -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432  -d postgres
async fn get_pgsql() -> KResult<(PgPool, Option<ExtraDatabaseParams>)> {
    let postgres_url =
        option_env!("KMS_POSTGRES_URL").unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms");
    let pg = PgPool::instantiate(postgres_url, true).await?;
    Ok((pg, None))
}

// To run local tests with a MariaDB in Docker, run
// docker run --name mariadb --env MARIADB_DATABASE=kms  --env MARIADB_USER=kms --env MARIADB_PASSWORD=kms --env MARIADB_ROOT_PASSWORD=cosmian -p 3306:3306 -d mariadb
async fn get_mysql() -> KResult<(MySqlPool, Option<ExtraDatabaseParams>)> {
    let mysql_url = option_env!("KMS_MYSQL_URL").unwrap_or("mysql://kms:kms@localhost:3306/kms");
    let my_sql = MySqlPool::instantiate(mysql_url, true).await?;
    Ok((my_sql, None))
}

// To run local tests with a Redis in Docker (and local storage - needed for transactions), run
// docker run --name redis -p 6379:6379 -d redis redis-server --save 60 1 --loglevel verbose
async fn get_redis_with_findex() -> KResult<(RedisWithFindex, Option<ExtraDatabaseParams>)> {
    let redis_url = get_redis_url();
    let redis_url = option_env!("KMS_REDIS_URL").unwrap_or(&redis_url);
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::new_random()?;
    let redis_findex = RedisWithFindex::instantiate(redis_url, master_key, b"label").await?;
    Ok((redis_findex, None))
}

#[tokio::test]
pub(crate) async fn test_redis_with_findex() -> KResult<()> {
    test_objects_db().await?;
    test_permissions_db().await?;
    test_corner_case().await?;
    json_access(&get_redis_with_findex().await?).await?;
    find_attributes(&get_redis_with_findex().await?).await?;
    owner(&get_redis_with_findex().await?).await?;
    permissions(&get_redis_with_findex().await?).await?;
    tags(&get_redis_with_findex().await?, false).await?;
    tx_and_list(&get_redis_with_findex().await?).await?;
    atomic(&get_redis_with_findex().await?).await?;
    upsert(&get_redis_with_findex().await?).await?;
    crud(&get_redis_with_findex().await?).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_sql_cipher() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let dir = TempDir::new()?;
    // SQLCipher uses a directory
    let dir_path = dir.path().join("test_sqlite_enc.db");
    if dir_path.exists() {
        std::fs::remove_dir_all(&dir_path)?;
    }
    std::fs::create_dir_all(&dir_path)?;

    // generate a database key
    let db_key = Secret::<AES_256_GCM_KEY_LENGTH>::new_random()?;

    json_access(&get_sql_cipher(&dir_path, &db_key)?).await?;
    find_attributes(&get_sql_cipher(&dir_path, &db_key)?).await?;
    owner(&get_sql_cipher(&dir_path, &db_key)?).await?;
    permissions(&get_sql_cipher(&dir_path, &db_key)?).await?;
    tags(&get_sql_cipher(&dir_path, &db_key)?, true).await?;
    tx_and_list(&get_sql_cipher(&dir_path, &db_key)?).await?;
    atomic(&get_sql_cipher(&dir_path, &db_key)?).await?;
    upsert(&get_sql_cipher(&dir_path, &db_key)?).await?;
    crud(&get_sql_cipher(&dir_path, &db_key)?).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_sqlite() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let dir = TempDir::new()?;
    let db_file = dir.path().join("test_sqlite.db");
    if db_file.exists() {
        std::fs::remove_file(&db_file)?;
    }

    json_access(&get_sqlite(&db_file).await?).await?;
    find_attributes(&get_sqlite(&db_file).await?).await?;
    owner(&get_sqlite(&db_file).await?).await?;
    permissions(&get_sqlite(&db_file).await?).await?;
    tags(&get_sqlite(&db_file).await?, true).await?;
    tx_and_list(&get_sqlite(&db_file).await?).await?;
    atomic(&get_sqlite(&db_file).await?).await?;
    upsert(&get_sqlite(&db_file).await?).await?;
    crud(&get_sqlite(&db_file).await?).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_postgresql() -> KResult<()> {
    json_access(&get_pgsql().await?).await?;
    find_attributes(&get_pgsql().await?).await?;
    owner(&get_pgsql().await?).await?;
    permissions(&get_pgsql().await?).await?;
    tags(&get_pgsql().await?, true).await?;
    tx_and_list(&get_pgsql().await?).await?;
    atomic(&get_pgsql().await?).await?;
    upsert(&get_pgsql().await?).await?;
    crud(&get_pgsql().await?).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mysql() -> KResult<()> {
    log_init(None);
    json_access(&get_mysql().await?).await?;
    find_attributes(&get_mysql().await?).await?;
    owner(&get_mysql().await?).await?;
    permissions(&get_mysql().await?).await?;
    tags(&get_mysql().await?, true).await?;
    tx_and_list(&get_mysql().await?).await?;
    atomic(&get_mysql().await?).await?;
    upsert(&get_mysql().await?).await?;
    crud(&get_mysql().await?).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_migrate_sqlite() -> KResult<()> {
    log_init(None);
    for sqlite_path in [
        "src/tests/migrate/kms_4.12.0.sqlite",
        "src/tests/migrate/kms_4.16.0.sqlite",
        "src/tests/migrate/kms_4.17.0.sqlite",
    ] {
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        let tmp_file_path = tmp_path.join("kms.db");
        if tmp_file_path.exists() {
            std::fs::remove_file(&tmp_file_path)?;
        }
        std::fs::copy(sqlite_path, &tmp_file_path)?;
        SqlitePool::instantiate(&tmp_file_path, false).await?;
    }
    Ok(())
}
