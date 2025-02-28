#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::{path::Path, sync::Arc};

use cosmian_kms_crypto::crypto::{
    secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH,
};
use cosmian_kms_interfaces::SessionParams;
use cosmian_logger::log_init;
use tempfile::TempDir;

use self::{
    database_tests::{crud, tx_and_list, upsert},
    find_attributes_test::find_attributes,
    json_access_test::json_access,
    owner_test::owner,
    permissions_test::permissions,
    tagging_tests::tags,
};
use crate::{
    error::DbResult,
    stores::{
        CachedSqlCipher, MySqlPool, PgPool, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH, RedisWithFindex,
        SqlCipherSessionParams, SqlitePool,
        additional_redis_findex_tests::{test_corner_case, test_objects_db, test_permissions_db},
    },
    tests::{database_tests::atomic, list_uids_for_tags_test::list_uids_for_tags_test},
};

mod database_tests;
mod find_attributes_test;
mod json_access_test;
mod list_uids_for_tags_test;
mod owner_test;
mod permissions_test;
mod tagging_tests;

pub(crate) fn get_redis_url() -> String {
    std::env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    )
}

fn get_sql_cipher(dir: &Path) -> DbResult<CachedSqlCipher> {
    let db = CachedSqlCipher::instantiate(dir, true)?;
    Ok(db)
}

async fn get_sqlite(db_file: &Path) -> DbResult<SqlitePool> {
    SqlitePool::instantiate(db_file, true).await
}

// To run local tests with a Postgres in Docker, run
// docker run --name postgres -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432  -d postgres
async fn get_pgsql() -> DbResult<PgPool> {
    let postgres_url =
        option_env!("KMS_POSTGRES_URL").unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms");
    let pg = PgPool::instantiate(postgres_url, true).await?;
    Ok(pg)
}

// To run local tests with a MariaDB in Docker, run
// docker run --name mariadb --env MARIADB_DATABASE=kms  --env MARIADB_USER=kms --env MARIADB_PASSWORD=kms --env MARIADB_ROOT_PASSWORD=cosmian -p 3306:3306 -d mariadb
async fn get_mysql() -> DbResult<MySqlPool> {
    let mysql_url = option_env!("KMS_MYSQL_URL").unwrap_or("mysql://kms:kms@localhost:3306/kms");
    let my_sql = MySqlPool::instantiate(mysql_url, true).await?;
    Ok(my_sql)
}

// To run local tests with a Redis in Docker (and local storage - needed for transactions), run
// docker run --name redis -p 6379:6379 -d redis redis-server --save 60 1 --loglevel verbose
async fn get_redis_with_findex() -> DbResult<RedisWithFindex> {
    let redis_url = get_redis_url();
    let redis_url = option_env!("KMS_REDIS_URL").unwrap_or(&redis_url);
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::new_random()?;
    let redis_findex = RedisWithFindex::instantiate(redis_url, master_key, b"label").await?;
    Ok(redis_findex)
}

#[tokio::test]
pub(crate) async fn test_redis_with_findex() -> DbResult<()> {
    test_objects_db().await?;
    test_permissions_db().await?;
    test_corner_case().await?;
    json_access(&get_redis_with_findex().await?, None).await?;
    find_attributes(&get_redis_with_findex().await?, None).await?;
    owner(&get_redis_with_findex().await?, None).await?;
    permissions(&get_redis_with_findex().await?, None).await?;
    tags(&get_redis_with_findex().await?, None, false).await?;
    tx_and_list(&get_redis_with_findex().await?, None).await?;
    atomic(&get_redis_with_findex().await?, None).await?;
    upsert(&get_redis_with_findex().await?, None).await?;
    crud(&get_redis_with_findex().await?, None).await?;
    list_uids_for_tags_test(&get_redis_with_findex().await?, None).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_sql_cipher() -> DbResult<()> {
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

    let params: Arc<dyn SessionParams> = Arc::new(SqlCipherSessionParams {
        group_id: 0,
        key: db_key.clone(),
    });

    json_access(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    find_attributes(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    owner(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    permissions(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    tags(&get_sql_cipher(&dir_path)?, Some(params.clone()), true).await?;
    tx_and_list(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    atomic(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    upsert(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    crud(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    list_uids_for_tags_test(&get_sql_cipher(&dir_path)?, Some(params.clone())).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_sqlite() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    let dir = TempDir::new()?;
    let db_file = dir.path().join("test_sqlite.db");
    if db_file.exists() {
        std::fs::remove_file(&db_file)?;
    }

    json_access(&get_sqlite(&db_file).await?, None).await?;
    find_attributes(&get_sqlite(&db_file).await?, None).await?;
    owner(&get_sqlite(&db_file).await?, None).await?;
    permissions(&get_sqlite(&db_file).await?, None).await?;
    tags(&get_sqlite(&db_file).await?, None, true).await?;
    tx_and_list(&get_sqlite(&db_file).await?, None).await?;
    atomic(&get_sqlite(&db_file).await?, None).await?;
    upsert(&get_sqlite(&db_file).await?, None).await?;
    crud(&get_sqlite(&db_file).await?, None).await?;
    list_uids_for_tags_test(&get_sqlite(&db_file).await?, None).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_postgresql() -> DbResult<()> {
    json_access(&get_pgsql().await?, None).await?;
    find_attributes(&get_pgsql().await?, None).await?;
    owner(&get_pgsql().await?, None).await?;
    permissions(&get_pgsql().await?, None).await?;
    tags(&get_pgsql().await?, None, true).await?;
    tx_and_list(&get_pgsql().await?, None).await?;
    atomic(&get_pgsql().await?, None).await?;
    upsert(&get_pgsql().await?, None).await?;
    crud(&get_pgsql().await?, None).await?;
    list_uids_for_tags_test(&get_pgsql().await?, None).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_mysql() -> DbResult<()> {
    log_init(None);
    json_access(&get_mysql().await?, None).await?;
    find_attributes(&get_mysql().await?, None).await?;
    owner(&get_mysql().await?, None).await?;
    permissions(&get_mysql().await?, None).await?;
    tags(&get_mysql().await?, None, true).await?;
    tx_and_list(&get_mysql().await?, None).await?;
    atomic(&get_mysql().await?, None).await?;
    upsert(&get_mysql().await?, None).await?;
    crud(&get_mysql().await?, None).await?;
    list_uids_for_tags_test(&get_mysql().await?, None).await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_migrate_sqlite() -> DbResult<()> {
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
