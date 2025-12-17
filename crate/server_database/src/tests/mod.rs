#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_in_result
)]
use std::path::Path;

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
#[cfg(feature = "non-fips")]
use crate::stores::RedisWithFindex;
#[cfg(feature = "non-fips")]
use crate::stores::additional_redis_findex_tests::{
    test_corner_case, test_objects_db, test_permissions_db,
};
use crate::{
    error::DbResult,
    stores::{MySqlPool, PgPool, SqlitePool},
    tests::{
        database_tests::{atomic, block_cipher_mode_migration_after_json_deserialization},
        list_uids_for_tags_test::list_uids_for_tags_test,
    },
};

mod database_tests;
mod find_attributes_test;
mod json_access_test;
mod list_uids_for_tags_test;
mod owner_test;
mod permissions_test;
mod tagging_tests;

#[cfg(feature = "non-fips")]
pub(crate) fn get_redis_url() -> String {
    std::env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    )
}

async fn get_sqlite(db_file: &Path) -> DbResult<SqlitePool> {
    SqlitePool::instantiate(db_file, true, None).await
}

// To run local tests with a Postgres in Docker, run
// docker run --name postgres -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432  -d postgres
async fn get_pgsql() -> DbResult<PgPool> {
    let postgres_url =
        option_env!("KMS_POSTGRES_URL").unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms");
    let pg = PgPool::instantiate(postgres_url, true, None).await?;
    Ok(pg)
}

// To run local tests with a MariaDB in Docker, run
// docker run --name mariadb --env MARIADB_DATABASE=kms  --env MARIADB_USER=kms --env MARIADB_PASSWORD=kms --env MARIADB_ROOT_PASSWORD=cosmian -p 3306:3306 -d mariadb
// docker run --name mysql --env MYSQL_DATABASE=kms  --env MYSQL_USER=kms --env MYSQL_PASSWORD=kms --env MYSQL_ROOT_PASSWORD=cosmian -p 3306:3306 -d mysql:8.0.42
async fn get_mysql() -> DbResult<MySqlPool> {
    let mysql_url = option_env!("KMS_MYSQL_URL").unwrap_or("mysql://kms:kms@localhost:3306/kms");
    let my_sql = MySqlPool::instantiate(mysql_url, true, None).await?;
    Ok(my_sql)
}

// To run local tests with a Redis in Docker (and local storage - needed for transactions), run
// docker run --name redis -p 6379:6379 -d redis redis-server --save 60 1 --loglevel verbose
#[cfg(feature = "non-fips")]
async fn get_redis_with_findex() -> DbResult<RedisWithFindex> {
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
        CsRng, Secret, reexport::rand_core::SeedableRng,
    };

    use crate::stores::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;
    let mut rng = CsRng::from_entropy();

    let redis_url = get_redis_url();
    let redis_url = option_env!("KMS_REDIS_URL").unwrap_or(&redis_url);
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
    let redis_findex = RedisWithFindex::instantiate(redis_url, master_key, true).await?;
    Ok(redis_findex)
}

#[ignore = "Requires a running Redis instance"]
#[allow(clippy::large_stack_frames)] // This a test, we can skip this as long as test machines can handle such a stack
#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_db_redis_with_findex() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    test_objects_db().await?;
    test_permissions_db().await?;
    test_corner_case().await?;
    Box::pin(json_access(&get_redis_with_findex().await?)).await?;
    find_attributes(&get_redis_with_findex().await?).await?;
    owner(&get_redis_with_findex().await?).await?;
    permissions(&get_redis_with_findex().await?).await?;
    Box::pin(tags(&get_redis_with_findex().await?, false)).await?;
    tx_and_list(&get_redis_with_findex().await?).await?;
    atomic(&get_redis_with_findex().await?).await?;
    upsert(&get_redis_with_findex().await?).await?;
    crud(&get_redis_with_findex().await?).await?;
    list_uids_for_tags_test(&get_redis_with_findex().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_redis_with_findex().await?, None)
        .await?;
    Ok(())
}

/// Run the tests with a `SQLite` database.
/// For additional logging, run the tests with
/// ```Rust
/// log_init(Some(
///     "info,cosmian_kms_server=trace,cosmian_kms_server_database=trace,\
///      cosmian_kms_interfaces=trace",
/// ));
/// ```
#[tokio::test]
pub(crate) async fn test_db_sqlite() -> DbResult<()> {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("info"));
    let dir = TempDir::new()?;
    let db_file = dir.path().join("test_sqlite.db");
    if db_file.exists() {
        std::fs::remove_file(&db_file)?;
    }
    Box::pin(json_access(&get_sqlite(&db_file).await?)).await?;
    find_attributes(&get_sqlite(&db_file).await?).await?;
    owner(&get_sqlite(&db_file).await?).await?;
    permissions(&get_sqlite(&db_file).await?).await?;
    Box::pin(tags(&get_sqlite(&db_file).await?, true)).await?;
    tx_and_list(&get_sqlite(&db_file).await?).await?;
    atomic(&get_sqlite(&db_file).await?).await?;
    upsert(&get_sqlite(&db_file).await?).await?;
    crud(&get_sqlite(&db_file).await?).await?;
    list_uids_for_tags_test(&get_sqlite(&db_file).await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_sqlite(&db_file).await?, None)
        .await?;
    Ok(())
}

#[ignore = "Requires a running PostgreSQL instance"]
#[tokio::test]
pub(crate) async fn test_db_postgresql() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("trace"));
    Box::pin(json_access(&get_pgsql().await?)).await?;
    find_attributes(&get_pgsql().await?).await?;
    owner(&get_pgsql().await?).await?;
    permissions(&get_pgsql().await?).await?;
    Box::pin(tags(&get_pgsql().await?, true)).await?;
    tx_and_list(&get_pgsql().await?).await?;
    atomic(&get_pgsql().await?).await?;
    upsert(&get_pgsql().await?).await?;
    crud(&get_pgsql().await?).await?;
    list_uids_for_tags_test(&get_pgsql().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_pgsql().await?, None).await?;
    Ok(())
}

#[ignore = "Requires a running MySQL or MariaDB instance"]
#[tokio::test]
pub(crate) async fn test_db_mysql() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    Box::pin(json_access(&get_mysql().await?)).await?;
    find_attributes(&get_mysql().await?).await?;
    owner(&get_mysql().await?).await?;
    permissions(&get_mysql().await?).await?;
    Box::pin(tags(&get_mysql().await?, true)).await?;
    tx_and_list(&get_mysql().await?).await?;
    atomic(&get_mysql().await?).await?;
    upsert(&get_mysql().await?).await?;
    crud(&get_mysql().await?).await?;
    list_uids_for_tags_test(&get_mysql().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_mysql().await?, None).await?;
    Ok(())
}
