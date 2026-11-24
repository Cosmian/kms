//! Per-database KDF salt of the Redis master password: random for new databases, the legacy
//! fixed salt for databases created before it.

use cosmian_kms_crypto::reexport::cosmian_crypto_core::FixedSizeCBytes;
use redis::aio::ConnectionManager;

use super::get_redis_url;
use crate::{
    db_ensure,
    error::DbResult,
    redis_master_key_from_password,
    stores::{
        RedisWithFindex,
        redis::redis_with_findex::{
            REDIS_KDF_SALT_KEY, redis_master_key_for_database,
            redis_master_key_from_password_with_salt,
        },
    },
};

/// Redis database index used by these tests (the migration fixtures use 14).
const SALT_TEST_REDIS_DB: u8 = 13;
const PASSWORD: &str = "salt-test-password";
const LEGACY_SALT: &[u8; 16] = b"rediswithfindex_";

/// URL of the test database, flushed.
async fn empty_database() -> DbResult<(String, ConnectionManager)> {
    let url = format!("{}/{SALT_TEST_REDIS_DB}", get_redis_url());
    let mut mgr = ConnectionManager::new(redis::Client::open(url.as_str())?).await?;
    redis::cmd("FLUSHDB").query_async::<()>(&mut mgr).await?;
    Ok((url, mgr))
}

async fn stored_salt(mgr: &mut ConnectionManager) -> DbResult<Vec<u8>> {
    Ok(redis::cmd("GET")
        .arg(REDIS_KDF_SALT_KEY)
        .query_async(mgr)
        .await?)
}

/// An empty database gets a random 16-byte salt, kept across restarts.
pub(super) async fn test_redis_fresh_db_uses_random_salt() -> DbResult<()> {
    let (url, mut mgr) = empty_database().await?;
    let key = redis_master_key_for_database(&url, PASSWORD).await?;
    let salt = stored_salt(&mut mgr).await?;
    db_ensure!(salt.len() == 16, "salt is {} bytes", salt.len());
    db_ensure!(
        salt != LEGACY_SALT,
        "a fresh database must not use the legacy salt"
    );
    db_ensure!(
        key.to_bytes() != redis_master_key_from_password(PASSWORD)?.to_bytes(),
        "a fresh database must not derive the legacy key"
    );
    let again = redis_master_key_for_database(&url, PASSWORD).await?;
    db_ensure!(
        key.to_bytes() == again.to_bytes(),
        "the key must be stable across restarts"
    );
    Ok(())
}

/// A database that holds data but no salt (created by an older KMS) keeps the legacy salt,
/// and the data written with the legacy key stays readable.
pub(super) async fn test_redis_legacy_db_keeps_legacy_salt() -> DbResult<()> {
    let (url, mut mgr) = empty_database().await?;
    let legacy_key = redis_master_key_from_password(PASSWORD)?;
    // what an older KMS leaves behind: data, no `kms_kdf_salt`
    let secret = cosmian_kms_crypto::reexport::cosmian_crypto_core::Secret::from_unprotected_bytes(
        &mut legacy_key.to_bytes(),
    );
    drop(RedisWithFindex::instantiate(&url, secret, true).await?);
    redis::cmd("DEL")
        .arg(REDIS_KDF_SALT_KEY)
        .query_async::<()>(&mut mgr)
        .await?;

    let key = redis_master_key_for_database(&url, PASSWORD).await?;
    db_ensure!(
        stored_salt(&mut mgr).await? == LEGACY_SALT,
        "the legacy salt must be recorded"
    );
    db_ensure!(
        key.to_bytes() == legacy_key.to_bytes(),
        "a legacy database must keep deriving the legacy key"
    );
    Ok(())
}

/// Clearing the database keeps its salt: the key held in memory still matches it.
pub(super) async fn test_redis_clear_keeps_salt() -> DbResult<()> {
    let (url, mut mgr) = empty_database().await?;
    let key = redis_master_key_for_database(&url, PASSWORD).await?;
    let salt = stored_salt(&mut mgr).await?;
    let secret = cosmian_kms_crypto::reexport::cosmian_crypto_core::Secret::from_unprotected_bytes(
        &mut key.to_bytes(),
    );
    drop(RedisWithFindex::instantiate(&url, secret, true).await?);
    db_ensure!(
        stored_salt(&mut mgr).await? == salt,
        "clearing the database must keep its salt"
    );
    Ok(())
}

#[test]
fn redis_master_key_from_password_with_salt_depends_on_salt() -> DbResult<()> {
    let a = redis_master_key_from_password_with_salt(PASSWORD, &[1; 16])?;
    let b = redis_master_key_from_password_with_salt(PASSWORD, &[2; 16])?;
    db_ensure!(a.to_bytes() != b.to_bytes(), "different salts, same key");
    db_ensure!(
        a.to_bytes() == redis_master_key_from_password_with_salt(PASSWORD, &[1; 16])?.to_bytes(),
        "same salt, different keys"
    );
    db_ensure!(
        redis_master_key_from_password_with_salt(PASSWORD, LEGACY_SALT)?.to_bytes()
            == redis_master_key_from_password(PASSWORD)?.to_bytes(),
        "the legacy key is the key of the legacy salt"
    );
    Ok(())
}
