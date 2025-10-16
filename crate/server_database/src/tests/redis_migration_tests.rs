#![allow(unused)]

use byteorder::{LittleEndian, ReadBytesExt};
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore, SessionParams};
use cosmian_logger::{log_init, trace};
use redis::aio::ConnectionManager;
use std::{
    fs::{self, File},
    io::{BufReader, Read},
    sync::Arc,
};
use test_kms_server::start_default_test_kms_server;
use tokio::sync::broadcast::error;

use crate::{DbError, error::DbResult, stores::RedisWithFindex};

pub(super) async fn migrations(
    db: &RedisWithFindex,
    db_params: Option<Arc<dyn SessionParams>>,
) -> DbResult<()> {
    cosmian_logger::log_init(None);
    from_5_2_0_to_5_9_0(db, db_params).await?;
    Ok(())
}

// TODO: comment this function
// Also get rid of that library after asserting this code is correct
async fn restore_db_from_dump(mut mgr: ConnectionManager) -> DbResult<()> {
    // --- Open the dump file ---
    let input_file = File::open("migrate/redis_5_2_0_dump.bin").expect("Failed to open dump file");
    let mut reader = BufReader::new(input_file);

    trace!("Starting RESTORE of all keys from redis_dump.bin...");

    let mut key_count = 0;

    loop {
        // --- Read the key-value pair from the file ---
        // 1. Read key length (as u64 little-endian)
        let key_len = match reader.read_u64::<LittleEndian>() {
            Ok(len) => Ok(len),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Reached end of file
                break;
            }
            Err(e) => Err(DbError::Default("Failed to read key length".to_owned())),
        }?;

        // 2. Read key data
        let mut key = vec![0_u8; key_len.try_into().unwrap()];
        reader
            .read_exact(&mut key)
            .expect("Failed to read key data");

        // 3. Read value length
        let value_len = reader
            .read_u64::<LittleEndian>()
            .expect("Failed to read value length")
            .try_into()
            .unwrap();

        // 4. Read value data
        let mut value_dump = vec![0_u8; value_len];
        reader
            .read_exact(&mut value_dump)
            .expect("Failed to read value data");

        // --- Restore the key-value pair to Redis ---
        // RESTORE key ttl serialized-value [REPLACE]
        // ttl=0 means no expiration, REPLACE will overwrite if key exists
        let _: () = redis::cmd("RESTORE")
            .arg(&key)
            .arg(0) // TTL (0 = no expiration)
            .arg(&value_dump)
            .query_async(&mut mgr)
            .await?;

        key_count += 1;
        trace!(
            "Restored key #{}: '{}'",
            key_count,
            String::from_utf8_lossy(&key)
        );
    }

    trace!(
        "\nRestore complete. Restored {} key-value pairs from redis_dump.bin.",
        key_count
    );

    Ok(())
}

async fn from_5_2_0_to_5_9_0(
    db: &RedisWithFindex,
    db_params: Option<Arc<dyn SessionParams>>,
) -> DbResult<()> {
    log_init(None);

    let mgr = db.mgr.clone();

    // flush the redis and insert the data from a redis dump made with a 5.2.0 version of the KMS
    redis::cmd("FLUSHDB")
        .query_async::<()>(&mut mgr.clone())
        .await?;

    // The restored database should look like this:
    // | ID | Tags | Kind | Comments | Permissions |
    // | :-- | :-- | :-- | :-- | :-- |
    // | mt_normal_aes | cat, dog, cow | AES | None | mt_normal_user: Get, Encrypt, Decrypt |
    // | mt_rsa | cat, fox | RSA | None | (not specified) |
    // | mt_rsa_pk | cat, fox | RSA | None | (not specified) |
    // | mt_covercrypt | cat, dog | Covercrypt | The example JSON | mt_owner: ALL permissions |
    // | mt_covercrypt_pk | cat, dog | Covercrypt | The example JSON | mt_owner: ALL permissions |
    restore_db_from_dump(mgr).await;

    // we start a fresh KMS, who finds the data in redis, and migrates it
    let ctx = start_default_test_kms_server().await;

    // now, we check that the data is correctly migrated by "getting" it

    Ok(())
}
