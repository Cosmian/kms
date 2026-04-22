use std::{
    fs::File,
    io::{BufReader, Read},
};

use cosmian_kms_server_database::reexport::redis::{self, aio::ConnectionManager};
use cosmian_logger::{debug, trace};

use crate::{error::KmsError, result::KResult};

pub(crate) fn read_u64_le<R: Read>(reader: &mut R) -> std::io::Result<u64> {
    let mut buf = [0_u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

pub(crate) async fn restore_db_from_dump(
    mut mgr: ConnectionManager,
    path_to_file: File,
) -> KResult<()> {
    // --- Open the dump file ---
    let mut reader = BufReader::new(path_to_file);

    debug!("Proceeding RESTORE of all keys from redis_dump.bin...");

    let mut key_count = 0;

    loop {
        // --- Read the key-value pair from the file ---
        // 1. Read key length (as u64 little-endian)
        let key_len = match read_u64_le(&mut reader) {
            Ok(len) => Ok(len),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Reached end of file
                break;
            }
            Err(_e) => Err(KmsError::Default("Failed to read key length".to_owned())),
        }?;

        // 2. Read key data
        let mut key = vec![0_u8; key_len.try_into().unwrap()];
        reader
            .read_exact(&mut key)
            .expect("Failed to read key data");

        // 3. Read value length
        let value_len = read_u64_le(&mut reader)
            .expect("Failed to read value length")
            .try_into()
            .unwrap();

        // 4. Read value data
        let mut value_dump = vec![0_u8; value_len];
        reader
            .read_exact(&mut value_dump)
            .expect("Failed to read value data");

        // --- Restore the key-value pair to Redis ---
        // The command used is : RESTORE key ttl serialized-value [REPLACE]
        // ttl=0 means no expiration, REPLACE will overwrite if key exists
        let _: () = redis::cmd("RESTORE")
            .arg(&key)
            .arg(0) // TTL (0 = no expiration)
            .arg(&value_dump)
            .query_async(&mut mgr)
            .await
            .unwrap();

        key_count += 1;
        trace!(
            "Restored key #{}: '{}'",
            key_count,
            String::from_utf8_lossy(&key)
        );
    }

    debug!(
        "\nRestore complete. Restored {} key-value pairs from redis_dump.bin.",
        key_count
    );

    Ok(())
}

pub(crate) fn open_file(test_data_path: &str, filename: &str) -> File {
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    File::open(format!(
        "{}/{}/{}",
        current_dir.display(),
        test_data_path,
        filename
    ))
    .unwrap_or_else(|_| panic!("Failed to open {filename}"))
}
