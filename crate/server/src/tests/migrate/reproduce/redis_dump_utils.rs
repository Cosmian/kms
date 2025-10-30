//! the code in this file is only for reproducing test data, it should not be included in production builds and neither on running tests
#![allow(clippy::all, unused)]
use redis::aio::ConnectionManager;
use redis::{Commands, RedisResult};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::io::{BufWriter, Write};

async fn dump_all(mut mgr: ConnectionManager, file_name: String) -> () {
    // --- Prepare the output file ---
    let output_file = File::create(file_name).expect("Failed to create dump file");
    let mut writer = BufWriter::new(output_file);

    println!("Starting SCAN and DUMP of all keys...");

    // --- Scan all keys ---
    let mut cursor = 0_u64;
    let mut key_count = 0;

    loop {
        let (new_cursor, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
            .arg(cursor)
            .query_async(&mut mgr)
            .await
            .unwrap();

        for key in keys {
            let value_dump: Vec<u8> = redis::cmd("DUMP")
                .arg(&key)
                .query_async(&mut mgr)
                .await
                .unwrap();

            // --- Write the key-value pair to the file ---
            // 1. Write key length (as u64 little-endian)
            writer
                .write_all(&(key.len() as u64).to_le_bytes())
                .expect("Failed to write key length");
            // 2. Write key data
            writer.write_all(&key).expect("Failed to write key data");
            // 3. Write value length
            writer
                .write_all(&(value_dump.len() as u64).to_le_bytes())
                .expect("Failed to write value length");
            // 4. Write value data
            writer
                .write_all(&value_dump)
                .expect("Failed to write value data");

            key_count += 1;
            println!("Wrote key #{} to redis_dump.bin", key_count);
        }

        cursor = new_cursor;
        if cursor == 0 {
            break;
        }
    }

    println!(
        "\nDump complete. Wrote {} key-value pairs to redis_dump.bin.",
        key_count
    );
}

fn read_u64_le<R: Read>(reader: &mut R) -> std::io::Result<u64> {
    let mut buf = [0_u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

pub async fn verify_dump(file_name: String) -> RedisResult<()> {
    // --- Connect to Redis ---
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let mut mgr = ConnectionManager::new(client).await?;

    println!("Reading keys from redis_dump.bin...");

    // --- Open and read the dump file ---
    let input_file = File::open(file_name).expect("Failed to open dump file");
    let mut reader = BufReader::new(input_file);

    // Store the dumped data in a HashMap for comparison
    let mut dump_data: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    // Read all key-value pairs from the dump file
    loop {
        // Try to read the key length
        let key_len = match read_u64_le(&mut reader) {
            Ok(len) => Ok::<_, redis::RedisError>(len),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Reached end of file
                break;
            }
            Err(e) => panic!("Failed to read key length: {}", e),
        }?;

        // Read the key data
        let mut key = vec![0_u8; key_len.try_into().unwrap()];
        reader
            .read_exact(&mut key)
            .expect("Failed to read key data");

        // Read the value length
        let value_len = read_u64_le(&mut reader)
            .expect("Failed to read value length")
            .try_into()
            .unwrap();

        // Read the value data
        let mut value = vec![0_u8; value_len];
        reader
            .read_exact(&mut value)
            .expect("Failed to read value data");

        dump_data.insert(key, value);
    }

    println!("Read {} key-value pairs from dump file.", dump_data.len());

    // --- Now compare with Redis ---
    println!("\nStarting verification against Redis...");

    let mut cursor = 0_u64;
    let mut verified_count = 0;
    let mut mismatch_count = 0;
    let mut missing_count = 0;

    loop {
        let (new_cursor, keys): (u64, Vec<Vec<u8>>) =
            redis::cmd("SCAN").arg(cursor).query_async(&mut mgr).await?;

        for key in keys {
            // Get the DUMP from Redis
            let redis_dump: Vec<u8> = redis::cmd("DUMP").arg(&key).query_async(&mut mgr).await?;

            // Check if this key exists in our dump file
            match dump_data.get(&key) {
                Some(file_dump) => {
                    if &redis_dump == file_dump {
                        verified_count += 1;
                        println!("✓ Key '{}' matches", String::from_utf8_lossy(&key));
                    } else {
                        mismatch_count += 1;
                        println!(
                            "✗ Key '{}' has different dump values!",
                            String::from_utf8_lossy(&key)
                        );
                        println!("  Redis dump length: {}", redis_dump.len());
                        println!("  File dump length: {}", file_dump.len());
                    }
                }
                None => {
                    missing_count += 1;
                    println!(
                        "✗ Key '{}' exists in Redis but not in dump file!",
                        String::from_utf8_lossy(&key)
                    );
                }
            }
        }

        cursor = new_cursor;
        if cursor == 0 {
            break;
        }
    }

    // Check for keys in dump file that don't exist in Redis
    let mut extra_in_dump = 0;
    for key in dump_data.keys() {
        let exists: bool = redis::cmd("EXISTS").arg(key).query_async(&mut mgr).await?;

        if !exists {
            extra_in_dump += 1;
            println!(
                "✗ Key '{}' exists in dump file but not in Redis!",
                String::from_utf8_lossy(key)
            );
        }
    }

    // --- Print summary ---
    println!("\n=== Verification Summary ===");
    println!("Total keys in dump file: {}", dump_data.len());
    println!("Keys verified successfully: {}", verified_count);
    println!("Keys with mismatched values: {}", mismatch_count);
    println!("Keys in Redis but missing from dump: {}", missing_count);
    println!("Keys in dump but missing from Redis: {}", extra_in_dump);

    if mismatch_count == 0 && missing_count == 0 && extra_in_dump == 0 {
        println!("\n✓ All keys match perfectly!");
    } else {
        println!("\n✗ Verification failed - discrepancies found!");
    }

    Ok(())
}
