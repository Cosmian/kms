use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_operations::{Decrypt, Revoke},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::kmip_operations::Locate,
    redis::{self, aio::ConnectionManager},
};
use cosmian_logger::{TracingConfig, trace, tracing_init};

use crate::{
    config::{MainDBConfig, ServerParams},
    core::KMS,
    result::KResult,
    tests::{
        migrate::utils::{open_file, restore_db_from_dump},
        test_utils::https_clap_config,
    },
};

const TEST_DATA_PATH: &str = "src/tests/migrate/data";

fn get_redis_url() -> String {
    option_env!("KMS_REDIS_URL")
        .unwrap_or(&std::env::var("REDIS_HOST").map_or_else(
            |_| "redis://localhost:6379".to_owned(),
            |var_env| format!("redis://{var_env}:6379"),
        ))
        .to_owned()
}

#[allow(deprecated)] // the deprecated label is necessary to test migration from old versions
async fn init_test_kms(dump_filename: &str) -> KResult<Arc<KMS>> {
    let redis_url = get_redis_url();
    let client = redis::Client::open(redis_url.clone()).unwrap();
    let mgr = ConnectionManager::new(client).await.unwrap();

    // flush the redis before inserting the data from a redis dump
    redis::cmd("FLUSHALL")
        .query_async::<()>(&mut mgr.clone())
        .await
        .unwrap();

    let dump_file = open_file(TEST_DATA_PATH, dump_filename);
    restore_db_from_dump(mgr, dump_file).await?;

    // start a fresh KMS, it finds the data in redis, and migrates it
    let mut clap_config = https_clap_config();
    clap_config.db = MainDBConfig {
        database_type: Some("redis-findex".to_owned()),
        database_url: Some(redis_url.clone()),
        redis_master_password: Some("password".to_owned()),
        clear_database: false,
        ..Default::default()
    };
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    Ok(kms)
}

fn log_init_colorized(rust_log: Option<&str>) {
    let config = TracingConfig {
        rust_log: rust_log
            .or(option_env!("RUST_LOG"))
            .map(std::borrow::ToOwned::to_owned),
        with_ansi_colors: true,
        ..TracingConfig::default()
    };
    tracing_init(&config);
}

// The restored database should look like this:
// | ID | Tags | Kind | Comments | Permissions |
// | :-- | :-- | :-- | :-- | :-- |
// | mt_normal_aes | cat, dog, cow | AES | None | mt_normal_user: Get, Encrypt, Decrypt, mt_owner: ALL permissions |
// | mt_rsa | cat, fox | RSA | None | mt_owner: ALL permissions|
// | mt_rsa_pk | cat, fox | RSA | None | mt_owner: ALL permissions|
// | [UID_Covercrypt] | cat, dog | Covercrypt | The example JSON | mt_owner: ALL permissions |
// | [UID_Covercrypt]_pk | cat, dog | Covercrypt | The example JSON | mt_owner: ALL permissions |
#[allow(deprecated)]
async fn from_5_2_0_to_5_12_0() -> KResult<()> {
    log_init_colorized(option_env!("RUST_LOG"));

    let owner = "mt_owner";
    let user = "mt_normal_user";
    let kms = init_test_kms("redis_dump_v5_2_0.bin").await?;

    // Now, we check that the data is correctly migrated by "locating" it.
    // All keys have the "cat" tag, so the owner should find 5 keys.
    let mut search_attrs = Attributes::default();
    let _: () = search_attrs.set_tags(vec!["cat".to_owned()])?;
    let locate = Locate {
        attributes: search_attrs.clone(),
        ..Locate::default()
    };
    let locate_response = kms
        .locate(
            Locate {
                attributes: search_attrs.clone(),
                ..Locate::default()
            },
            owner,
        )
        .await?;
    assert_eq!(locate_response.located_items.unwrap(), 5);

    // verify permission boundaries: normal user can only "get" 1 key (with the same request)
    let locate_response = kms.locate(locate, user).await?;
    assert_eq!(locate_response.located_items.unwrap(), 1);

    // but he hasn't enough rights to, for example, revoke it
    let revoke_response = kms
        .revoke(
            Revoke {
                unique_identifier: Some(UniqueIdentifier::from("mt_normal_aes".to_owned())),
                revocation_reason: RevocationReason {
                    revocation_message: Some("Test".to_owned()),
                    revocation_reason_code: RevocationReasonCode::Unspecified,
                },
                compromise_occurrence_date: None,
                cascade: true,
            },
            user,
        )
        .await;
    revoke_response.unwrap_err();

    // Verify specific individual keys can be retrieved with more fine-grained search
    let test_keys = vec![
        (
            vec!["cat", "dog", "cow"],
            Some(CryptographicAlgorithm::AES),
            1,
        ),
        (vec!["cat", "fox"], Some(CryptographicAlgorithm::RSA), 2),
        (
            vec!["cat", "dog"],
            Some(CryptographicAlgorithm::CoverCrypt),
            2,
        ),
    ];

    for (expected_tags, expected_algo, expected_result) in test_keys {
        let mut key_attrs = Attributes {
            cryptographic_algorithm: expected_algo,
            ..Default::default()
        };

        key_attrs.set_tags(expected_tags)?;

        let locate_specific = Locate {
            attributes: key_attrs,
            ..Locate::default()
        };
        let specific_response = kms.locate(locate_specific, owner).await?;

        let found_count = specific_response.located_items.unwrap();

        trace!("Found {found_count} keys with tags algo {expected_algo:?}, object type");
        // Should find at least one key with these attributes
        assert_eq!(
            found_count, expected_result,
            "Should find {expected_result} keys... found {found_count} keys",
        );
    }

    // Key sanity check: try to decrypt and verify it matches the expected output
    // The plaintext (already encrypted using the anterior KMS version) : "The quick brown fox jumps over the lazy dog\n"
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let encrypted_bytes = std::fs::read(format!(
        "{}/{}/encrypted_data_5_2_0.enc",
        current_dir.display(),
        TEST_DATA_PATH
    ))?;

    let decrypt_response = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(UniqueIdentifier::from("mt_rsa".to_owned())),
                data: Some(encrypted_bytes),
                ..Decrypt::default()
            },
            owner,
        )
        .await?;

    trace!("decrypt response: {:?}", decrypt_response.data);
    assert_eq!(
        decrypt_response.data.as_ref().map(|z| z.as_slice()),
        Some(b"The quick brown fox jumps over the lazy dog\n".as_slice())
    );

    Ok(())
}

// This test DB was produced using the ui - to reproduce it, do the following:
// - have a redis running at localhost:6379
// - start a 5.0.0 KMS with a fresh redis database :
// ```bash
// docker run -p 9998:9998 --rm --name kms_demo \
//   --network host \
//   ghcr.io/cosmian/kms:5.1.0 \
//   --database-type redis-findex \
//   --database-url redis://127.0.0.1:6379 \
//   --redis-master-password password \
//   --redis-findex-label label --clear-database
// ```
// - create two sym keys (SHAKE), call them `mt_should_not_exist` and `mt_exists`, tag them with "cat"
// ```bash
// # assuming on cli repository root, with the cli binary built
// ./target/debug/cosmian kms sym keys create mt_should_not_exist -a shake -t cat
// ./target/debug/cosmian kms sym keys create mt_exists -a shake -t cat
// ```
// - grant `Locate` permission on both keys to user `mt_owner`
// - revoke mt_should_not_exist key with NA as revocation reason. **Use the UI for this operation to avoid CLI bugs**
// - destroy mt_should_not_exist, **tick Remove completely from database**
// The redis database is now ready, dump it using the utility function `dump_all`
#[allow(deprecated)]
async fn from_5_1_0_to_5_12_0() -> KResult<()> {
    log_init_colorized(option_env!("RUST_LOG"));
    let dump_file = open_file(TEST_DATA_PATH, "redis_dump_v5_1_0.bin");

    let owner = "mt_owner";
    let redis_url = get_redis_url();
    let client = redis::Client::open(redis_url.clone()).unwrap();
    let mgr = ConnectionManager::new(client).await.unwrap();

    // flush the redis and insert the data from a redis dump made with a 5.2.0 version of the KMS
    redis::cmd("FLUSHALL")
        .query_async::<()>(&mut mgr.clone())
        .await
        .unwrap();

    restore_db_from_dump(mgr, dump_file).await?;

    // we start a fresh KMS, it finds the data in redis, and migrates it
    let mut clap_config = https_clap_config();
    clap_config.db = MainDBConfig {
        database_type: Some("redis-findex".to_owned()),
        database_url: Some(redis_url),
        redis_master_password: Some("password".to_owned()),
        clear_database: false,
        ..Default::default()
    };
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // assert the deletion/revocation worked as expected
    let locate_response = kms
        .locate(
            Locate {
                attributes: Attributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(
                        "mt_should_not_exist".to_owned(),
                    )),
                    ..Attributes::default()
                },
                ..Locate::default()
            },
            owner,
        )
        .await?;
    assert_eq!(locate_response.located_items.unwrap(), 0);

    // since all keys had the "cat" tag, so we should find 1 key
    let mut search_attrs = Attributes::default();
    let _: () = search_attrs.set_tags(vec!["cat".to_owned()])?;
    let locate_response = kms
        .locate(
            Locate {
                attributes: search_attrs.clone(),
                ..Locate::default()
            },
            owner,
        )
        .await?;
    assert_eq!(locate_response.located_items.unwrap(), 1);

    // the owner can only locate keys, nothing else
    let revoke_response = kms
        .revoke(
            Revoke {
                unique_identifier: Some(UniqueIdentifier::from("mt_exists".to_owned())),
                revocation_reason: RevocationReason {
                    revocation_message: Some("Test".to_owned()),
                    revocation_reason_code: RevocationReasonCode::Unspecified,
                },
                compromise_occurrence_date: None,
                cascade: true,
            },
            owner,
        )
        .await;
    revoke_response.unwrap_err();

    Ok(())
}

// If those tests are run in parallel, they will trigger redis errors;
// for some reason, the #[serial] attribute from serial_test crate does
// not solve the problem, hence this function.
#[ignore = "Requires a running Redis instance"]
#[allow(clippy::large_futures)]
#[tokio::test]
#[cfg(not(any(target_os = "windows", target_os = "macos")))] // no redis on those CI machines
async fn findex_redis_migration_tests() -> KResult<()> {
    log_init_colorized(option_env!("RUST_LOG"));
    // let _: () = from_5_1_0_to_5_12_0().await?;
    let _: () = from_5_2_0_to_5_12_0().await?;
    trace!("Both migration tests completed successfully");
    Ok(())
}
