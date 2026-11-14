use std::path::Path;

use cosmian_logger::{log_init, reexport::tracing};
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
    issue_940_repro::test_issue_940, test_active_key_count_counter,
    test_certificate_serial_tag_backfill, test_corner_case, test_live_count_counter,
    test_migration_state_markers, test_objects_db, test_permissions_db, test_wrapped_by_backfill,
};
use crate::{
    error::{DbError, DbResult},
    stores::{MySqlPool, PgPool, SqlitePool},
    tests::{
        database_tests::{
            atomic, block_cipher_mode_migration_after_json_deserialization,
            count_non_destroyed_keys_test, create_duplicate_uid_test, find_due_for_rotation_test,
            find_with_options_test, update_if_version_test, wrapping_key_link_test,
        },
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
    use cosmian_kms_crypto::{crypto::KmsRng, reexport::cosmian_crypto_core::Secret};

    use crate::stores::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;
    let mut rng = KmsRng::new().seeded_csrng()?;

    let redis_url = get_redis_url();
    let redis_url = option_env!("KMS_REDIS_URL").unwrap_or(&redis_url);
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
    let redis_findex = RedisWithFindex::instantiate(redis_url, master_key, true).await?;
    Ok(redis_findex)
}

#[ignore = "Requires a running Redis instance"]
#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_db_redis_with_findex() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    test_objects_db().await?;
    test_permissions_db().await?;
    test_corner_case().await?;
    test_live_count_counter().await?;
    test_active_key_count_counter().await?;
    test_wrapped_by_backfill().await?;
    test_certificate_serial_tag_backfill().await?;
    Box::pin(test_issue_940()).await?;
    test_migration_state_markers().await?;
    Box::pin(json_access(&get_redis_with_findex().await?)).await?;
    find_attributes(&get_redis_with_findex().await?).await?;
    owner(&get_redis_with_findex().await?).await?;
    permissions(&get_redis_with_findex().await?).await?;
    Box::pin(tags(&get_redis_with_findex().await?, false)).await?;
    tx_and_list(&get_redis_with_findex().await?).await?;
    Box::pin(atomic(&get_redis_with_findex().await?)).await?;
    upsert(&get_redis_with_findex().await?).await?;
    crud(&get_redis_with_findex().await?).await?;
    list_uids_for_tags_test(&get_redis_with_findex().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_redis_with_findex().await?).await?;
    find_due_for_rotation_test(&get_redis_with_findex().await?).await?;
    Box::pin(wrapping_key_link_test(&get_redis_with_findex().await?)).await?;
    Box::pin(update_if_version_test(&get_redis_with_findex().await?)).await?;
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
    Box::pin(atomic(&get_sqlite(&db_file).await?)).await?;
    upsert(&get_sqlite(&db_file).await?).await?;
    crud(&get_sqlite(&db_file).await?).await?;
    create_duplicate_uid_test(&get_sqlite(&db_file).await?).await?;
    list_uids_for_tags_test(&get_sqlite(&db_file).await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_sqlite(&db_file).await?).await?;
    find_due_for_rotation_test(&get_sqlite(&db_file).await?).await?;
    count_non_destroyed_keys_test(&get_sqlite(&db_file).await?).await?;
    find_with_options_test(&get_sqlite(&db_file).await?).await?;
    Box::pin(wrapping_key_link_test(&get_sqlite(&db_file).await?)).await?;
    Box::pin(update_if_version_test(&get_sqlite(&db_file).await?)).await?;
    Ok(())
}

/// Faithful migration test: build a **legacy** `SQLite` database whose `objects`
/// table predates the `wrapping_key_id` column, insert a wrapped object row by
/// hand, then open it with the current [`SqlitePool`]. Opening must add the
/// column, create its index and backfill the wrapping-key link so the object
/// becomes discoverable through `find_wrapped_by`.
#[tokio::test]
async fn test_sqlite_wrapping_key_id_backfill_migration() -> DbResult<()> {
    use std::collections::HashSet;

    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes, kmip_objects::Object, kmip_types::CryptographicAlgorithm,
        },
    };
    use cosmian_kms_interfaces::{ObjectsStore, UserId};
    use uuid::Uuid;

    log_init(Some("info"));
    let dir = TempDir::new()?;
    let db_file = dir.path().join("legacy_sqlite.db");

    let owner = "legacy_owner";
    let wrapping_key_uid = "legacy_wrapping_key";
    let wrapped_uid = Uuid::new_v4().to_string();

    // Serialize a wrapped object exactly as the database stores it.
    let wrapped_obj: Object = serde_json::from_value(serde_json::json!({
        "SymmetricKey": {
            "KeyBlock": {
                "KeyFormatType": "TransparentSymmetricKey",
                "CryptographicAlgorithm": "AES",
                "CryptographicLength": 256,
                "KeyWrappingData": {
                    "WrappingMethod": "Encrypt",
                    "EncryptionKeyInformation": { "UniqueIdentifier": wrapping_key_uid },
                    "EncodingOption": "TTLVEncoding"
                }
            }
        }
    }))
    .map_err(|e| DbError::ServerError(format!("failed to build wrapped object: {e}")))?;
    let object_json =
        serde_json::to_string(&wrapped_obj).map_err(|e| DbError::ServerError(e.to_string()))?;
    let attributes_json = serde_json::to_string(&Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        ..Default::default()
    })
    .map_err(|e| DbError::ServerError(e.to_string()))?;

    // ── Create a legacy-schema database (objects table WITHOUT wrapping_key_id) ──
    {
        let conn = rusqlite::Connection::open(&db_file)
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE objects (
                 id VARCHAR(128) PRIMARY KEY,
                 object VARCHAR NOT NULL,
                 attributes jsonb NOT NULL,
                 state VARCHAR(32),
                 owner VARCHAR(255)
             );",
        )
        .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        conn.execute(
            "INSERT INTO objects (id, object, attributes, state, owner) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![wrapped_uid, object_json, attributes_json, "Active", owner],
        )
        .map_err(|e| DbError::DatabaseError(e.to_string()))?;
    } // raw connection is dropped/closed here

    // ── Open with the current backend → triggers the column add + backfill ──
    let pool = SqlitePool::instantiate(&db_file, false, None).await?;

    // The pre-existing wrapped object must now be discoverable by its wrapping key.
    let found = pool
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    let found_uids: HashSet<&str> = found.iter().map(|(uid, _, _)| uid.as_str()).collect();
    if !found_uids.contains(wrapped_uid.as_str()) {
        return Err(DbError::ServerError(format!(
            "backfill migration: wrapped object '{wrapped_uid}' should be discoverable via \
             find_wrapped_by after migration, got: {found_uids:?}"
        )));
    }

    // Re-opening must be a no-op (marker set): the object stays discoverable.
    let pool2 = SqlitePool::instantiate(&db_file, false, None).await?;
    let found2 = pool2
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    if found2.iter().all(|(uid, _, _)| uid != &wrapped_uid) {
        return Err(DbError::ServerError(
            "backfill migration: wrapped object lost after re-opening the database".to_owned(),
        ));
    }

    Ok(())
}

/// A certificate object with serial `0ABBCC` (hex).
pub(crate) fn legacy_certificate_object() -> cosmian_kmip::kmip_2_1::kmip_objects::Object {
    use cosmian_kmip::{
        kmip_0::kmip_types::CertificateType,
        kmip_2_1::kmip_objects::{Certificate, Object},
    };
    use openssl::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::X509Builder,
    };

    let mut builder = X509Builder::new().unwrap();
    let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_slice(&[0x0A, 0xBB, 0xCC]).unwrap()).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    Object::Certificate(Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: builder.build().to_der().unwrap(),
    })
}

/// A certificate stored before the `_serial=<HEX>` tag existed (it only carries `_cert`) gets
/// the tag when the database is re-opened; the marker is recorded.
#[tokio::test]
async fn test_sqlite_certificate_serial_tag_backfill() -> DbResult<()> {
    use cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
    use cosmian_kms_interfaces::ObjectsStore;

    const CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM: &str = "certificate_serial_tag_backfilled";

    log_init(Some("info"));
    let dir = TempDir::new()?;
    let db_file = dir.path().join("serial_tag_sqlite.db");
    let db_err = |e: rusqlite::Error| DbError::DatabaseError(e.to_string());

    let object = legacy_certificate_object();
    let object_json =
        serde_json::to_string(&object).map_err(|e| DbError::ServerError(e.to_string()))?;
    let attributes_json = serde_json::to_string(&Attributes::default())
        .map_err(|e| DbError::ServerError(e.to_string()))?;

    // Create the schema, then drop the pool
    drop(SqlitePool::instantiate(&db_file, true, None).await?);
    // Seed a legacy certificate (`_cert` tag only) and clear the completion marker
    {
        let conn = rusqlite::Connection::open(&db_file).map_err(db_err)?;
        conn.execute(
            "INSERT INTO objects (id, object, attributes, state, owner) \
             VALUES ('legacy_cert', ?1, ?2, 'Active', 'legacy_owner')",
            rusqlite::params![object_json, attributes_json],
        )
        .map_err(db_err)?;
        conn.execute(
            "INSERT INTO tags (id, tag) VALUES ('legacy_cert', '_cert')",
            [],
        )
        .map_err(db_err)?;
        conn.execute(
            "DELETE FROM parameters WHERE name = ?1",
            [CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM],
        )
        .map_err(db_err)?;
    }

    let pool = SqlitePool::instantiate(&db_file, false, None).await?;
    let tags = pool.retrieve_tags("legacy_cert").await?;
    let expected: std::collections::HashSet<String> =
        ["_cert".to_owned(), "_serial=0ABBCC".to_owned()].into();
    if tags != expected {
        return Err(DbError::ServerError(format!(
            "the backfill must add the serial tag, keeping the existing tags; got {tags:?}"
        )));
    }
    drop(pool);

    let conn = rusqlite::Connection::open(&db_file).map_err(db_err)?;
    let marker: String = conn
        .query_row(
            "SELECT value FROM parameters WHERE name = ?1",
            [CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    if marker != "true" {
        return Err(DbError::ServerError(format!(
            "serial tag backfill marker should be 'true', got '{marker}'"
        )));
    }
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
    Box::pin(atomic(&get_pgsql().await?)).await?;
    upsert(&get_pgsql().await?).await?;
    crud(&get_pgsql().await?).await?;
    list_uids_for_tags_test(&get_pgsql().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_pgsql().await?).await?;
    find_due_for_rotation_test(&get_pgsql().await?).await?;
    count_non_destroyed_keys_test(&get_pgsql().await?).await?;
    find_with_options_test(&get_pgsql().await?).await?;
    Box::pin(wrapping_key_link_test(&get_pgsql().await?)).await?;
    Box::pin(update_if_version_test(&get_pgsql().await?)).await?;
    Ok(())
}

// Multi-host PostgreSQL tests — require two running PostgreSQL instances:
//   Port 5432: docker run --name pg1 -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432 -d postgres
//   Port 5433: docker run --name pg2 -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5433:5432 -d postgres
async fn get_pgsql_multihost() -> DbResult<PgPool> {
    let url = option_env!("KMS_POSTGRES_MULTIHOST_URL").unwrap_or(
        "postgresql://kms:kms@127.0.0.1:5432,127.0.0.1:5433/kms?target_session_attrs=read-write",
    );
    PgPool::instantiate(url, true, None).await
}

#[ignore = "Requires two running PostgreSQL instances on ports 5432 and 5433. \
             Must not run concurrently with test_db_postgresql (shared DB on port 5432)."]
#[tokio::test]
pub(crate) async fn test_db_postgresql_multihost() -> DbResult<()> {
    log_init(option_env!("RUST_LOG"));
    // Verify that a multi-host connection string with target_session_attrs works
    let pg = get_pgsql_multihost().await?;
    crud(&pg).await?;
    Box::pin(atomic(&pg)).await?;
    upsert(&pg).await?;
    Ok(())
}

/// What a Destroy leaves behind: the same object with empty key material.
fn zeroized_copy(
    object: &cosmian_kmip::kmip_2_1::kmip_objects::Object,
) -> DbResult<cosmian_kmip::kmip_2_1::kmip_objects::Object> {
    use cosmian_kmip::kmip_2_1::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_types::KeyFormatType,
    };
    let mut zeroized = object.clone();
    let key_block = zeroized
        .key_block_mut()
        .map_err(|e| DbError::DatabaseError(e.to_string()))?;
    key_block.key_format_type = KeyFormatType::Raw;
    key_block.key_value = Some(KeyValue::Structure {
        key_material: KeyMaterial::ByteString(zeroize::Zeroizing::from(vec![])),
        attributes: None,
    });
    Ok(zeroized)
}

#[ignore = "Requires a running PostgreSQL instance"]
#[tokio::test]
pub(crate) async fn test_db_postgresql_state_event_merge() -> DbResult<()> {
    use std::collections::HashSet;

    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
            kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
        },
    };
    use cosmian_kms_interfaces::{ObjectsStore, UserId};
    use uuid::Uuid;

    log_init(option_env!("RUST_LOG"));
    let pg = get_pgsql().await?;
    let owner = UserId::from("state_merge_test_user");
    let key_obj = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[0_u8; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )
    .map_err(|e| DbError::DatabaseError(e.to_string()))?;
    let key_json = serde_json::to_string(&key_obj)?;
    let zeroized_json = serde_json::to_string(&zeroized_copy(&key_obj)?)?;
    let attrs = Attributes::default();

    let new_object = || async {
        pg.create(None, &owner, &key_obj, &attrs, &HashSet::new())
            .await
    };
    let expect_state = |label: &str, got: Option<State>, want: State| {
        if got == Some(want) {
            Ok(())
        } else {
            Err(DbError::ServerError(format!(
                "{label}: expected {want:?}, got {got:?}"
            )))
        }
    };
    let state_of = |uid: String| {
        let pg = &pg;
        async move { state_on(pg, &uid).await }
    };
    let stored_json = |uid: String| {
        let pg = &pg;
        async move {
            let owm = pg
                .retrieve(&uid)
                .await?
                .ok_or_else(|| DbError::ServerError(format!("{uid}: object missing")))?;
            Ok::<_, DbError>(serde_json::to_string(owm.object())?)
        }
    };
    // Simulates a lifecycle event arriving through logical replication.
    let replica_event = |uid: String, state: &'static str, object: Option<String>| {
        let pg = &pg;
        async move {
            let client = pg.raw_pool().get().await.map_err(DbError::from)?;
            client
                .batch_execute("SET session_replication_role = 'replica';")
                .await
                .map_err(DbError::from)?;
            let inserted = client
                .execute(
                    "INSERT INTO object_state_events (event_id, object_id, state, object, \
                     wrapping_key_id) VALUES (gen_random_uuid(), $1, $2, $3, NULL)",
                    &[&uid, &state, &object],
                )
                .await;
            client
                .batch_execute("SET session_replication_role = 'origin';")
                .await
                .map_err(DbError::from)?;
            inserted.map_err(DbError::from)?;
            Ok::<_, DbError>(())
        }
    };

    // a) a replicated Destroyed event wins over a local Deactivated.
    let uid = new_object().await?;
    pg.update_state(&uid, State::Deactivated).await?;
    replica_event(uid.clone(), "Destroyed", None).await?;
    expect_state("a", state_of(uid).await?, State::Destroyed)?;

    // b) Compromised joined with Destroyed is Destroyed_Compromised, and stays so.
    let uid = new_object().await?;
    pg.update_state(&uid, State::Compromised).await?;
    pg.update_state(&uid, State::Destroyed).await?;
    expect_state(
        "b",
        state_of(uid.clone()).await?,
        State::Destroyed_Compromised,
    )?;
    pg.update_state(&uid, State::Active).await?;
    expect_state("b2", state_of(uid).await?, State::Destroyed_Compromised)?;

    // c) an explicit downgrade replaces the observed state.
    let uid = new_object().await?;
    pg.update_state(&uid, State::Active).await?;
    pg.update_state_allow_downgrade(&uid, State::PreActive)
        .await?;
    expect_state("c", state_of(uid.clone()).await?, State::PreActive)?;

    // d) a replicated Destroyed event carries its zeroized payload onto the row.
    replica_event(uid.clone(), "Destroyed", Some(zeroized_json.clone())).await?;
    expect_state("d", state_of(uid.clone()).await?, State::Destroyed)?;
    if stored_json(uid.clone()).await? != zeroized_json {
        return Err(DbError::ServerError("d: payload not zeroized".to_owned()));
    }

    // e) a later payload write cannot bring the key material back.
    pg.update_object(&uid, &key_obj, &attrs, None).await?;
    if stored_json(uid.clone()).await? != zeroized_json {
        return Err(DbError::ServerError("e: key material survived".to_owned()));
    }

    // f) Batch Undo order: reset the state, then restore the payload.
    pg.update_state_allow_downgrade(&uid, State::Active).await?;
    pg.update_object(&uid, &key_obj, &attrs, None).await?;
    expect_state("f", state_of(uid.clone()).await?, State::Active)?;
    if stored_json(uid).await? != key_json {
        return Err(DbError::ServerError("f: payload not restored".to_owned()));
    }

    // g) backfill: an object without events gets exactly one, and the marker is set.
    let uid = Uuid::new_v4().to_string();
    let url = option_env!("KMS_POSTGRES_URL").unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms");
    {
        let client = pg.raw_pool().get().await.map_err(DbError::from)?;
        client
            .execute(
                "INSERT INTO objects (id, object, attributes, state, owner) \
                 VALUES ($1, $2, '{}'::jsonb, 'Active', 'backfill_owner')",
                &[&uid, &key_json],
            )
            .await
            .map_err(DbError::from)?;
        client
            .execute(
                "DELETE FROM parameters WHERE name = $1",
                &[&"object_state_events_backfilled"],
            )
            .await
            .map_err(DbError::from)?;
    }
    let pg_again = PgPool::instantiate(url, false, None).await?;
    let client = pg_again.raw_pool().get().await.map_err(DbError::from)?;
    let events: i64 = client
        .query_one(
            "SELECT count(*) FROM object_state_events WHERE object_id = $1",
            &[&uid],
        )
        .await
        .map_err(DbError::from)?
        .get(0);
    let marker: String = client
        .query_one(
            "SELECT value FROM parameters WHERE name = $1",
            &[&"object_state_events_backfilled"],
        )
        .await
        .map_err(DbError::from)?
        .get(0);
    if events != 1 || marker != "true" {
        return Err(DbError::ServerError(format!(
            "g: expected 1 event and marker true, got {events} and {marker}"
        )));
    }

    Ok(())
}

/// `PostgreSQL` failover retry test.
///
/// Verifies that when one node in a multi-host `PostgreSQL` cluster goes down, the
/// `pg_retry!` and `pg_retry_tx!` macros detect the connection-level error,
/// **discard** the stale pool connection, and successfully complete the operation
/// via the surviving node.
///
/// # Setup
/// This test is orchestrated by the MISE task `test:db:psql`.  Run it with:
/// ```bash
/// mise run test:db:psql
/// ```
/// The MISE task starts the `pg-failover` Docker Compose profile (containers
/// **pg1** on port 5434 and **pg2** on port 5435), then coordinates the pg1
/// stop/restart via two signal files whose paths it exports as:
/// - `KMS_PG_FAILOVER_READY_FILE` — the test writes this when the pool is warm
/// - `KMS_PG_FAILOVER_STOP_FILE`  — the MISE task writes this after stopping pg1
///
/// If neither env var is set the test returns `Ok(())` immediately (silently
/// skipped when running under `check_and_test_db`).
///
/// # How the test works
/// 1. Initialises the schema on both nodes independently (simulates streaming
///    replication in a real HA setup).
/// 2. Opens a dual-host pool and runs `crud()` while both nodes are up.
/// 3. Signals readiness → waits for the external stop signal.
/// 4. Re-runs `crud()` + `tx_and_list()` through the same pool.  The pool
///    holds stale connections to pg1; the retry macros must detect the IO error,
///    discard the stale connections, and reconnect to pg2.
/// 5. Asserts success within a reasonable elapsed time.
///
/// The test uses `target_session_attrs=any` so two completely independent
/// (non-replicated) `PostgreSQL` instances satisfy the connection requirements.
#[ignore = "Orchestrated by `mise run test:db:psql` (requires the pg-failover \
             Docker Compose profile and the KMS_PG_FAILOVER_* signal-file env vars)."]
#[tokio::test]
pub(crate) async fn test_db_postgresql_failover() -> DbResult<()> {
    log_init(Some("warn,cosmian_kms_server_database=warn"));

    // ── Guard: skip unless orchestrated by the MISE task ─────────────────────
    // The MISE psql task sets KMS_PG_FAILOVER_READY_FILE before running this
    // test.  When absent (e.g. called by check_and_test_db with only the
    // standard test_db_postgresql filter), we return Ok to avoid hanging.
    let ready_file = {
        let Ok(p) = std::env::var("KMS_PG_FAILOVER_READY_FILE") else {
            tracing::info!(
                "test_db_postgresql_failover: KMS_PG_FAILOVER_READY_FILE not set — skipped"
            );
            return Ok(());
        };
        p
    };
    let stop_file = std::env::var("KMS_PG_FAILOVER_STOP_FILE")
        .map_err(|e| DbError::ServerError(format!("KMS_PG_FAILOVER_STOP_FILE must be set: {e}")))?;

    // ── URL configuration ─────────────────────────────────────────────────────
    // Default ports match the docker-compose pg-failover profile (5434/5435).
    let pg1_url = option_env!("KMS_PG_FAILOVER_PRIMARY_URL")
        .unwrap_or("postgresql://kms:kms@127.0.0.1:5434/kms");
    let pg2_url = option_env!("KMS_PG_FAILOVER_SECONDARY_URL")
        .unwrap_or("postgresql://kms:kms@127.0.0.1:5435/kms");
    let multihost_url = option_env!("KMS_PG_FAILOVER_MULTIHOST_URL").unwrap_or(
        "postgresql://kms:kms@127.0.0.1:5434,127.0.0.1:5435/kms?target_session_attrs=any",
    );

    // ── Schema initialisation ─────────────────────────────────────────────────
    // pg1 (port 5434) — will be stopped to simulate a primary failure.
    PgPool::instantiate(pg1_url, true, None).await?;
    // pg2 (port 5435) — the surviving node the pool must fail over to.
    PgPool::instantiate(pg2_url, true, None).await?;

    // ── Pool setup ────────────────────────────────────────────────────────────
    let pg = PgPool::instantiate(multihost_url, false, None).await?;

    // ── Baseline: both nodes up ───────────────────────────────────────────────
    // Warm up the pool: creates a connection to pg1 (first host in the URL).
    crud(&pg).await?;

    // ── Signal readiness to the MISE orchestrator ─────────────────────────────
    std::fs::write(&ready_file, b"")
        .map_err(|e| DbError::ServerError(format!("write ready-file {ready_file}: {e}")))?;

    // ── Wait for the MISE orchestrator to stop pg1 ────────────────────────────
    // The orchestrator runs `docker stop pg1` then writes to stop_file.
    // We poll using spawn_blocking to avoid blocking the async runtime.
    let stop_file_clone = stop_file.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !Path::new(&stop_file_clone).exists() {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timed out (60s) waiting for stop signal at {stop_file_clone}"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    })
    .await
    .map_err(|e| DbError::ServerError(format!("spawn_blocking join: {e}")))?
    .map_err(DbError::ServerError)?;

    // No grace period: RecyclingMethod::Verified detects dead connections during
    // pool.get() itself (via simple_query("")) — no sleep needed before the
    // failover operations.

    // ── Failover: operations MUST succeed via pg2 ─────────────────────────────
    let before = std::time::Instant::now();

    // create() → pg_retry_tx! (transactional retry path)
    crud(&pg).await?;
    // retrieve() / find() → pg_retry! (non-transactional retry path)
    Box::pin(tx_and_list(&pg)).await?;

    let elapsed = before.elapsed();

    // ── Assertions ────────────────────────────────────────────────────────────
    if elapsed >= std::time::Duration::from_secs(5) {
        return Err(DbError::ServerError(format!(
            "Expected failover to complete within 5s but took {elapsed:?}"
        )));
    }

    Ok(())
}

/// Enable or disable both Spock subscriptions of the two-node test cluster.
async fn set_replication(pg1: &PgPool, pg2: &PgPool, enabled: bool) -> DbResult<()> {
    let func = if enabled { "sub_enable" } else { "sub_disable" };
    for (pg, sub) in [(pg1, "sub_n1_n2"), (pg2, "sub_n2_n1")] {
        let client = pg.raw_pool().get().await.map_err(DbError::from)?;
        client
            .batch_execute(&format!("SELECT spock.{func}('{sub}', true);"))
            .await
            .map_err(DbError::from)?;
    }
    Ok(())
}

/// Block until everything committed so far on each node has been applied on the other.
async fn sync_both(pg1: &PgPool, pg2: &PgPool) -> DbResult<()> {
    for (provider, subscriber, origin) in [(pg1, pg2, "n1"), (pg2, pg1, "n2")] {
        let lsn: String = provider
            .raw_pool()
            .get()
            .await
            .map_err(DbError::from)?
            .query_one("SELECT spock.sync_event()::text;", &[])
            .await
            .map_err(DbError::from)?
            .get(0);
        let applied: bool = subscriber
            .raw_pool()
            .get()
            .await
            .map_err(DbError::from)?
            .query_one(
                "CALL spock.wait_for_sync_event(NULL, $1::name, $2::text::pg_lsn, 60);",
                &[&origin, &lsn],
            )
            .await
            .map_err(DbError::from)?
            .get("result");
        if !applied {
            return Err(DbError::ServerError(format!(
                "replication from {origin} did not apply sync event {lsn} within 60s"
            )));
        }
    }
    Ok(())
}

async fn state_on(
    pg: &PgPool,
    uid: &str,
) -> DbResult<Option<cosmian_kmip::kmip_0::kmip_types::State>> {
    use cosmian_kms_interfaces::ObjectsStore;
    Ok(pg.retrieve_state(uid).await?.map(|(state, _)| state))
}

#[ignore = "Orchestrated by `mise run test:db:pgedge` (requires the pgedge Docker Compose profile)."]
#[tokio::test]
pub(crate) async fn test_db_pgedge_active_active() -> DbResult<()> {
    use std::collections::HashSet;

    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation, extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
            kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
        },
    };
    use cosmian_kms_interfaces::{AtomicOperation, ObjectsStore, PermissionsStore, UserId};
    use uuid::Uuid;

    log_init(option_env!("RUST_LOG"));

    let url1 = std::env::var("KMS_PGEDGE_1_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6432/kms".to_owned());
    let url2 = std::env::var("KMS_PGEDGE_2_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6433/kms".to_owned());

    // Instantiate PgPool on both nodes: creates KMS schema, PK migrations, and monotonic trigger
    let pg1 = PgPool::instantiate(&url1, true, None).await?;
    let pg2 = PgPool::instantiate(&url2, true, None).await?;

    // Wire Spock logical multi-master replication on both nodes (idempotent setup)
    {
        let c1 = pg1.raw_pool().get().await.map_err(DbError::from)?;
        c1.batch_execute("CREATE EXTENSION IF NOT EXISTS spock;")
            .await
            .map_err(DbError::from)?;
        let n1_exists: bool = c1
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.node WHERE node_name = 'n1');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !n1_exists {
            c1.batch_execute(
                "SELECT spock.node_create(node_name := 'n1', dsn := 'host=pgedge1 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c1.batch_execute("SELECT spock.repset_add_all_tables('default', ARRAY['public']);")
            .await
            .map_err(DbError::from)?;
    }

    {
        let c2 = pg2.raw_pool().get().await.map_err(DbError::from)?;
        c2.batch_execute("CREATE EXTENSION IF NOT EXISTS spock;")
            .await
            .map_err(DbError::from)?;
        let n2_exists: bool = c2
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.node WHERE node_name = 'n2');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !n2_exists {
            c2.batch_execute(
                "SELECT spock.node_create(node_name := 'n2', dsn := 'host=pgedge2 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c2.batch_execute("SELECT spock.repset_add_all_tables('default', ARRAY['public']);")
            .await
            .map_err(DbError::from)?;
    }

    // Create subscriptions and wait for initial sync
    {
        let c1 = pg1.raw_pool().get().await.map_err(DbError::from)?;
        let sub1_exists: bool = c1
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.subscription WHERE sub_name = 'sub_n1_n2');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !sub1_exists {
            c1.batch_execute(
                "SELECT spock.sub_create(subscription_name := 'sub_n1_n2', provider_dsn := 'host=pgedge2 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c1.batch_execute("SELECT spock.sub_wait_for_sync('sub_n1_n2');")
            .await
            .map_err(DbError::from)?;
    }

    {
        let c2 = pg2.raw_pool().get().await.map_err(DbError::from)?;
        let sub2_exists: bool = c2
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM spock.subscription WHERE sub_name = 'sub_n2_n1');",
                &[],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !sub2_exists {
            c2.batch_execute(
                "SELECT spock.sub_create(subscription_name := 'sub_n2_n1', provider_dsn := 'host=pgedge1 port=5432 dbname=kms user=kms password=kms');",
            )
            .await
            .map_err(DbError::from)?;
        }
        c2.batch_execute("SELECT spock.sub_wait_for_sync('sub_n2_n1');")
            .await
            .map_err(DbError::from)?;
    }

    // Prepare test objects
    let owner = UserId::from("pgedge_test_user");
    let key_obj = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[0_u8; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )
    .map_err(|e| DbError::DatabaseError(e.to_string()))?;
    let zeroized_object = zeroized_copy(&key_obj)?;
    let attrs = Attributes::default();

    // Creates an object on pg1 (optionally `Active`) and waits until both nodes have it.
    let new_object = |active: bool| {
        let (pg1, pg2, owner, key_obj) = (&pg1, &pg2, &owner, &key_obj);
        async move {
            let uid = Uuid::new_v4().to_string();
            pg1.atomic(
                owner,
                &[AtomicOperation::Create((
                    uid.clone(),
                    owner.clone(),
                    key_obj.clone(),
                    Attributes::default(),
                    HashSet::new(),
                ))],
            )
            .await?;
            if active {
                pg1.update_state(&uid, State::Active).await?;
            }
            sync_both(pg1, pg2).await?;
            Ok::<_, DbError>(uid)
        }
    };
    let expect = |label: &str, got: Option<State>, want: State| {
        if got == Some(want) {
            Ok(())
        } else {
            Err(DbError::ServerError(format!(
                "{label}: expected {want:?}, got {got:?}"
            )))
        }
    };

    // S1: pg1 Destroyed vs pg2 Deactivated.
    let uid = new_object(false).await?;
    set_replication(&pg1, &pg2, false).await?;
    pg1.update_state(&uid, State::Destroyed).await?;
    pg2.update_state(&uid, State::Deactivated).await?;
    expect(
        "S1 isolated pg1",
        state_on(&pg1, &uid).await?,
        State::Destroyed,
    )?;
    expect(
        "S1 isolated pg2",
        state_on(&pg2, &uid).await?,
        State::Deactivated,
    )?;
    set_replication(&pg1, &pg2, true).await?;
    sync_both(&pg1, &pg2).await?;
    expect("S1 pg1", state_on(&pg1, &uid).await?, State::Destroyed)?;
    expect("S1 pg2", state_on(&pg2, &uid).await?, State::Destroyed)?;

    // S2: pg2 Destroyed vs pg1 Deactivated (the later commit is the lower state).
    let uid = new_object(false).await?;
    set_replication(&pg1, &pg2, false).await?;
    pg2.update_state(&uid, State::Destroyed).await?;
    pg1.update_state(&uid, State::Deactivated).await?;
    expect(
        "S2 isolated pg1",
        state_on(&pg1, &uid).await?,
        State::Deactivated,
    )?;
    expect(
        "S2 isolated pg2",
        state_on(&pg2, &uid).await?,
        State::Destroyed,
    )?;
    set_replication(&pg1, &pg2, true).await?;
    sync_both(&pg1, &pg2).await?;
    expect("S2 pg1", state_on(&pg1, &uid).await?, State::Destroyed)?;
    expect("S2 pg2", state_on(&pg2, &uid).await?, State::Destroyed)?;

    // S3: Compromised on one node, Destroyed on the other.
    let uid = new_object(false).await?;
    set_replication(&pg1, &pg2, false).await?;
    pg1.update_state(&uid, State::Compromised).await?;
    pg2.update_state(&uid, State::Destroyed).await?;
    expect(
        "S3 isolated pg1",
        state_on(&pg1, &uid).await?,
        State::Compromised,
    )?;
    expect(
        "S3 isolated pg2",
        state_on(&pg2, &uid).await?,
        State::Destroyed,
    )?;
    set_replication(&pg1, &pg2, true).await?;
    sync_both(&pg1, &pg2).await?;
    expect(
        "S3 pg1",
        state_on(&pg1, &uid).await?,
        State::Destroyed_Compromised,
    )?;
    expect(
        "S3 pg2",
        state_on(&pg2, &uid).await?,
        State::Destroyed_Compromised,
    )?;

    // S4: a concurrent payload write must not bring key material back on a Destroyed row.
    let uid = new_object(false).await?;
    set_replication(&pg1, &pg2, false).await?;
    pg1.atomic(
        &owner,
        &[
            AtomicOperation::UpdateObject((
                uid.clone(),
                zeroized_object.clone(),
                attrs.clone(),
                None,
            )),
            AtomicOperation::UpdateState((uid.clone(), State::Destroyed)),
        ],
    )
    .await?;
    pg2.update_object(&uid, &key_obj, &attrs, None).await?;
    expect(
        "S4 isolated pg1",
        state_on(&pg1, &uid).await?,
        State::Destroyed,
    )?;
    if state_on(&pg2, &uid).await? == Some(State::Destroyed) {
        return Err(DbError::ServerError(
            "S4: partition did not hold".to_owned(),
        ));
    }
    set_replication(&pg1, &pg2, true).await?;
    sync_both(&pg1, &pg2).await?;
    let zeroized_json = serde_json::to_string(&zeroized_object)?;
    for (name, pg) in [("pg1", &pg1), ("pg2", &pg2)] {
        expect(
            &format!("S4 {name}"),
            state_on(pg, &uid).await?,
            State::Destroyed,
        )?;
        let stored = pg
            .retrieve(&uid)
            .await?
            .ok_or_else(|| DbError::ServerError(format!("S4 {name}: object missing")))?;
        if serde_json::to_string(stored.object())? != zeroized_json {
            return Err(DbError::ServerError(format!(
                "S4 {name}: key material survived Destroy"
            )));
        }
    }

    // S5: a downgrade removes only the events its node observed.
    let uid = new_object(true).await?;
    set_replication(&pg1, &pg2, false).await?;
    pg1.update_state_allow_downgrade(&uid, State::PreActive)
        .await?;
    pg2.update_state(&uid, State::Destroyed).await?;
    expect(
        "S5 isolated pg1",
        state_on(&pg1, &uid).await?,
        State::PreActive,
    )?;
    expect(
        "S5 isolated pg2",
        state_on(&pg2, &uid).await?,
        State::Destroyed,
    )?;
    set_replication(&pg1, &pg2, true).await?;
    sync_both(&pg1, &pg2).await?;
    expect("S5 pg1", state_on(&pg1, &uid).await?, State::Destroyed)?;
    expect("S5 pg2", state_on(&pg2, &uid).await?, State::Destroyed)?;

    // S6: a downgrade replicates without concurrency.
    let uid = new_object(true).await?;
    pg1.update_state_allow_downgrade(&uid, State::PreActive)
        .await?;
    sync_both(&pg1, &pg2).await?;
    expect("S6 pg1", state_on(&pg1, &uid).await?, State::PreActive)?;
    expect("S6 pg2", state_on(&pg2, &uid).await?, State::PreActive)?;

    // Grants: whole-row last-update-wins is the accepted contract; the nodes must agree and
    // the row is either gone or holds both operations.
    let uid = new_object(false).await?;
    let alice = UserId::from("alice");
    pg1.grant_operations(&uid, &alice, HashSet::from([KmipOperation::Get]))
        .await?;
    sync_both(&pg1, &pg2).await?;
    set_replication(&pg1, &pg2, false).await?;
    pg2.remove_operations(&uid, &alice, HashSet::from([KmipOperation::Get]))
        .await?;
    pg1.grant_operations(&uid, &alice, HashSet::from([KmipOperation::Encrypt]))
        .await?;
    set_replication(&pg1, &pg2, true).await?;
    sync_both(&pg1, &pg2).await?;
    let perm1 = pg1
        .list_user_operations_on_object(&uid, &alice, false)
        .await?;
    let perm2 = pg2
        .list_user_operations_on_object(&uid, &alice, false)
        .await?;
    if perm1 != perm2
        || !(perm1.is_empty()
            || perm1 == HashSet::from([KmipOperation::Get, KmipOperation::Encrypt]))
    {
        return Err(DbError::ServerError(format!(
            "read_access did not converge: pg1={perm1:?}, pg2={perm2:?}"
        )));
    }

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
    Box::pin(atomic(&get_mysql().await?)).await?;
    upsert(&get_mysql().await?).await?;
    crud(&get_mysql().await?).await?;
    list_uids_for_tags_test(&get_mysql().await?).await?;
    find_with_options_test(&get_mysql().await?).await?;
    block_cipher_mode_migration_after_json_deserialization(&get_mysql().await?).await?;
    find_due_for_rotation_test(&get_mysql().await?).await?;
    count_non_destroyed_keys_test(&get_mysql().await?).await?;
    Box::pin(wrapping_key_link_test(&get_mysql().await?)).await?;
    Box::pin(update_if_version_test(&get_mysql().await?)).await?;
    Ok(())
}
