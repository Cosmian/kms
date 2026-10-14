//! Upgrade tests for the `objects.domain` column.
//!
//! Databases created before the RBAC `domain` attribute existed have no such column,
//! and `CREATE TABLE IF NOT EXISTS` leaves their `objects` table untouched. Every SQL
//! backend must therefore add the column itself when it opens an existing database.
//!
//! Each test stores an object, drops the column to recreate the previous schema,
//! re-opens the database and checks that the old row is still readable and that
//! objects can be stored with a domain. A second re-open checks idempotence.

use std::{collections::HashSet, path::Path};

use cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
    kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_interfaces::{ObjectsStore, UserId};
use cosmian_logger::reexport::tracing;
use mysql_async::prelude::Queryable;
use uuid::Uuid;

use crate::{
    error::{DbError, DbResult},
    stores::{MySqlPool, PgPool, SqlitePool},
};

const OWNER: &str = "domain_migration_owner";

/// Store a random AES key with the given `domain` and return its uid.
async fn store_key<DB: ObjectsStore>(db: &DB, domain: &str) -> DbResult<String> {
    let mut key_bytes = vec![0_u8; 32];
    CsRng::from_entropy().fill_bytes(&mut key_bytes);
    let key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        key_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let uid = Uuid::new_v4().to_string();
    db.create(
        Some(uid.clone()),
        &UserId::from(OWNER),
        &key,
        key.attributes()?,
        &HashSet::new(),
        domain,
    )
    .await?;
    Ok(uid)
}

/// Check a database that went through the upgrade: the object stored before it is still
/// readable (with an empty domain) and new objects keep the domain they are stored with.
async fn check_upgraded<DB: ObjectsStore>(db: &DB, legacy_uid: &str) -> DbResult<()> {
    let legacy = db.retrieve(legacy_uid).await?.ok_or_else(|| {
        DbError::ServerError(format!("object {legacy_uid} was lost by the upgrade"))
    })?;
    if !legacy.domain().is_empty() {
        return Err(DbError::ServerError(format!(
            "object stored before the upgrade should have an empty domain, got '{}'",
            legacy.domain()
        )));
    }

    let uid = store_key(db, "tenant_a").await?;
    let stamped = db
        .retrieve(&uid)
        .await?
        .ok_or_else(|| DbError::ServerError(format!("object {uid} not found after creation")))?;
    if stamped.domain() != "tenant_a" {
        return Err(DbError::ServerError(format!(
            "domain 'tenant_a' was not persisted, got '{}'",
            stamped.domain()
        )));
    }
    Ok(())
}

fn expect_domain_column(present: bool, expected: bool, step: &str) -> DbResult<()> {
    if present == expected {
        Ok(())
    } else {
        Err(DbError::ServerError(format!(
            "{step}: objects.domain column present = {present}, expected {expected}"
        )))
    }
}

fn sqlite_has_domain_column(conn: &rusqlite::Connection) -> DbResult<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('objects') WHERE name = 'domain'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| DbError::DatabaseError(e.to_string()))?;
    Ok(count > 0)
}

/// `SQLite`: drop `objects.domain`, re-open the database file and check the upgrade.
pub(super) async fn sqlite_domain_column_upgrade(db_file: &Path) -> DbResult<()> {
    let legacy_uid = store_key(&SqlitePool::instantiate(db_file, true, None).await?, "").await?;

    {
        let conn = rusqlite::Connection::open(db_file)
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        conn.execute_batch("ALTER TABLE objects DROP COLUMN domain;")
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        expect_domain_column(sqlite_has_domain_column(&conn)?, false, "after DROP COLUMN")?;
    }

    let db = SqlitePool::instantiate(db_file, false, None).await?;
    check_upgraded(&db, &legacy_uid).await?;
    {
        let conn = rusqlite::Connection::open(db_file)
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        expect_domain_column(sqlite_has_domain_column(&conn)?, true, "after upgrade")?;
    }

    let db = SqlitePool::instantiate(db_file, false, None).await?;
    check_upgraded(&db, &legacy_uid).await
}

async fn pgsql_has_domain_column(client: &tokio_postgres::Client) -> DbResult<bool> {
    Ok(client
        .query_opt(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() \
             AND table_name = 'objects' AND column_name = 'domain'",
            &[],
        )
        .await
        .map_err(DbError::from)?
        .is_some())
}

/// `PostgreSQL`: drop `objects.domain`, re-open the database and check the upgrade.
pub(super) async fn pgsql_domain_column_upgrade(url: &str) -> DbResult<()> {
    let legacy_uid = store_key(&PgPool::instantiate(url, true, None).await?, "").await?;

    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .map_err(DbError::from)?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!("PostgreSQL test connection error: {e}");
        }
    });
    client
        .batch_execute("ALTER TABLE objects DROP COLUMN domain;")
        .await
        .map_err(DbError::from)?;
    expect_domain_column(
        pgsql_has_domain_column(&client).await?,
        false,
        "after DROP COLUMN",
    )?;

    let db = PgPool::instantiate(url, false, None).await?;
    expect_domain_column(
        pgsql_has_domain_column(&client).await?,
        true,
        "after upgrade",
    )?;
    check_upgraded(&db, &legacy_uid).await?;

    let db = PgPool::instantiate(url, false, None).await?;
    check_upgraded(&db, &legacy_uid).await
}

async fn mysql_has_domain_column(conn: &mut mysql_async::Conn) -> DbResult<bool> {
    let rows: Vec<mysql_async::Row> = conn
        .query("SHOW COLUMNS FROM objects LIKE 'domain'")
        .await
        .map_err(DbError::from)?;
    Ok(!rows.is_empty())
}

/// `MySQL`/`MariaDB`: drop `objects.domain`, re-open the database and check the upgrade.
pub(super) async fn mysql_domain_column_upgrade(url: &str) -> DbResult<()> {
    let legacy_uid = store_key(&MySqlPool::instantiate(url, true, None).await?, "").await?;

    let opts = mysql_async::Opts::from_url(url).map_err(DbError::from)?;
    let mut conn = mysql_async::Conn::new(opts).await.map_err(DbError::from)?;
    conn.query_drop("ALTER TABLE objects DROP COLUMN domain")
        .await
        .map_err(DbError::from)?;
    expect_domain_column(
        mysql_has_domain_column(&mut conn).await?,
        false,
        "after DROP COLUMN",
    )?;

    let db = MySqlPool::instantiate(url, false, None).await?;
    expect_domain_column(
        mysql_has_domain_column(&mut conn).await?,
        true,
        "after upgrade",
    )?;
    check_upgraded(&db, &legacy_uid).await?;

    let db = MySqlPool::instantiate(url, false, None).await?;
    check_upgraded(&db, &legacy_uid).await?;
    conn.disconnect().await.map_err(DbError::from)?;
    Ok(())
}
