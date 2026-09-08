//! `PgAuditSink` (write path) and `PgAuditReader` (read path) for the `PostgreSQL` audit
//! backend.
//!
//! Multi-writer safety
//! ====================
//! Two independent mechanisms guard against two KMS instances sharing an
//! `instance_id` and corrupting each other's chain:
//! 1. **Advisory lock** (primary defense): [`PgAuditSink::connect`] acquires a
//!    session-level `pg_try_advisory_lock` keyed by `instance_id` on a dedicated,
//!    unpooled connection held for the sink's entire lifetime, *before* `resume()` or
//!    HTTP startup. A competing instance fails to connect at all. Because the lock is
//!    session-scoped on a connection this sink never shares with the write pool, it
//!    cannot be silently dropped by pool recycling. It is **not** reacquired mid-session:
//!    if the dedicated session itself dies (e.g. a network partition), the lock is
//!    released by `PostgreSQL` and a competing writer could take over the `instance_id`
//!    until this process reconnects. The composite-key defense below is what makes that
//!    residual window safe rather than silently corrupting.
//! 2. **Composite primary key** (defense in depth): `(instance_id, id)` makes a genuine
//!    chain fork *structurally impossible*, not just detected — see
//!    [`PgAuditSink::write_event_once`] for how a lost-acknowledgement retry (same writer,
//!    same row) is told apart from a genuine second writer (same slot, different row).
//!
//! `kms_audit_events` schema (`audit.sql`)
//! =======================================
//! `audit.sql` deliberately has **no `--` comments inside any multi-line query body**:
//! the `rawsql` loader joins a query's lines with spaces before handing it to
//! `PostgreSQL`, so an inline `--` would comment out everything after it, including the
//! statement's closing `;`.

use async_trait::async_trait;
use cosmian_kms_access::audit::{AuditEvent, verify_chain_link, verify_event};
use cosmian_kms_interfaces::{AuditSink, ChainHead, InterfaceError, InterfaceResult};
use cosmian_logger::error;
use deadpool_postgres::{
    Config as PgConfig, GenericClient as _, ManagerConfig, Pool, RecyclingMethod,
};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use tokio_postgres::{NoTls, error::SqlState};

use super::{AUDIT_QUERIES, row::event_from_row};
use crate::{
    db_error,
    error::{DbError, DbResult},
    stores::sql::{
        extract_query_params, is_pg_retryable_error, pg_retry_backoff_ms,
        rebuild_url_without_ssl_params,
    },
};

macro_rules! get_audit_query {
    ($name:literal) => {
        AUDIT_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

/// The audit writer is a single task awaiting one `write_event_atomic` at a time, so it can
/// never use a second connection. The pool exists so `write_event_atomic`'s retry loop can ask
/// for a fresh connection after a failover kills the current one.
const AUDIT_POOL_SIZE: usize = 1;

/// Events fetched per page when reading a chain back (`resume()`'s full-chain
/// verification, and every `PgAuditReader` page) — bounds memory regardless of how long
/// the chain has grown, matching the file backend's O(1)-startup-window design intent
/// (there, a tail window; here, one page at a time).
const AUDIT_PAGE_SIZE: i64 = 1_000;

/// Builds a connection pool for `url`. `sslmode=disable` connects in the clear; anything
/// else (including the default, `prefer`) negotiates TLS but does not verify the server
/// certificate — matching the object store's least-surprise default. Certificate pinning
/// (`verify-ca`/`verify-full`) is not supported by the audit backend today; use the
/// object-store connection's stronger guarantees as the model to extend this if a
/// deployment needs it.
fn build_pool(url: &str, max_size: usize, recycling_method: RecyclingMethod) -> DbResult<Pool> {
    let query_params = extract_query_params(url);
    let clean_url = rebuild_url_without_ssl_params(url, &query_params);

    let mut cfg = PgConfig::new();
    cfg.url = Some(clean_url);
    cfg.manager = Some(ManagerConfig { recycling_method });
    cfg.pool = Some(deadpool_postgres::PoolConfig {
        max_size,
        ..Default::default()
    });

    let sslmode = query_params.get("sslmode").map_or("prefer", String::as_str);
    if sslmode == "disable" {
        cfg.create_pool(None, NoTls)
            .map_err(|e| DbError::DatabaseError(e.to_string()))
    } else {
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| DbError::DatabaseError(format!("TLS setup failed: {e}")))?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = MakeTlsConnector::new(builder.build());
        cfg.create_pool(None, connector)
            .map_err(|e| DbError::DatabaseError(e.to_string()))
    }
}

/// Opens a single, unpooled `PostgreSQL` session for holding the instance's advisory
/// lock — see the module docs for why this must never share a connection with the pool.
async fn connect_dedicated_session(url: &str) -> DbResult<tokio_postgres::Client> {
    let query_params = extract_query_params(url);
    let clean_url = rebuild_url_without_ssl_params(url, &query_params);
    let sslmode = query_params.get("sslmode").map_or("prefer", String::as_str);

    let client = if sslmode == "disable" {
        let (client, connection) = tokio_postgres::connect(&clean_url, NoTls)
            .await
            .map_err(DbError::from)?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("audit: dedicated advisory-lock session ended unexpectedly: {e}");
            }
        });
        client
    } else {
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| DbError::DatabaseError(format!("TLS setup failed: {e}")))?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = MakeTlsConnector::new(builder.build());
        let (client, connection) = tokio_postgres::connect(&clean_url, connector)
            .await
            .map_err(DbError::from)?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("audit: dedicated advisory-lock session ended unexpectedly: {e}");
            }
        });
        client
    };
    Ok(client)
}

/// Write path for the `PostgreSQL` audit backend, driven exclusively by the server's
/// single writer task (see `crate::core::audit` in the `server` crate).
pub struct PgAuditSink {
    pool: Pool,
    /// Identifies this KMS instance's chain. Every row this sink writes carries it, and
    /// it scopes every read: one instance, one chain.
    instance_id: String,
    /// Holds the instance's advisory lock for the sink's entire lifetime — see the
    /// module docs. Never read again after `connect()`; kept alive purely so the
    /// session (and therefore the lock) stays open until this sink is dropped.
    #[allow(
        dead_code,
        reason = "kept alive to hold the session-scoped advisory lock"
    )]
    lock_session: tokio_postgres::Client,
}

impl PgAuditSink {
    /// Connects to `url`, acquires `instance_id`'s advisory lock, and ensures the schema
    /// exists and is current.
    ///
    /// # Errors
    /// Returns an error if `instance_id` is empty or over 255 characters, the pool or
    /// dedicated session cannot be built, another writer already holds the instance's
    /// advisory lock, or the schema cannot be created/validated.
    pub async fn connect(url: &str, instance_id: &str) -> DbResult<Self> {
        if instance_id.is_empty() || instance_id.len() > 255 {
            return Err(db_error!(
                "audit: --audit-instance-id must be between 1 and 255 characters"
            ));
        }

        let pool = build_pool(url, AUDIT_POOL_SIZE, RecyclingMethod::Fast)?;

        // Acquired BEFORE ensure_schema/resume/HTTP startup — see the module docs.
        let lock_session = connect_dedicated_session(url).await?;
        let acquired: bool = lock_session
            .query_one(
                get_audit_query!("select-audit-advisory-lock"),
                &[&instance_id],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if !acquired {
            return Err(db_error!(
                "audit: another writer already holds the advisory lock for \
                 instance_id={instance_id} — two KMS instances must not share an audit \
                 instance_id; set a distinct --audit-instance-id on each"
            ));
        }

        Self::ensure_schema(&pool).await?;

        Ok(Self {
            pool,
            instance_id: instance_id.to_owned(),
            lock_session,
        })
    }

    /// Ensures `kms_audit_events` exists and is current, running the full idempotent DDL
    /// bundle (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`,
    /// `CREATE OR REPLACE FUNCTION`, `DROP`+`CREATE TRIGGER`, `REVOKE`) unconditionally on
    /// every boot — every statement is a no-op when already applied, so this both
    /// bootstraps a fresh table and self-heals a table missing a column or trigger added
    /// by a later KMS version.
    ///
    /// A hardened production deployment whose KMS role has only `INSERT`/`SELECT` on a
    /// table owned by someone else gets a permission-denied error here (`SQLSTATE 42501`)
    /// — expected, not fatal: falls back to a read-only check that every required column
    /// is present, trusting the documented setup SQL to have configured
    /// triggers/constraints correctly.
    ///
    /// # Errors
    /// Returns an error if a non-permission DDL failure occurs, or if the read-only
    /// fallback check finds a required column missing.
    async fn ensure_schema(pool: &Pool) -> DbResult<()> {
        let client = pool.get().await.map_err(DbError::from)?;

        for name in [
            "create-table-audit-events",
            "add-column-audit-events-details",
            "create-index-audit-events-timestamp",
            "create-audit-append-only-guard",
            "create-audit-trigger-no-update",
            "create-audit-trigger-no-update-create",
            "create-audit-trigger-no-delete",
            "create-audit-trigger-no-delete-create",
            "create-audit-revoke-mutations",
        ] {
            let sql = AUDIT_QUERIES
                .get(name)
                .ok_or_else(|| db_error!("{} SQL query can't be found", name))?;
            if let Err(e) = client.batch_execute(sql).await {
                if e.as_db_error()
                    .is_some_and(|db| *db.code() == SqlState::INSUFFICIENT_PRIVILEGE)
                {
                    return Self::verify_schema_columns(&client).await;
                }
                return Err(DbError::from(e));
            }
        }
        Ok(())
    }

    /// Read-only fallback for [`Self::ensure_schema`] when the role lacks DDL rights: a
    /// zero-row `SELECT` fails to parse (and therefore errors) if any required column is
    /// missing, without needing to mutate anything.
    async fn verify_schema_columns(client: &deadpool_postgres::Object) -> DbResult<()> {
        client
            .query(get_audit_query!("select-audit-schema-columns"), &[])
            .await
            .map_err(|e| {
                DbError::DatabaseError(format!(
                    "audit: kms_audit_events is missing required columns and this role \
                     cannot create them ({e}). Run the documented audit setup SQL as a \
                     privileged role first."
                ))
            })?;
        Ok(())
    }

    /// Reads the `row_hash` stored for `(instance_id, id)`, if any. Used only to
    /// disambiguate a unique-violation on insert (see [`Self::write_event_once`]).
    async fn stored_row_hash(pool: &Pool, instance_id: &str, id: i64) -> DbResult<Option<Vec<u8>>> {
        let client = pool.get().await.map_err(DbError::from)?;
        let row = client
            .query_opt(
                get_audit_query!("select-audit-event-row-hash"),
                &[&instance_id, &id],
            )
            .await
            .map_err(DbError::from)?;
        Ok(row.map(|r| r.get(0)))
    }

    /// Single-attempt insert of `event`, retried by [`Self::write_event`] on transient
    /// errors.
    async fn write_event_once(pool: &Pool, instance_id: &str, event: &AuditEvent) -> DbResult<()> {
        let client = pool.get().await.map_err(DbError::from)?;
        let duration_ms = i64::try_from(event.duration_ms).unwrap_or(i64::MAX);
        let result_str = event.result.as_canonical_str();
        let prev_hash = event.prev_hash.as_slice();
        let row_hash = event.row_hash.as_slice();

        let res = client
            .execute(
                get_audit_query!("insert-audit-event"),
                &[
                    &instance_id,
                    &event.id,
                    &event.timestamp,
                    &event.operation,
                    &event.user,
                    &event.object_uid,
                    &event.algorithm,
                    &event.client_ip,
                    &result_str,
                    &duration_ms,
                    &event.request_id,
                    &event.details,
                    &prev_hash,
                    &row_hash,
                ],
            )
            .await;

        let Err(e) = res else {
            return Ok(());
        };
        // Release the pooled connection before the disambiguation read below: on a
        // size-1 pool (always — see `AUDIT_POOL_SIZE`), holding it while calling
        // `stored_row_hash` (which itself does `pool.get()`) would deadlock forever
        // waiting for a connection that only `client`'s own drop can free.
        drop(client);

        // SQLSTATE 23505 on (instance_id, id). Do NOT report "another writer" yet: a
        // retry after a lost commit acknowledgement collides with our own row. Read the
        // stored hash to tell the two apart. `ON CONFLICT DO NOTHING` is not an option
        // here — it would paper over the genuine case and leave two divergent chains
        // that each verify in isolation.
        if e.as_db_error()
            .is_some_and(|db| *db.code() == SqlState::UNIQUE_VIOLATION)
        {
            let stored = Self::stored_row_hash(pool, instance_id, event.id).await?;
            return match stored {
                Some(h) if h == event.row_hash => Ok(()),
                _ => Err(DbError::DatabaseError(format!(
                    "audit: another writer is appending to chain instance_id={instance_id} at \
                     id={}. Two KMS instances must not share an audit instance_id — set a \
                     distinct --audit-instance-id on each.",
                    event.id
                ))),
            };
        }

        Err(DbError::from(e))
    }
}

#[async_trait]
impl AuditSink for PgAuditSink {
    fn name(&self) -> &'static str {
        "postgres"
    }

    /// Verifies the **entire** chain (not just the last row) page by page before
    /// resuming, catching an interior tamper the same way the file backend's unconditional
    /// interior scan does. Deliberately fail-fast: unlike the file backend, `PostgreSQL`
    /// writes are atomic (a single `INSERT`), so there is no torn-write case to recover
    /// from, and papering over a corrupted chain here would silently continue an audit
    /// trail that can no longer be trusted.
    ///
    /// TODO: reconsider whether a narrower, ADR-006-style recovery (e.g. quarantine and
    /// reanchor, matching the file backend) makes sense for `PostgreSQL` once there is
    /// operational experience with how this fails in practice.
    async fn resume(&mut self) -> InterfaceResult<ChainHead> {
        let mut prev: Option<AuditEvent> = None;
        let mut after_id = -1_i64;
        loop {
            let client = self
                .pool
                .get()
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let rows = client
                .query(
                    get_audit_query!("select-audit-events-page"),
                    &[&self.instance_id, &after_id, &AUDIT_PAGE_SIZE],
                )
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            drop(client);
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let event = event_from_row(row)?;
                if !verify_event(&event) {
                    return Err(InterfaceError::Db(format!(
                        "audit: event id={} for instance_id={} has an invalid row_hash — \
                         the chain may be corrupted or tampered. Repair or remove it \
                         before restarting.",
                        event.id, self.instance_id
                    )));
                }
                if !verify_chain_link(&event, prev.as_ref()) {
                    return Err(InterfaceError::Db(format!(
                        "audit: event id={} for instance_id={} does not link to the \
                         previous row — the chain may be corrupted or tampered. Repair or \
                         remove it before restarting.",
                        event.id, self.instance_id
                    )));
                }
                after_id = event.id;
                prev = Some(event);
            }
        }

        Ok(prev.map_or(ChainHead::EMPTY, |event| ChainHead {
            next_id: event.id.checked_add(1).unwrap_or(event.id),
            prev_hash: event.row_hash,
        }))
    }

    async fn write_event_atomic(&mut self, event: &AuditEvent) -> InterfaceResult<()> {
        let mut last_err = None;
        for attempt in 0..crate::stores::sql::PG_MAX_RETRIES {
            match Self::write_event_once(&self.pool, &self.instance_id, event).await {
                Ok(()) => return Ok(()),
                Err(e) if is_pg_retryable_error(&e.to_string()) => {
                    let delay = pg_retry_backoff_ms(attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    last_err = Some(e);
                }
                Err(e) => return Err(InterfaceError::from(e)),
            }
        }
        Err(InterfaceError::from(last_err.unwrap_or_else(|| {
            DbError::DatabaseError("audit: too many retry attempts".to_owned())
        })))
    }
}

/// Read-only view of a `PostgreSQL` audit database, used by `ckms audit export|verify`.
///
/// Deliberately separate from [`PgAuditSink`]: it never writes, and it lists *every*
/// chain in the database rather than a single instance's, because an auditor verifying a
/// cluster needs every stream. Both types decode rows through [`event_from_row`], so the
/// read and write representations cannot drift.
pub struct PgAuditReader {
    pool: Pool,
}

impl PgAuditReader {
    /// Connects to the audit database for reading.
    ///
    /// # Errors
    /// Returns an error if the pool cannot be built or the initial connection fails.
    pub async fn connect(url: &str) -> DbResult<Self> {
        let pool = build_pool(url, 4, RecyclingMethod::Verified)?;
        // Fail fast on a bad URL/credentials rather than on the first query.
        let _client = pool.get().await.map_err(DbError::from)?;
        Ok(Self { pool })
    }

    /// Lists every `instance_id` present in the audit database, in ascending order.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub async fn list_instances(&self) -> DbResult<Vec<String>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        let rows = client
            .query(get_audit_query!("select-audit-instances"), &[])
            .await
            .map_err(DbError::from)?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    /// Fetches up to one page of events for `instance_id` with `id > after_id`, in
    /// ascending order. Returns an empty `Vec` once the chain is exhausted.
    ///
    /// Bounded, streaming-friendly building block: a caller that needs "every event"
    /// (export/verify) pages through this in a loop instead of materializing the entire
    /// chain in memory at once — a production chain can be far larger than available RAM.
    ///
    /// # Errors
    /// Returns an error if the query fails or a row cannot be decoded.
    pub async fn events_page(&self, instance_id: &str, after_id: i64) -> DbResult<Vec<AuditEvent>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        let rows = client
            .query(
                get_audit_query!("select-audit-events-page"),
                &[&instance_id, &after_id, &AUDIT_PAGE_SIZE],
            )
            .await
            .map_err(DbError::from)?;
        rows.iter()
            .map(|row| event_from_row(row).map_err(|e| DbError::DatabaseError(e.to_string())))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod live_tests {
    use cosmian_kms_access::audit::{AuditEvent, AuditResult, audit_now, compute_row_hash};
    use cosmian_kms_interfaces::AuditSink;
    use tokio_postgres::NoTls;
    use uuid::Uuid;

    use super::{PgAuditReader, PgAuditSink};

    /// Live audit database URL, resolved at **compile time** (matches the convention used
    /// by the object-store tests in `crate::tests::get_pgsql`).
    fn audit_url() -> String {
        option_env!("KMS_AUDIT_POSTGRES_URL")
            .unwrap_or("postgresql://kms_audit:kms_audit@127.0.0.1:5436/kms_audit")
            .to_owned()
    }

    /// A fresh, random `instance_id` per test so concurrent test runs never collide on the
    /// same chain or advisory lock.
    fn unique_instance_id(label: &str) -> String {
        format!("test-{label}-{}", Uuid::new_v4())
    }

    fn make_event(id: i64, prev_hash: [u8; 32]) -> AuditEvent {
        let mut ev = AuditEvent {
            id,
            timestamp: audit_now(),
            operation: "Encrypt".to_owned(),
            user: "alice".to_owned(),
            object_uid: Some("obj-1".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result: AuditResult::Success,
            duration_ms: 5,
            request_id: None,
            details: None,
            prev_hash,
            row_hash: [0_u8; 32],
        };
        ev.row_hash = compute_row_hash(&ev);
        ev
    }

    /// A raw, unpooled connection used only to simulate a privileged administrator
    /// bypassing the append-only guard (disabling triggers) or attempting to mutate the
    /// table directly.
    async fn raw_client(url: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(url, NoTls)
            .await
            .expect("cannot connect to audit database");
        tokio::spawn(async move {
            drop(connection.await);
        });
        client
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_chain_resumes_across_restart() {
        let instance_id = unique_instance_id("resume");
        let url = audit_url();

        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let head = sink.resume().await.unwrap();
        assert_eq!(head.next_id, 0);
        assert_eq!(head.prev_hash, [0_u8; 32]);

        let ev0 = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev0).await.unwrap();
        let ev1 = make_event(1, ev0.row_hash);
        sink.write_event_atomic(&ev1).await.unwrap();
        drop(sink);

        let mut sink2 = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let head2 = sink2.resume().await.unwrap();
        assert_eq!(
            head2.next_id, 2,
            "resume must continue from the last written id"
        );
        assert_eq!(head2.prev_hash, ev1.row_hash);
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_resume_rejects_tampered_last_row() {
        let instance_id = unique_instance_id("tamper");
        let url = audit_url();

        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let ev0 = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev0).await.unwrap();
        drop(sink);

        // Simulate a privileged administrator: the append-only triggers fire regardless
        // of role, including for the table owner, so tampering even in a test requires
        // disabling them first — exactly the bypass the design's threat model calls out.
        let raw = raw_client(&url).await;
        raw.batch_execute("ALTER TABLE kms_audit_events DISABLE TRIGGER kms_audit_no_update;")
            .await
            .unwrap();
        raw.execute(
            "UPDATE kms_audit_events SET row_hash = $1 WHERE instance_id = $2 AND id = 0",
            &[&vec![0_u8; 32], &instance_id],
        )
        .await
        .unwrap();
        raw.batch_execute("ALTER TABLE kms_audit_events ENABLE TRIGGER kms_audit_no_update;")
            .await
            .unwrap();

        let mut sink2 = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let result = sink2.resume().await;
        assert!(result.is_err(), "resume() must reject a tampered last row");
    }

    /// `resume()` verifies the **entire** chain, not just the last row: tampering an
    /// early row (leaving the last row untouched) must still be caught.
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_resume_rejects_interior_tamper() {
        let instance_id = unique_instance_id("interior-tamper");
        let url = audit_url();

        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let ev0 = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev0).await.unwrap();
        let ev1 = make_event(1, ev0.row_hash);
        sink.write_event_atomic(&ev1).await.unwrap();
        let ev2 = make_event(2, ev1.row_hash);
        sink.write_event_atomic(&ev2).await.unwrap();
        drop(sink);

        // Tamper row 0's content without touching its stored row_hash — the LAST row
        // (id=2) is untouched and would look perfectly fine to a last-row-only check.
        let raw = raw_client(&url).await;
        raw.batch_execute("ALTER TABLE kms_audit_events DISABLE TRIGGER kms_audit_no_update;")
            .await
            .unwrap();
        raw.execute(
            "UPDATE kms_audit_events SET operation = 'Destroy' WHERE instance_id = $1 AND id = 0",
            &[&instance_id],
        )
        .await
        .unwrap();
        raw.batch_execute("ALTER TABLE kms_audit_events ENABLE TRIGGER kms_audit_no_update;")
            .await
            .unwrap();

        let mut sink2 = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let result = sink2.resume().await;
        assert!(
            result.is_err(),
            "resume() must catch a mid-chain tamper, not just the last row"
        );
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_duplicate_writer_rejected_by_advisory_lock() {
        let instance_id = unique_instance_id("dup-writer-lock");
        let url = audit_url();

        let _sink_a = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let result_b = PgAuditSink::connect(&url, &instance_id).await;
        assert!(
            result_b.is_err(),
            "a second writer must be rejected while the first still holds the \
             instance's advisory lock"
        );
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_write_retry_after_lost_ack_is_idempotent() {
        let instance_id = unique_instance_id("retry-ack");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();

        let ev = make_event(0, [0_u8; 32]);
        // Write the same, byte-identical event twice: the second "retry" must be treated
        // as success (our own row, ack lost), not as a rogue writer.
        sink.write_event_atomic(&ev).await.unwrap();
        sink.write_event_atomic(&ev).await.unwrap();
    }

    /// Simulates a hardened production deployment where the KMS role has only
    /// `INSERT`/`SELECT` on a table owned by someone else: `ensure_schema`'s DDL bundle
    /// must fail with `SQLSTATE 42501` and fall back to the read-only column check
    /// instead of aborting `connect()`.
    ///
    /// Requires a companion role `kms_audit_writer` (password `writer_pw`) granted only
    /// `INSERT, SELECT` on `kms_audit_events` — set up by the documented production audit
    /// setup SQL, or manually for this test:
    /// `CREATE ROLE kms_audit_writer LOGIN PASSWORD 'writer_pw'; GRANT INSERT, SELECT ON
    /// kms_audit_events TO kms_audit_writer;`
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance and a pre-provisioned restricted \
                kms_audit_writer role (see doc comment)"]
    async fn pg_connect_falls_back_to_column_check_without_ddl_rights() {
        let base_url = audit_url();
        // Swap in the restricted role's credentials, keeping the same host/port/database.
        let restricted_url =
            base_url.replacen("kms_audit:kms_audit", "kms_audit_writer:writer_pw", 1);

        let result = PgAuditSink::connect(&restricted_url, &unique_instance_id("no-ddl")).await;
        assert!(
            result.is_ok(),
            "connect() must fall back to a read-only column check, not fail, when the \
             role lacks DDL rights on an already-correct schema: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_distinct_instances_keep_independent_chains() {
        let url = audit_url();
        let id_a = unique_instance_id("chain-a");
        let id_b = unique_instance_id("chain-b");

        let mut sink_a = PgAuditSink::connect(&url, &id_a).await.unwrap();
        let head_a = sink_a.resume().await.unwrap();
        let mut sink_b = PgAuditSink::connect(&url, &id_b).await.unwrap();
        let head_b = sink_b.resume().await.unwrap();

        assert_eq!(head_a.next_id, 0);
        assert_eq!(head_b.next_id, 0);
        assert_eq!(head_a.prev_hash, [0_u8; 32]);
        assert_eq!(head_b.prev_hash, [0_u8; 32]);

        let ev_a = make_event(0, [0_u8; 32]);
        sink_a.write_event_atomic(&ev_a).await.unwrap();
        let ev_b = make_event(0, [0_u8; 32]);
        sink_b.write_event_atomic(&ev_b).await.unwrap();

        let reader = PgAuditReader::connect(&url).await.unwrap();
        let events_a = reader.events_page(&id_a, -1).await.unwrap();
        let events_b = reader.events_page(&id_b, -1).await.unwrap();
        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 1);
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_events_page_paginates_and_terminates() {
        let instance_id = unique_instance_id("pagination");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();

        let mut prev_hash = [0_u8; 32];
        for id in 0..3_i64 {
            let ev = make_event(id, prev_hash);
            sink.write_event_atomic(&ev).await.unwrap();
            prev_hash = ev.row_hash;
        }

        let reader = PgAuditReader::connect(&url).await.unwrap();
        let page = reader.events_page(&instance_id, -1).await.unwrap();
        assert_eq!(page.len(), 3);
        let last_id = page.last().unwrap().id;
        let next_page = reader.events_page(&instance_id, last_id).await.unwrap();
        assert!(
            next_page.is_empty(),
            "paginating past the end of the chain must terminate with an empty page"
        );
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_update_and_delete_are_rejected() {
        let instance_id = unique_instance_id("no-mutate");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();
        let ev = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev).await.unwrap();

        let raw = raw_client(&url).await;

        let update_err = raw
            .execute(
                "UPDATE kms_audit_events SET username = 'mallory' WHERE instance_id = $1 AND id = 0",
                &[&instance_id],
            )
            .await
            .expect_err("UPDATE must be rejected by the append-only trigger");
        assert_eq!(
            update_err.as_db_error().map(|e| e.code().code().to_owned()),
            Some("23001".to_owned())
        );

        let delete_err = raw
            .execute(
                "DELETE FROM kms_audit_events WHERE instance_id = $1 AND id = 0",
                &[&instance_id],
            )
            .await
            .expect_err("DELETE must be rejected by the append-only trigger");
        assert_eq!(
            delete_err.as_db_error().map(|e| e.code().code().to_owned()),
            Some("23001".to_owned())
        );
    }
}
