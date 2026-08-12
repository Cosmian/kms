//! `PgAuditSink` (write path) and `PgAuditReader` (read path) for the `PostgreSQL` audit backend.

use async_trait::async_trait;
use cosmian_kms_access::audit::{AuditEvent, verify_event};
use cosmian_kms_interfaces::{AuditSink, ChainHead, InterfaceError, InterfaceResult};
use deadpool_postgres::{Pool, RecyclingMethod};
use tokio_postgres::error::SqlState;

use super::{AUDIT_QUERIES, row::event_from_row};
use crate::{
    db_error,
    error::{DbError, DbResult},
    stores::sql::{build_pool, retry_transient},
};

macro_rules! get_audit_query {
    ($name:literal) => {
        AUDIT_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

/// The audit writer is a single task awaiting one `write_event` at a time, so it can never use a
/// second connection. The pool exists only so a connection killed by a failover is replaced
/// without hand-written reconnect logic — a bare `tokio_postgres::Client` would need that.
const AUDIT_POOL_SIZE: u32 = 1;

/// Write path for the `PostgreSQL` audit backend, driven exclusively by the server's single
/// writer task (see `crate::core::audit` in the `server` crate).
pub struct PgAuditSink {
    pool: Pool,
    /// Identifies this KMS instance's chain. Every row this sink writes carries it, and it scopes
    /// every read: one instance, one chain.
    instance_id: String,
}

impl PgAuditSink {
    /// Connects to `url`, probing whether `kms_audit_events` already exists and creating the
    /// schema only if it does not.
    ///
    /// Probing first (rather than always running the DDL bundle) is what makes the documented
    /// production deployment work: a hardened installation grants the KMS role only
    /// `INSERT`/`SELECT` on a table owned by someone else, and such a role cannot run
    /// `CREATE OR REPLACE FUNCTION` or `REVOKE`. An unconditional DDL pass would abort startup on
    /// every correctly-hardened installation.
    ///
    /// # Errors
    /// Returns an error if the pool cannot be built, the initial connection fails, or (when the
    /// table does not yet exist) the bootstrap DDL fails.
    pub async fn connect(url: &str, instance_id: &str) -> DbResult<Self> {
        // `RecyclingMethod::Fast`, not `Verified`: `Verified` issues a `simple_query("")` health
        // check on every `pool.get()`, which on a size-1 pool doubles the round trips on the
        // audit write path. `write_event` already retries transient errors, so paying for a
        // liveness probe before every insert buys nothing the retry does not already cover.
        let pool = build_pool(url, Some(AUDIT_POOL_SIZE), RecyclingMethod::Fast)?;

        let client = pool.get().await.map_err(DbError::from)?;
        let exists_row = client
            .query_one(get_audit_query!("select-audit-table-exists"), &[])
            .await
            .map_err(DbError::from)?;
        let exists: bool = exists_row.get(0);

        if !exists {
            for name in [
                "create-table-audit-events",
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
                client.batch_execute(sql).await.map_err(DbError::from)?;
            }
        }

        Ok(Self {
            pool,
            instance_id: instance_id.to_owned(),
        })
    }

    /// Reads the `row_hash` stored for `(instance_id, id)`, if any. Used only to disambiguate a
    /// unique-violation on insert (see [`Self::write_event_once`]).
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

    /// Single-attempt insert of `event`, used as the retried operation inside `write_event`.
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
                    &prev_hash,
                    &row_hash,
                ],
            )
            .await;

        let Err(e) = res else {
            return Ok(());
        };
        // Release the pooled connection before the disambiguation read below: on a size-1 pool
        // (which this always is — see `AUDIT_POOL_SIZE`), holding it while calling
        // `stored_row_hash` (which itself does `pool.get()`) would deadlock forever waiting for
        // a connection that only `client`'s own drop can free.
        drop(client);

        // SQLSTATE 23505 on (instance_id, id). Do NOT report "another writer" yet: a retry after
        // a lost commit acknowledgement collides with our own row. Read the stored hash to tell
        // the two apart. `ON CONFLICT DO NOTHING` is not an option here — it would paper over the
        // genuine case and leave two divergent chains that each verify in isolation.
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

    async fn resume(&mut self) -> InterfaceResult<ChainHead> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let row_opt = client
            .query_opt(
                get_audit_query!("select-audit-chain-head"),
                &[&self.instance_id],
            )
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;

        let Some(row) = row_opt else {
            return Ok(ChainHead::EMPTY);
        };

        let event = event_from_row(&row)?;
        if !verify_event(&event) {
            return Err(InterfaceError::Db(format!(
                "audit: last persisted event (id={}) for instance_id={} has an invalid \
                 row_hash — the chain tail may be corrupted or tampered. Repair or remove it \
                 before restarting.",
                event.id, self.instance_id
            )));
        }

        Ok(ChainHead {
            next_id: event.id.checked_add(1).unwrap_or(event.id),
            prev_hash: event.row_hash,
        })
    }

    async fn write_event(&mut self, event: &AuditEvent) -> InterfaceResult<()> {
        let pool = self.pool.clone();
        let instance_id = self.instance_id.clone();
        let event = event.clone();
        retry_transient(move |_attempt| {
            let pool = pool.clone();
            let instance_id = instance_id.clone();
            let event = event.clone();
            async move { Self::write_event_once(&pool, &instance_id, &event).await }
        })
        .await
        .map_err(InterfaceError::from)
    }
}

/// Read-only view of a `PostgreSQL` audit database, used by `ckms audit export|verify`.
///
/// Deliberately separate from [`PgAuditSink`]: it never writes, and it lists *every* chain in the
/// database rather than a single instance's, because an auditor verifying a cluster needs every
/// stream. Both types decode rows through [`event_from_row`], so the read and write
/// representations cannot drift.
pub struct PgAuditReader {
    pool: Pool,
}

impl PgAuditReader {
    /// Connects to the audit database for reading.
    ///
    /// # Errors
    /// Returns an error if the pool cannot be built or the initial connection fails.
    pub async fn connect(url: &str) -> DbResult<Self> {
        let pool = build_pool(url, None, RecyclingMethod::Verified)?;
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

    /// Returns every event for `instance_id`, in ascending `id` order.
    ///
    /// # Errors
    /// Returns an error if the query fails or a row cannot be decoded.
    pub async fn events_for_instance(&self, instance_id: &str) -> DbResult<Vec<AuditEvent>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        let rows = client
            .query(get_audit_query!("select-audit-events"), &[&instance_id])
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

    /// Live audit database URL, resolved at **compile time** (matches the convention used by
    /// the object-store tests in `crate::tests::get_pgsql`).
    fn audit_url() -> String {
        option_env!("KMS_AUDIT_POSTGRES_URL")
            .unwrap_or("postgresql://kms_audit:kms_audit@127.0.0.1:5436/kms_audit")
            .to_owned()
    }

    /// A fresh, random `instance_id` per test so concurrent test runs never collide on the same
    /// chain.
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
            prev_hash,
            row_hash: [0_u8; 32],
        };
        ev.row_hash = compute_row_hash(&ev);
        ev
    }

    /// A raw, unpooled connection used only to simulate a privileged administrator bypassing
    /// the append-only guard (disabling triggers) or attempting to mutate the table directly.
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
        sink.write_event(&ev0).await.unwrap();
        let ev1 = make_event(1, ev0.row_hash);
        sink.write_event(&ev1).await.unwrap();
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
        sink.write_event(&ev0).await.unwrap();
        drop(sink);

        // Simulate a privileged administrator: the append-only triggers fire regardless of
        // role, including for the table owner, so tampering even in a test requires disabling
        // them first — exactly the bypass the design's threat model calls out.
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

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_duplicate_writer_rejected_by_primary_key() {
        let instance_id = unique_instance_id("dup-writer");
        let url = audit_url();

        let mut sink_a = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink_a.resume().await.unwrap();
        let mut sink_b = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink_b.resume().await.unwrap();

        let ev = make_event(0, [0_u8; 32]);
        sink_a.write_event(&ev).await.unwrap();

        // A different event claiming the same (instance_id, id) slot must be rejected —
        // this is NOT the "ack lost, retry collides with our own row" case (different bytes).
        let mut ev_conflict = make_event(0, [0_u8; 32]);
        ev_conflict.user = "mallory".to_owned();
        ev_conflict.row_hash = compute_row_hash(&ev_conflict);
        let result = sink_b.write_event(&ev_conflict).await;
        assert!(
            result.is_err(),
            "a second writer claiming the same chain slot with different content must fail"
        );
        let msg = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("another writer"), "{msg}");
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_write_retry_after_lost_ack_is_idempotent() {
        let instance_id = unique_instance_id("retry-ack");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();

        let ev = make_event(0, [0_u8; 32]);
        // Write the same, byte-identical event twice: the second "retry" must be treated as
        // success (our own row, ack lost), not as a rogue writer.
        sink.write_event(&ev).await.unwrap();
        sink.write_event(&ev).await.unwrap();
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
        sink_a.write_event(&ev_a).await.unwrap();
        let ev_b = make_event(0, [0_u8; 32]);
        sink_b.write_event(&ev_b).await.unwrap();

        let reader = PgAuditReader::connect(&url).await.unwrap();
        let events_a = reader.events_for_instance(&id_a).await.unwrap();
        let events_b = reader.events_for_instance(&id_b).await.unwrap();
        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 1);
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_update_and_delete_are_rejected() {
        let instance_id = unique_instance_id("no-mutate");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();
        let ev = make_event(0, [0_u8; 32]);
        sink.write_event(&ev).await.unwrap();

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
