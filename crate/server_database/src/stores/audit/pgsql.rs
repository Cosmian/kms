//! `PgAuditSink` (write path) and `PgAuditReader` (read path) for the `PostgreSQL` audit
//! backend.
//!
//! Chain generations and recovery
//! ==============================
//! A stable `instance_id` owns a sequence of immutable **generations**
//! (`chain_generation`, starting at 0). At any time exactly one generation is active for
//! writes; every older generation is sealed, forensic evidence that is never modified
//! again. [`PgAuditSink::resume`] verifies only the latest generation: a clean one
//! resumes normally, a corrupted one is left untouched and a fresh generation is started
//! with a row-0 `audit:reanchor` event recording the failure and a digest of the sealed
//! generation — see [`PgAuditSink::seal_and_roll`]. This mirrors the file backend's
//! always-start policy (ADR-0006) for content corruption; connectivity, schema, and lock
//! failures still abort startup.
//!
//! Multi-writer safety
//! ====================
//! Two independent mechanisms guard against two KMS instances sharing an
//! `instance_id` and corrupting each other's chain:
//! 1. **Advisory lock** : [`PgAuditSink::connect`] acquires a
//!    session-level `pg_try_advisory_lock` keyed by `instance_id` on a dedicated,
//!    unpooled connection held for the sink's entire lifetime, *before* `resume()` or
//!    HTTP startup. A competing instance fails to connect at all. Because the lock is
//!    session-scoped on a connection this sink never shares with the write pool, it
//!    cannot be silently dropped by pool recycling. It is **not** reacquired mid-session:
//!    if the dedicated session itself dies (e.g. a network partition), the lock is
//!    released by `PostgreSQL` and a competing writer could take over the `instance_id`
//!    until this process reconnects. The composite-key defense below is what makes that
//!    residual window safe rather than silently corrupting. The seal-and-roll reanchor
//!    insert (see above) runs directly on this dedicated session rather than a pooled
//!    one, precisely so `PostgreSQL` itself — not a separate liveness check racing the
//!    write — guarantees the lock is held for that insert's entire duration.
//! 2. **Composite primary key** : `(instance_id, chain_generation, id)`
//!    makes a genuine chain fork *structurally impossible*, not just detected — see
//!    [`PgAuditSink::write_event_once`] for how a lost-acknowledgement retry (same writer,
//!    same row) is told apart from a genuine second writer (same slot, different row).

use async_trait::async_trait;
use cosmian_kms_access::audit::{
    AuditEvent, AuditEventDraft, AuditResult, audit_now, verify_chain_link, verify_event,
};
use cosmian_kms_interfaces::{
    AuditSink, ChainHead, InterfaceError, InterfaceResult, SealReason, WriteOutcome,
};
use cosmian_logger::error;
use deadpool_postgres::{
    Config as PgConfig, GenericClient as _, ManagerConfig, Pool, RecyclingMethod,
};
use openssl::hash::{Hasher, MessageDigest};
use tokio_postgres::{NoTls, error::SqlState};

use super::{AUDIT_QUERIES, row::event_from_row};
use crate::{
    db_error,
    error::{DbError, DbResult},
    stores::sql::{
        build_pg_tls_connector, extract_query_params, is_pg_retryable_error, pg_retry_backoff_ms,
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

/// Builds a 1-connection pool for `url`. `sslmode=disable` connects in the clear; any other
/// mode (default `prefer`) negotiates TLS honoring `sslmode`/`sslrootcert`/`sslcert`/`sslkey`
/// via `sql::build_pg_tls_connector` — identical behavior to the object-store connection.
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
        let connector = build_pg_tls_connector(&query_params)?;
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
        let connector = build_pg_tls_connector(&query_params)?;
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
    /// module docs. Also used directly (not through `pool`) to insert a seal-and-roll
    /// reanchor row, so the lock is provably held for that insert's entire duration.
    lock_session: tokio_postgres::Client,
    /// The generation currently accepting writes. Set by [`Self::resume`] (never before);
    /// `write_event_atomic` always writes into this generation.
    active_generation: i64,
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
            active_generation: 0,
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
            "create-index-audit-events-timestamp",
            "create-audit-control-table",
            "create-audit-append-only-guard",
            "create-audit-trigger-no-update",
            "create-audit-trigger-no-update-create",
            "create-audit-trigger-no-delete",
            "create-audit-trigger-no-delete-create",
            "create-audit-trigger-no-truncate",
            "create-audit-trigger-no-truncate-create",
            "create-audit-reject-sealed-insert",
            "create-audit-trigger-no-insert-sealed",
            "create-audit-trigger-no-insert-sealed-create",
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

    /// Reads the `(prev_hash, row_hash)` stored for `(instance_id, chain_generation,
    /// id)`, if any. Used only to disambiguate a unique-violation on insert (see
    /// [`Self::write_event_once`]).
    async fn stored_chain_fields(
        pool: &Pool,
        instance_id: &str,
        generation: i64,
        id: i64,
    ) -> DbResult<Option<([u8; 32], [u8; 32])>> {
        let client = pool.get().await.map_err(DbError::from)?;
        let row = client
            .query_opt(
                get_audit_query!("select-audit-event-chain-fields"),
                &[&instance_id, &generation, &id],
            )
            .await
            .map_err(DbError::from)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let prev_hash: Vec<u8> = row.get(0);
        let row_hash: Vec<u8> = row.get(1);
        let prev_hash = <[u8; 32]>::try_from(prev_hash.as_slice())
            .map_err(|_e| db_error!("audit: stored prev_hash has the wrong length"))?;
        let row_hash = <[u8; 32]>::try_from(row_hash.as_slice())
            .map_err(|_e| db_error!("audit: stored row_hash has the wrong length"))?;
        Ok(Some((prev_hash, row_hash)))
    }

    /// Executes `insert-audit-event` on `client` for `(instance_id, generation)`. Shared
    /// by the steady-state pooled write path ([`Self::write_event_once`]) and the
    /// lock-session reanchor insert ([`Self::seal_and_roll`]) so the parameter binding is
    /// defined exactly once. Returns the raw `tokio_postgres` error (not [`DbError`]): the
    /// caller needs the original `SqlState` to disambiguate a unique-violation retry from
    /// a genuine competing writer, which [`DbError::from`] collapses into one message.
    async fn insert_event_row(
        client: &tokio_postgres::Client,
        query: &str,
        instance_id: &str,
        generation: i64,
        event: &AuditEvent,
    ) -> Result<u64, tokio_postgres::Error> {
        let duration_ms = i64::try_from(event.duration_ms).unwrap_or(i64::MAX);
        let result_str = event.result.as_canonical_str();
        let prev_hash = event.prev_hash.as_slice();
        let row_hash = event.row_hash.as_slice();

        client
            .execute(
                query,
                &[
                    &instance_id,
                    &generation,
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
            .await
    }

    /// Single-attempt insert of `event` into `generation`, retried by
    /// [`Self::write_event_atomic`] on transient errors.
    ///
    /// A unique-violation on `(instance_id, generation, id)` is not automatically a
    /// competing writer: a retry after a lost commit acknowledgement collides with our
    /// own prior row at the same slot. The stored row is read back to tell the two cases
    /// apart:
    /// * identical `row_hash` — the exact same write, replayed: already durable, done.
    /// * different content but the stored row's `prev_hash` matches this draft's
    ///   `prev_hash` — the slot holds a *different*, already-durable event from this same
    ///   writer (the draft that used to be queued for this id was abandoned after a
    ///   lost-ack retry gave up). The chain is still valid; the caller must resync onto
    ///   it and retry the current draft one id further, never dropping it silently.
    /// * stored `prev_hash` does not match — a genuine fork (corruption, or a second
    ///   writer that slipped past the advisory lock): unrecoverable here.
    async fn write_event_once(
        pool: &Pool,
        instance_id: &str,
        generation: i64,
        event: &AuditEvent,
    ) -> DbResult<WriteOutcome> {
        let client = pool.get().await.map_err(DbError::from)?;
        let query = get_audit_query!("insert-audit-event");
        let res = Self::insert_event_row(&client, query, instance_id, generation, event).await;

        let Err(e) = res else {
            return Ok(WriteOutcome::Written);
        };
        // Drop below is necessary for 1 client pool: holding it while calling
        // `stored_chain_fields` (which itself does `pool.get()`) would deadlock forever.
        drop(client);

        // SQLSTATE 23505 on (instance_id, chain_generation, id). `ON CONFLICT DO NOTHING`
        // is not an option here — it would paper over the genuine-fork case and leave two
        // divergent chains that each verify in isolation.
        if e.as_db_error()
            .is_some_and(|db| *db.code() == SqlState::UNIQUE_VIOLATION)
        {
            let stored = Self::stored_chain_fields(pool, instance_id, generation, event.id).await?;
            return match stored {
                Some((_, row_hash)) if row_hash == event.row_hash => Ok(WriteOutcome::Written),
                Some((prev_hash, row_hash)) if prev_hash == event.prev_hash => {
                    Ok(WriteOutcome::Resynced(ChainHead {
                        next_id: event.id.checked_add(1).ok_or_else(|| {
                            db_error!(
                                "audit: instance_id={instance_id} id counter exhausted at \
                                 i64::MAX during resync"
                            )
                        })?,
                        prev_hash: row_hash,
                    }))
                }
                _ => Err(DbError::DatabaseError(format!(
                    "audit: another writer is appending to chain instance_id={instance_id} \
                     generation={generation} at id={}. Two KMS instances must not share an \
                     audit instance_id — set a distinct --audit-instance-id on each.",
                    event.id
                ))),
            };
        }

        Err(DbError::from(e))
    }

    /// Inserts `event` directly on [`Self::lock_session`] rather than through `pool` —
    /// see the module docs for why this is what makes the reanchor insert safe against
    /// advisory-lock loss, instead of merely checking the lock is held immediately
    /// beforehand (which would still race the loss against the write).
    async fn insert_reanchor_on_lock_session(
        &self,
        generation: i64,
        event: &AuditEvent,
    ) -> DbResult<()> {
        let query = get_audit_query!("insert-audit-event");
        Self::insert_event_row(
            &self.lock_session,
            query,
            &self.instance_id,
            generation,
            event,
        )
        .await
        .map_err(DbError::from)?;
        Ok(())
    }

    /// Returns the generation this instance should resume writing into: the
    /// `kms_audit_control` row's authoritative pointer if one exists, or — first ever
    /// boot before that row has been written — `MAX(chain_generation)` over any existing
    /// rows, immediately persisted to the control row so every later call takes the fast
    /// path. `None` means a genuinely brand-new instance with no rows at all.
    ///
    /// This, not a bare `MAX()`, is what [`Self::resume`] trusts: `MAX()` alone can be
    /// skewed by ordinary `INSERT` privilege into an already-sealed generation, which is
    /// exactly what `kms_audit_no_insert_sealed` (backed by this same control row) exists
    /// to reject at the database level.
    async fn latest_generation(&self) -> DbResult<Option<i64>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        if let Some(row) = client
            .query_opt(
                get_audit_query!("select-audit-control-generation"),
                &[&self.instance_id],
            )
            .await
            .map_err(DbError::from)?
        {
            return Ok(Some(row.get(0)));
        }

        let max_generation: Option<i64> = client
            .query_one(
                get_audit_query!("select-audit-latest-generation"),
                &[&self.instance_id],
            )
            .await
            .map_err(DbError::from)?
            .get(0);
        if let Some(generation) = max_generation {
            client
                .execute(
                    get_audit_query!("upsert-audit-control-generation"),
                    &[&self.instance_id, &generation],
                )
                .await
                .map_err(DbError::from)?;
        }
        Ok(max_generation)
    }

    /// Upserts the control row to `generation` on the pooled connection. Used only for a
    /// brand-new instance's first-ever generation — [`Self::seal_and_roll`] updates the
    /// control row on [`Self::lock_session`] instead, before its reanchor insert, so both
    /// happen on the session that provably holds the instance's advisory lock.
    async fn set_active_generation(&self, generation: i64) -> DbResult<()> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        client
            .execute(
                get_audit_query!("upsert-audit-control-generation"),
                &[&self.instance_id, &generation],
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// Verifies every row of `generation`, page by page, the same way the file backend's
    /// unconditional interior scan does. Returns the chain head when every row verifies,
    /// or the first failure's classification when one doesn't — recovery from that
    /// failure is [`Self::seal_and_roll`]'s job, not this function's.
    async fn verify_generation(&self, generation: i64) -> InterfaceResult<GenerationOutcome> {
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
                    &[&self.instance_id, &generation, &after_id, &AUDIT_PAGE_SIZE],
                )
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            drop(client);
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let Ok(event) = event_from_row(row) else {
                    return Ok(GenerationOutcome::Corrupt(RecoveryFailure {
                        reason: SealReason::Unparsable,
                        first_failure_id: row.get("id"),
                    }));
                };
                if !verify_event(&event) {
                    return Ok(GenerationOutcome::Corrupt(RecoveryFailure {
                        reason: SealReason::HashMismatch,
                        first_failure_id: event.id,
                    }));
                }
                if !verify_chain_link(&event, prev.as_ref()) {
                    return Ok(GenerationOutcome::Corrupt(RecoveryFailure {
                        reason: SealReason::BrokenLink,
                        first_failure_id: event.id,
                    }));
                }
                after_id = event.id;
                prev = Some(event);
            }
        }

        Ok(prev.map_or(
            GenerationOutcome::Valid(ChainHead::EMPTY),
            |event| match event.id.checked_add(1) {
                Some(next_id) => GenerationOutcome::Valid(ChainHead {
                    next_id,
                    prev_hash: event.row_hash,
                }),
                None => GenerationOutcome::Corrupt(RecoveryFailure {
                    reason: SealReason::IdOverflow,
                    first_failure_id: event.id,
                }),
            },
        ))
    }

    /// Computes the recovery evidence digest over every stored row of `generation`: the
    /// deterministic text projection in `select-audit-generation-evidence`, one line per
    /// row (in `id` order) plus the footer `v1|end|<generation>|<row_count>`, streamed
    /// through OpenSSL SHA-256 page by page — bounded per-page memory, matching
    /// `AUDIT_PAGE_SIZE`'s existing bounded-read design intent.
    ///
    /// Independently reproducible without this code: run the query in `psql` with
    /// unaligned, tuples-only output, append the same footer line, and pipe both through
    /// `sha256sum` — see the audit operator guide for the exact command.
    async fn compute_generation_evidence(&self, generation: i64) -> DbResult<String> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).map_err(|e| {
            DbError::DatabaseError(format!("audit: cannot start evidence hasher: {e}"))
        })?;
        let mut row_count: i64 = 0;
        let mut after_id = -1_i64;
        loop {
            let client = self.pool.get().await.map_err(DbError::from)?;
            let rows = client
                .query(
                    get_audit_query!("select-audit-generation-evidence"),
                    &[&self.instance_id, &generation, &after_id, &AUDIT_PAGE_SIZE],
                )
                .await
                .map_err(DbError::from)?;
            drop(client);
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let line: String = row.get(1);
                hasher.update(line.as_bytes()).map_err(|e| {
                    DbError::DatabaseError(format!("audit: evidence hashing failed: {e}"))
                })?;
                hasher.update(b"\n").map_err(|e| {
                    DbError::DatabaseError(format!("audit: evidence hashing failed: {e}"))
                })?;
                row_count += 1;
            }
            after_id = rows.last().map_or(after_id, |r| r.get::<_, i64>(0));
        }

        hasher
            .update(format!("v1|end|{generation}|{row_count}\n").as_bytes())
            .map_err(|e| DbError::DatabaseError(format!("audit: evidence hashing failed: {e}")))?;
        let digest = hasher
            .finish()
            .map_err(|e| DbError::DatabaseError(format!("audit: evidence hashing failed: {e}")))?;
        Ok(format!("v1:sha256:{}", hex::encode(digest.as_ref())))
    }

    /// Seals `sealed_generation` as forensic evidence — never modified again — and starts
    /// `sealed_generation + 1` with a row-0 `audit:reanchor` event identifying the
    /// failure and carrying a digest of the sealed generation. This is the KMS's
    /// always-start recovery for `PostgreSQL` content corruption (ADR-0006): the
    /// corrupted generation is preserved, not discarded, and startup proceeds.
    ///
    /// # Errors
    /// Returns an error if the generation counter is exhausted, the evidence digest
    /// cannot be computed, or the reanchor cannot be persisted — these are treated as
    /// operational failures, not corruption, and still abort startup.
    async fn seal_and_roll(
        &mut self,
        sealed_generation: i64,
        failure: RecoveryFailure,
    ) -> InterfaceResult<ChainHead> {
        let evidence = self
            .compute_generation_evidence(sealed_generation)
            .await
            .map_err(InterfaceError::from)?;

        let new_generation = sealed_generation.checked_add(1).ok_or_else(|| {
            InterfaceError::Db(format!(
                "audit: instance_id={} chain_generation counter exhausted at i64::MAX — \
                 cannot start a fresh generation",
                self.instance_id
            ))
        })?;

        let details = serde_json::json!({
            "sealed_generation": sealed_generation,
            "new_generation": new_generation,
            "first_failure_id": failure.first_failure_id,
            "reason": failure.reason.as_str(),
            "evidence": evidence,
        })
        .to_string();

        let draft = AuditEventDraft {
            timestamp: audit_now(),
            operation: "audit:reanchor".to_owned(),
            user: "server".to_owned(),
            object_uid: None,
            algorithm: None,
            client_ip: None,
            result: AuditResult::Success,
            duration_ms: 0,
            request_id: None,
            details: Some(details),
        };
        let reanchor = draft.finalize(0, [0_u8; 32]);

        // Must happen before the reanchor insert, on the same lock-held session: the
        // `kms_audit_no_insert_sealed` trigger checks the control row's active_generation
        // for every INSERT, including this one.
        self.lock_session
            .execute(
                get_audit_query!("upsert-audit-control-generation"),
                &[&self.instance_id, &new_generation],
            )
            .await
            .map_err(|e| {
                InterfaceError::from(DbError::DatabaseError(format!(
                    "audit: failed to advance control row to generation {new_generation}: {e}"
                )))
            })?;

        self.insert_reanchor_on_lock_session(new_generation, &reanchor)
            .await
            .map_err(InterfaceError::from)?;

        error!(
            "audit: instance_id={} sealed generation {sealed_generation} (reason={}, \
             first_failure_id={}, evidence={evidence}) — starting generation {new_generation}",
            self.instance_id,
            failure.reason.as_str(),
            failure.first_failure_id,
        );

        self.active_generation = new_generation;
        Ok(ChainHead {
            next_id: 1,
            prev_hash: reanchor.row_hash,
        })
    }
}

/// First-failure classification produced by [`PgAuditSink::verify_generation`].
struct RecoveryFailure {
    reason: SealReason,
    first_failure_id: i64,
}

/// Outcome of verifying one generation's stored rows.
enum GenerationOutcome {
    Valid(ChainHead),
    Corrupt(RecoveryFailure),
}

#[async_trait]
impl AuditSink for PgAuditSink {
    fn name(&self) -> &'static str {
        "postgres"
    }

    /// Resumes the latest chain generation for this instance, or starts generation 0 for
    /// a brand-new instance. A clean latest generation resumes normally; a corrupted one
    /// is sealed unchanged and a fresh generation takes over — see the module docs and
    /// [`Self::seal_and_roll`]. Older, already-sealed generations are never re-verified.
    async fn resume(&mut self) -> InterfaceResult<ChainHead> {
        let Some(generation) = self
            .latest_generation()
            .await
            .map_err(InterfaceError::from)?
        else {
            self.active_generation = 0;
            self.set_active_generation(0)
                .await
                .map_err(InterfaceError::from)?;
            return Ok(ChainHead::EMPTY);
        };

        match self.verify_generation(generation).await? {
            GenerationOutcome::Valid(head) => {
                self.active_generation = generation;
                Ok(head)
            }
            GenerationOutcome::Corrupt(failure) => self.seal_and_roll(generation, failure).await,
        }
    }

    async fn write_event_atomic(&mut self, event: &AuditEvent) -> InterfaceResult<WriteOutcome> {
        let mut last_err = None;
        for attempt in 0..crate::stores::sql::PG_MAX_RETRIES {
            match Self::write_event_once(
                &self.pool,
                &self.instance_id,
                self.active_generation,
                event,
            )
            .await
            {
                Ok(outcome) => return Ok(outcome),
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

/// Read-only view of a `PostgreSQL` audit database. Not currently wired into any `ckms
/// audit` subcommand — used today by tests and ad-hoc inspection tooling.
///
/// Deliberately separate from [`PgAuditSink`]: it never writes, and it lists *every*
/// chain in the database rather than a single instance's, because an auditor verifying a
/// cluster needs every stream. Both types decode rows through [`event_from_row`], so the
/// read and write representations cannot drift. Generations are never concatenated into
/// one chain: each is independently anchored, and a caller must ask for one explicitly.
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

    /// Lists every `chain_generation` stored for `instance_id`, in ascending order (the
    /// order generations were started in). An instance with no rows returns an empty
    /// `Vec`.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub async fn list_generations(&self, instance_id: &str) -> DbResult<Vec<i64>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        let rows = client
            .query(
                get_audit_query!("select-audit-generations"),
                &[&instance_id],
            )
            .await
            .map_err(DbError::from)?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    /// Fetches up to one page of events for `(instance_id, generation)` with `id >
    /// after_id`, in ascending order. Returns an empty `Vec` once the generation is
    /// exhausted. `generation` is required, not defaulted: generations are independently
    /// anchored chains and must never be silently concatenated — see
    /// [`Self::list_generations`] to enumerate them first.
    ///
    /// Bounded, streaming-friendly building block: a caller that needs "every event"
    /// (export/verify) pages through this in a loop instead of materializing the entire
    /// chain in memory at once — a production chain can be far larger than available RAM.
    ///
    /// # Errors
    /// Returns an error if the query fails or a row cannot be decoded.
    pub async fn events_page(
        &self,
        instance_id: &str,
        generation: i64,
        after_id: i64,
    ) -> DbResult<Vec<AuditEvent>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        let rows = client
            .query(
                get_audit_query!("select-audit-events-page"),
                &[&instance_id, &generation, &after_id, &AUDIT_PAGE_SIZE],
            )
            .await
            .map_err(DbError::from)?;
        rows.iter()
            .map(|row| event_from_row(row).map_err(|e| DbError::DatabaseError(e.to_string())))
            .collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod live_tests {
    use cosmian_kms_access::audit::{AuditEvent, AuditResult, audit_now, compute_row_hash};
    use cosmian_kms_interfaces::{AuditSink, ChainHead, WriteOutcome};
    use tokio_postgres::NoTls;
    use uuid::Uuid;

    use super::{PgAuditReader, PgAuditSink};

    /// Live audit database URL. Defaults to the repository's shared `docker-compose`
    /// `PostgreSQL` service (see `.mise/lib/test_slots.sh`'s `KMS_AUDIT_POSTGRES_URL`), so a
    /// local `docker compose up -d postgres` is enough to run these tests.
    fn audit_url() -> String {
        option_env!("KMS_AUDIT_POSTGRES_URL")
            .unwrap_or("postgresql://kms:kms@127.0.0.1:5432/kms")
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

    /// Writes a clean 3-row generation 0 (ids 0, 1, 2) and returns the sink so the caller
    /// can drop it before corrupting the table directly.
    async fn seed_generation_zero(url: &str, instance_id: &str) -> PgAuditSink {
        let mut sink = PgAuditSink::connect(url, instance_id).await.unwrap();
        sink.resume().await.unwrap();
        let ev0 = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev0).await.unwrap();
        let ev1 = make_event(1, ev0.row_hash);
        sink.write_event_atomic(&ev1).await.unwrap();
        let ev2 = make_event(2, ev1.row_hash);
        sink.write_event_atomic(&ev2).await.unwrap();
        sink
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

    /// Disables the append-only triggers, runs one parameterised `UPDATE`, then
    /// re-enables them — the bypass every tamper test below needs, since the triggers
    /// fire regardless of role.
    async fn tamper_row(
        url: &str,
        sql: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) {
        let raw = raw_client(url).await;
        raw.batch_execute("ALTER TABLE kms_audit_events DISABLE TRIGGER kms_audit_no_update;")
            .await
            .unwrap();
        raw.execute(sql, params).await.unwrap();
        raw.batch_execute("ALTER TABLE kms_audit_events ENABLE TRIGGER kms_audit_no_update;")
            .await
            .unwrap();
    }

    /// Shared post-corruption assertions for seal-and-roll recovery: `resume()` must
    /// succeed (not fail closed), generation 0 must be byte-for-byte unchanged from
    /// `sealed_before` (captured after corruption, before recovery — the baseline
    /// recovery must leave untouched), generation 1 must start with exactly one valid
    /// `audit:reanchor` identifying the failure, and a following write must link onto it.
    async fn assert_recovers_into_generation_1(
        url: &str,
        instance_id: &str,
        expected_failure_id: i64,
        expected_reason: &str,
        sealed_before: &[AuditEvent],
    ) {
        let mut sink = PgAuditSink::connect(url, instance_id).await.unwrap();
        let head = sink
            .resume()
            .await
            .unwrap_or_else(|e| panic!("resume() must recover content corruption, not fail: {e}"));
        assert_eq!(
            head.next_id, 1,
            "recovery must anchor the new generation at id=1"
        );

        let reader = PgAuditReader::connect(url).await.unwrap();
        let sealed_after = reader.events_page(instance_id, 0, -1).await.unwrap();
        assert_eq!(
            sealed_before.len(),
            sealed_after.len(),
            "sealed generation 0 must not gain or lose rows"
        );
        for (before, after) in sealed_before.iter().zip(sealed_after.iter()) {
            assert_eq!(
                before.row_hash, after.row_hash,
                "sealed generation 0 must not change"
            );
        }

        let gen1 = reader.events_page(instance_id, 1, -1).await.unwrap();
        assert_eq!(
            gen1.len(),
            1,
            "generation 1 must start with exactly the reanchor"
        );
        let reanchor = &gen1[0];
        assert_eq!(reanchor.operation, "audit:reanchor");
        assert_eq!(reanchor.id, 0);
        assert_eq!(reanchor.prev_hash, [0_u8; 32]);
        let details: serde_json::Value =
            serde_json::from_str(reanchor.details.as_deref().unwrap()).unwrap();
        assert_eq!(details["sealed_generation"], 0);
        assert_eq!(details["new_generation"], 1);
        assert_eq!(details["first_failure_id"], expected_failure_id);
        assert_eq!(details["reason"], expected_reason);
        assert!(
            details["evidence"]
                .as_str()
                .is_some_and(|e| e.starts_with("v1:sha256:")),
            "reanchor must carry a versioned evidence digest"
        );

        sink.write_event_atomic(&make_event(1, head.prev_hash))
            .await
            .unwrap();
        let gen1_after = reader.events_page(instance_id, 1, -1).await.unwrap();
        assert_eq!(gen1_after.len(), 2);
        assert_eq!(gen1_after[1].prev_hash, reanchor.row_hash);
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_chain_resumes_across_restart() {
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

    /// T1a: a complete, well-formed row whose own hash doesn't match its stored bytes
    /// (the tail row here) must seal generation 0 and reanchor generation 1 — not fail
    /// startup, per ADR-0006's always-start policy for content corruption.
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_seal_and_roll_recovers_tail_hash_mismatch() {
        let instance_id = unique_instance_id("seal-roll-tail");
        let url = audit_url();

        let sink = seed_generation_zero(&url, &instance_id).await;
        drop(sink);

        tamper_row(
            &url,
            "UPDATE kms_audit_events SET row_hash = $2 WHERE instance_id = $1 AND \
             chain_generation = 0 AND id = 2",
            &[&instance_id, &vec![0_u8; 32]],
        )
        .await;

        let reader = PgAuditReader::connect(&url).await.unwrap();
        let sealed_before = reader.events_page(&instance_id, 0, -1).await.unwrap();

        assert_recovers_into_generation_1(&url, &instance_id, 2, "hash_mismatch", &sealed_before)
            .await;
    }

    /// T1b: a row whose own hash is internally consistent but doesn't chain to its
    /// predecessor (an interior row here, id=1, with the tail row id=2 left untouched)
    /// must also recover — proving recovery is not accidentally tail-only.
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_seal_and_roll_recovers_interior_broken_link() {
        let instance_id = unique_instance_id("seal-roll-interior");
        let url = audit_url();

        let sink = seed_generation_zero(&url, &instance_id).await;
        drop(sink);

        // Forge row 1 from its *actual* stored fields, changing only `prev_hash` and
        // recomputing `row_hash` to match — otherwise the row's own hash wouldn't match
        // its other stored columns (unrelated timestamp/fields), producing a
        // hash_mismatch instead of the broken-link case this test targets.
        let reader = PgAuditReader::connect(&url).await.unwrap();
        let before_tamper = reader.events_page(&instance_id, 0, -1).await.unwrap();
        let mut forged = before_tamper[1].clone();
        forged.prev_hash = [0xAA_u8; 32];
        forged.row_hash = compute_row_hash(&forged);
        tamper_row(
            &url,
            "UPDATE kms_audit_events SET prev_hash = $2, row_hash = $3 WHERE instance_id = \
             $1 AND chain_generation = 0 AND id = 1",
            &[
                &instance_id,
                &forged.prev_hash.as_slice(),
                &forged.row_hash.as_slice(),
            ],
        )
        .await;

        let sealed_before = reader.events_page(&instance_id, 0, -1).await.unwrap();

        assert_recovers_into_generation_1(&url, &instance_id, 1, "broken_link", &sealed_before)
            .await;
    }

    /// T3: the evidence digest stored in the reanchor must match the same SHA-256
    /// computed independently over the documented SQL projection, proving the digest is
    /// reproducible without this code — see the audit operator guide for the exact
    /// `psql | sha256sum` recipe this mirrors.
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_evidence_digest_matches_sql_projection() {
        use openssl::hash::{Hasher, MessageDigest};

        let instance_id = unique_instance_id("evidence");
        let url = audit_url();

        let sink = seed_generation_zero(&url, &instance_id).await;
        drop(sink);
        tamper_row(
            &url,
            "UPDATE kms_audit_events SET row_hash = $2 WHERE instance_id = $1 AND \
             chain_generation = 0 AND id = 2",
            &[&instance_id, &vec![0_u8; 32]],
        )
        .await;

        let mut sink2 = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink2.resume().await.unwrap();

        let reader = PgAuditReader::connect(&url).await.unwrap();
        let gen1 = reader.events_page(&instance_id, 1, -1).await.unwrap();
        let details: serde_json::Value =
            serde_json::from_str(gen1[0].details.as_deref().unwrap()).unwrap();
        let stored_digest = details["evidence"].as_str().unwrap();

        // Independently reproduce the digest from the documented projection, exactly as
        // an operator would with `psql -qtA` piped to `sha256sum`.
        let raw = raw_client(&url).await;
        let rows = raw
            .query(
                "SELECT 'v1' || '|' || encode(convert_to(instance_id, 'UTF8'), 'hex') || '|' \
                 || chain_generation || '|' || id || '|' || to_char(timestamp AT TIME ZONE \
                 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') || '|' || \
                 encode(convert_to(operation, 'UTF8'), 'hex') || '|' || \
                 encode(convert_to(username, 'UTF8'), 'hex') || '|' || \
                 COALESCE(encode(convert_to(object_uid, 'UTF8'), 'hex'), '-') || '|' || \
                 COALESCE(encode(convert_to(algorithm, 'UTF8'), 'hex'), '-') || '|' || \
                 COALESCE(encode(convert_to(client_ip, 'UTF8'), 'hex'), '-') || '|' || \
                 encode(convert_to(result, 'UTF8'), 'hex') || '|' || duration_ms || '|' || \
                 COALESCE(request_id::text, '-') || '|' || \
                 COALESCE(encode(convert_to(details, 'UTF8'), 'hex'), '-') || '|' || \
                 encode(prev_hash, 'hex') || '|' || encode(row_hash, 'hex') FROM \
                 kms_audit_events WHERE instance_id = $1 AND chain_generation = 0 ORDER BY \
                 id ASC",
                &[&instance_id],
            )
            .await
            .unwrap();

        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        let row_count = rows.len();
        for row in &rows {
            let line: String = row.get(0);
            hasher.update(line.as_bytes()).unwrap();
            hasher.update(b"\n").unwrap();
        }
        hasher
            .update(format!("v1|end|0|{row_count}\n").as_bytes())
            .unwrap();
        let expected = format!(
            "v1:sha256:{}",
            hex::encode(hasher.finish().unwrap().as_ref())
        );

        assert_eq!(
            stored_digest, expected,
            "stored evidence digest must match the independently reproduced SQL projection"
        );
    }

    /// Inserts an event directly into `kms_audit_events`, bypassing `PgAuditSink`
    /// entirely — used to simulate a raw client (or a compromised process sharing the
    /// audit role's credentials) attempting to forge a row.
    async fn raw_insert_event(
        url: &str,
        instance_id: &str,
        generation: i64,
        event: &AuditEvent,
    ) -> Result<(), tokio_postgres::Error> {
        let raw = raw_client(url).await;
        let duration_ms = i64::try_from(event.duration_ms).unwrap();
        let result_str = event.result.as_canonical_str();
        raw.execute(
            "INSERT INTO kms_audit_events (instance_id, chain_generation, id, timestamp, \
             operation, username, object_uid, algorithm, client_ip, result, duration_ms, \
             request_id, details, prev_hash, row_hash) VALUES \
             ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            &[
                &instance_id,
                &generation,
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
                &event.prev_hash.as_slice(),
                &event.row_hash.as_slice(),
            ],
        )
        .await
        .map(|_| ())
    }

    /// H2: once `seal_and_roll` has advanced the control row past generation 0, a raw
    /// `INSERT` targeting the now-sealed generation must be rejected by the database
    /// itself — ordinary `INSERT` privilege must not be enough to forge evidence into a
    /// generation the KMS itself no longer considers active. The now-active generation
    /// must still accept inserts normally.
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_sealed_generation_rejects_direct_insert() {
        let instance_id = unique_instance_id("sealed-insert-guard");
        let url = audit_url();

        let sink = seed_generation_zero(&url, &instance_id).await;
        drop(sink);
        tamper_row(
            &url,
            "UPDATE kms_audit_events SET row_hash = $2 WHERE instance_id = $1 AND \
             chain_generation = 0 AND id = 2",
            &[&instance_id, &vec![0_u8; 32]],
        )
        .await;

        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume()
            .await
            .expect("resume must seal generation 0 and roll to generation 1");

        let forged = make_event(3, [0xCC_u8; 32]);
        let err = raw_insert_event(&url, &instance_id, 0, &forged)
            .await
            .expect_err("insert into the sealed generation must be rejected");
        assert_eq!(
            err.as_db_error().map(|e| e.code().code().to_owned()),
            Some("23001".to_owned())
        );

        // The now-active generation is unaffected by the guard.
        raw_insert_event(&url, &instance_id, 1, &make_event(1, [0xAA_u8; 32]))
            .await
            .expect("insert into the active generation must still succeed");
    }

    /// H2: a brand-new instance's control row must be initialized to generation 0 before
    /// `resume()` returns, so the very first write (which the guard also checks) is never
    /// blocked by its own bootstrap.
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_control_table_initialized_for_new_instance() {
        let instance_id = unique_instance_id("control-init");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        let head = sink.resume().await.unwrap();
        assert_eq!(head, ChainHead::EMPTY);

        let raw = raw_client(&url).await;
        let row = raw
            .query_one(
                "SELECT active_generation FROM kms_audit_control WHERE instance_id = $1",
                &[&instance_id],
            )
            .await
            .unwrap();
        let active: i64 = row.get(0);
        assert_eq!(
            active, 0,
            "control row must be initialized to generation 0 for a brand-new instance"
        );

        // Proven end-to-end: the guard the control row backs does not block this write.
        sink.write_event_atomic(&make_event(0, [0_u8; 32]))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_duplicate_writer_rejected_by_advisory_lock() {
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
    async fn pg_audit_write_retry_after_lost_ack_is_idempotent() {
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

    /// H1: when a lost-ack retry's slot already durably holds a *different* event from
    /// this same writer (the draft that used to target this id was abandoned, but its
    /// write actually landed), `write_event_once` must report `Resynced` onto the real
    /// stored chain head instead of misreporting a competing writer — and the original
    /// row must remain untouched (never-update contract).
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_collision_resyncs_after_lost_ack_with_different_content() {
        let instance_id = unique_instance_id("resync");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();

        let ev0 = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev0).await.unwrap();

        // The writer "forgot" ev0 succeeded (ack lost) and moved on to a different
        // draft, still targeting id=0 with the same expected prev_hash.
        let mut ev0_different = make_event(0, [0_u8; 32]);
        ev0_different.operation = "Decrypt".to_owned();
        ev0_different.row_hash = compute_row_hash(&ev0_different);
        assert_ne!(ev0_different.row_hash, ev0.row_hash);

        let outcome =
            PgAuditSink::write_event_once(&sink.pool, &instance_id, 0, &ev0_different)
                .await
                .unwrap();
        match outcome {
            WriteOutcome::Resynced(head) => {
                assert_eq!(head.next_id, 1);
                assert_eq!(head.prev_hash, ev0.row_hash);
            }
            WriteOutcome::Written => panic!("expected a resync, not a plain write"),
        }

        let reader = PgAuditReader::connect(&url).await.unwrap();
        let page = reader.events_page(&instance_id, 0, -1).await.unwrap();
        assert_eq!(page.len(), 1, "the abandoned draft must never be persisted");
        assert_eq!(
            page[0].row_hash, ev0.row_hash,
            "the original stored row must remain untouched"
        );
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
    async fn pg_audit_connect_falls_back_to_column_check_without_ddl_rights() {
        let base_url = audit_url();
        // Swap in the restricted role's credentials, keeping the same host/port/database.
        let restricted_url = base_url.replacen("kms:kms", "kms_audit_writer:writer_pw", 1);

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
    async fn pg_audit_distinct_instances_keep_independent_chains() {
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
        let events_a = reader.events_page(&id_a, 0, -1).await.unwrap();
        let events_b = reader.events_page(&id_b, 0, -1).await.unwrap();
        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 1);
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_events_page_paginates_and_terminates() {
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
        let page = reader.events_page(&instance_id, 0, -1).await.unwrap();
        assert_eq!(page.len(), 3);
        let last_id = page.last().unwrap().id;
        let next_page = reader.events_page(&instance_id, 0, last_id).await.unwrap();
        assert!(
            next_page.is_empty(),
            "paginating past the end of the chain must terminate with an empty page"
        );
    }

    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_update_and_delete_are_rejected() {
        let instance_id = unique_instance_id("no-mutate");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();
        let ev = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev).await.unwrap();

        let raw = raw_client(&url).await;

        let update_err = raw
            .execute(
                "UPDATE kms_audit_events SET username = 'mallory' WHERE instance_id = $1 AND \
                 chain_generation = 0 AND id = 0",
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
                "DELETE FROM kms_audit_events WHERE instance_id = $1 AND chain_generation = \
                 0 AND id = 0",
                &[&instance_id],
            )
            .await
            .expect_err("DELETE must be rejected by the append-only trigger");
        assert_eq!(
            delete_err.as_db_error().map(|e| e.code().code().to_owned()),
            Some("23001".to_owned())
        );
    }

    /// `TRUNCATE` fires only statement-level triggers, and `REVOKE` doesn't bind the
    /// table owner — the ordinary connecting role, per the module docs. A row-level-only
    /// guard would let `TRUNCATE` silently erase the whole table; the dedicated
    /// statement-level trigger must reject it too.
    #[tokio::test]
    #[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
    async fn pg_audit_truncate_is_rejected() {
        let instance_id = unique_instance_id("no-truncate");
        let url = audit_url();
        let mut sink = PgAuditSink::connect(&url, &instance_id).await.unwrap();
        sink.resume().await.unwrap();
        let ev = make_event(0, [0_u8; 32]);
        sink.write_event_atomic(&ev).await.unwrap();

        let raw = raw_client(&url).await;
        let truncate_err = raw
            .execute("TRUNCATE kms_audit_events", &[])
            .await
            .expect_err("TRUNCATE must be rejected by the append-only trigger");
        assert_eq!(
            truncate_err.as_db_error().map(|e| e.code().code().to_owned()),
            Some("23001".to_owned())
        );
    }
}
