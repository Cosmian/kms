//! The `AuditSink` trait: a durable destination for finalised audit events.
//!
//! Implemented by each backend that wants to persist the audit hash chain. A sink never
//! assigns ids and never computes hashes — it persists what it is given, in the order it
//! is given, and reports where the chain left off so the writer can resume it. Backends
//! are interchangeable at the trait boundary: a chain started on one backend can be
//! verified after export from another, because both encode the same [`AuditEvent`] and
//! the same canonical hash (see `cosmian_kms_access::audit::canonical_bytes`).
//!
//! # Recovery policy is per-backend, not part of this contract
//!
//! [`AuditSink::resume`] does not mandate a single recovery policy, but every backend is
//! expected to always start rather than fail closed on **content** corruption (a tampered
//! or malformed row) — see ADR-0006. A backend whose storage can be torn mid-write (an
//! appended file, killed mid-`fsync`) recovers a trustworthy prefix and truncates the
//! rest; a backend whose writes are atomic (a single `INSERT`) has no torn-write case and
//! instead seals the corrupted evidence aside and starts a fresh chain. Only truly
//! operational faults — connectivity, permissions, lock contention, a failure to persist
//! the recovery evidence itself — may still abort startup. Document the chosen mechanics
//! on the implementing type, not here.

use async_trait::async_trait;
use cosmian_kms_access::audit::AuditEvent;

use crate::InterfaceResult;

/// Why a stored/recovered row failed content verification and triggered seal-and-roll
/// recovery. Shared by every `AuditSink` backend so file and database recovery emit the
/// same diagnostic vocabulary in `audit:reanchor` details and error logs. Reason strings
/// are diagnostic only — never an input to a row's own hash — so backends may adopt or
/// refine this vocabulary without affecting hash-chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealReason {
    /// A complete, well-formed row whose `row_hash` doesn't match its own bytes.
    HashMismatch,
    /// A row that verifies on its own but does not chain to its predecessor.
    BrokenLink,
    /// Bytes/columns that don't decode as an `AuditEvent` at all.
    Unparseable,
    /// A valid, verified row whose `id` is `i64::MAX` — continuing the chain in place
    /// would overflow the next id.
    IdOverflow,
}

impl SealReason {
    /// Stable diagnostic string stored in recovery `details` and error logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash_mismatch",
            Self::BrokenLink => "broken_link",
            Self::Unparseable => "unparseable",
            Self::IdOverflow => "id_overflow",
        }
    }
}

/// Position of the audit hash chain: the id to assign to the next event, and the
/// `row_hash` of the last durably persisted one.
#[derive(Debug, Clone, Copy)]
pub struct ChainHead {
    pub next_id: i64,
    pub prev_hash: [u8; 32],
}

impl ChainHead {
    /// Seed for an empty chain: the first event gets id 0 and an all-zeros `prev_hash`.
    pub const EMPTY: Self = Self {
        next_id: 0,
        prev_hash: [0_u8; 32],
    };
}

/// A durable destination for finalised audit events.
///
/// # Contract
/// * `write_event_atomic` : on `Ok` the event is durable; on `Err` nothing was
///   persisted. The writer relies on this — a failed write does not advance
///   `next_id`/`prev_hash`. This ensures that a half-written row does not silently fork the chain.
/// * A sink **must never update or delete** a previously written event.
#[async_trait]
pub trait AuditSink: Send {
    /// Short sink name for log messages: `"file"`, `"postgres"`.
    fn name(&self) -> &'static str;

    /// Reads the chain head so the writer can resume an existing log. Called exactly
    /// once, before any `write_event_atomic`.
    ///
    /// Recovery policy on a corrupted or unreadable tail is entirely up to the
    /// implementation — see the module docs.
    ///
    /// # Errors
    /// Returns an error when the tail cannot be read, or when the implementation's own
    /// recovery policy decides the chain must not be resumed as-is.
    async fn resume(&mut self) -> InterfaceResult<ChainHead>;

    /// Durably persists one finalised event.
    ///
    /// # Errors
    /// Returns an error when the event could not be persisted. On error, the caller must
    /// not consider the event committed (see the trait-level contract).
    async fn write_event_atomic(&mut self, event: &AuditEvent) -> InterfaceResult<()>;

    /// Whether the sink is currently refusing new writes — e.g. a configured on-disk
    /// size cap has been reached. Checked by the writer loop **before** every write; when
    /// `true` the event is silently skipped without ever calling [`Self::write_event_atomic`],
    /// exactly like a channel-capacity drop.
    ///
    /// Defaults to `false`: most backends have no such concept. A backend that does
    /// (only the file backend, today) updates its own internal state after each write
    /// and reports it here instead of returning an error from `write_event_atomic` — an error
    /// there would be logged per rejected event; this path is a silent, rate-limited
    /// skip owned entirely by the sink.
    fn is_write_capacity_exceeded(&self) -> bool {
        false
    }

    /// Called once when the writer loop exits (channel closed on graceful shutdown).
    ///
    /// # Errors
    /// Returns an error if final synchronisation fails; the writer logs it and exits
    /// regardless.
    async fn final_sync(&mut self) -> InterfaceResult<()> {
        Ok(())
    }
}
