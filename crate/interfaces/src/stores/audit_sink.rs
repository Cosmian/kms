//! Durable storage interface for finalised audit events.
//!
//! Implemented by each backend that wants to persist the audit hash chain. A sink never
//! assigns ids and never computes hashes — it persists what it is given, in the order it
//! is given, and reports where the chain left off so the writer can resume it. Backends
//! are interchangeable at the trait boundary for the base [`AuditEvent`] fields: a chain
//! started on one backend can be verified after export from another, because both encode
//! the same fields and the same canonical hash (see
//! `cosmian_kms_access::audit::canonical_bytes`). This does **not** extend to a recovery
//! event's `details` payload — the JSON shape a backend records there (e.g. a file
//! backend's sealed-file name and SHA-256 vs. a database backend's evidence digest) is
//! backend-specific and needs a backend-aware verifier; see the implementing type's own
//! documentation for its `details` schema.
//!
//! # Recovery policy is per-backend, not part of this contract
//!
//! [`AuditSink::resume`] does not mandate a single recovery policy, but every backend is
//! expected to always start rather than fail closed on **content** corruption (a tampered
//! or malformed row) (see ADR-0006). A backend whose storage can be torn mid-write (an
//! appended file, killed mid-`fsync`) recovers a trustworthy prefix and truncates the
//! rest; a backend whose writes are atomic (a single `INSERT`) has no torn-write case and
//! instead seals the corrupted evidence aside and starts a fresh chain. Only truly
//! operational faults (connectivity, permissions, lock contention, a failure to persist
//! the recovery evidence itself) may still abort startup. Document the chosen mechanics
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
    Unparsable,
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
            Self::Unparsable => "unparsable",
            Self::IdOverflow => "id_overflow",
        }
    }
}

/// Position of the audit hash chain: the id to assign to the next event, and the
/// `row_hash` of the last durably persisted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainHead {
    pub next_id: i64,
    pub prev_hash: [u8; 32],
}

impl ChainHead {
    /// Chain head before the first event.
    pub const EMPTY: Self = Self {
        next_id: 0,
        prev_hash: [0_u8; 32],
    };
}

/// Outcome of [`AuditSink::write_event_atomic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The event was durably written at the position it was given.
    Written,
    /// The event was not written because it would reach the sink's capacity.
    /// The caller must write a terminal event at the same chain position.
    CapacityReached,
    /// The requested slot was already durably occupied by a valid link in this same
    /// chain — see the implementing backend for when this can happen (e.g. a prior
    /// write whose acknowledgement was lost). The caller must retry the *same* draft
    /// at the returned chain head instead of advancing past it or dropping it.
    Resynced(ChainHead),
}

/// A durable destination for finalised audit events.
///
/// # Contract
/// * [`WriteOutcome::Written`] means the event is durable at the given position.
///   [`WriteOutcome::CapacityReached`] and [`WriteOutcome::Resynced`] require the caller
///   to retry as documented. On error, nothing is persisted.
/// * A sink **must never update or delete** a previously written event.
#[async_trait]
pub trait AuditSink: Send {
    /// Short sink name for log messages: `"file"`, `"postgres"`.
    fn name(&self) -> &'static str;

    /// Recovers the backend and returns the chain head.
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
    async fn write_event_atomic(&mut self, event: &AuditEvent) -> InterfaceResult<WriteOutcome>;

    /// Whether the writer should drop events without calling
    /// [`Self::write_event_atomic`].
    fn is_write_capacity_exceeded(&self) -> bool {
        false
    }

    /// Performs backend-specific shutdown synchronisation.
    ///
    /// # Errors
    /// Returns an error if synchronisation fails.
    async fn final_sync(&mut self) -> InterfaceResult<()> {
        Ok(())
    }
}
