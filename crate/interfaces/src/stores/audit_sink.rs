//! The `AuditSink` trait: a durable destination for finalised audit events.
//!
//! Should be implemented by each backend that wants to serve as an audit sink.
//! A sink never assigns ids and never computes hashes, it persists what it is given, in the order it is given. The backends are interchangeable. **A chain started on one backend can be
//! verified after export from another**.

use async_trait::async_trait;
use cosmian_kms_access::audit::AuditEvent;

use crate::InterfaceResult;

/// Position of the audit hash chain: the id to assign to the next event, and the `row_hash` of
/// the last durably persisted one.
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
/// * `write_event` **must be atomic**: on `Ok` the event is durable; on `Err` nothing was
///   persisted. The writer relies on this — a failed write does not advance `next_id`/`prev_hash`,
///   so a half-written row would silently fork the chain.
/// * A sink **must never update or delete** a previously written event.
#[async_trait]
pub trait AuditSink: Send {
    /// Short sink name for log messages: `"file"`, `"postgres"`.
    fn name(&self) -> &'static str;

    /// Reads the chain head so the writer can resume an existing log. Called exactly once,
    /// before any `write_event`.
    ///
    /// # Errors
    /// Returns an error when the tail cannot be read, or when the last persisted event fails its
    /// own `verify_event` check — the server must refuse to start rather than fork the chain onto
    /// a corrupted or tampered seed.
    async fn resume(&mut self) -> InterfaceResult<ChainHead>;

    /// Durably persists one finalised event.
    ///
    /// # Errors
    /// Returns an error when the event could not be persisted. On error, the caller must not
    /// consider the event committed (see the trait-level contract).
    async fn write_event(&mut self, event: &AuditEvent) -> InterfaceResult<()>;

    /// Whether a write failure that survived the sink's own retries should stop the server rather
    /// than be logged and skipped.
    ///
    /// Defaults to `true`: losing the audit trail defeats the purpose of having enabled it.
    /// `FileSink` overrides this to `false` to preserve the behaviour shipped with the original
    /// file-only backend, where a failed file write is logged, the chain slot is reused, and the
    /// server keeps serving.
    ///
    /// Takes no error argument on purpose: neither implementation varies its answer per error, and
    /// a parameter no caller reads is a knob that invites inconsistent policy later.
    fn write_failure_is_fatal(&self) -> bool {
        true
    }

    /// Called once when the writer loop exits (channel closed on graceful shutdown).
    ///
    /// # Errors
    /// Returns an error if final synchronisation fails; the writer logs it and exits regardless.
    async fn final_sync(&mut self) -> InterfaceResult<()> {
        Ok(())
    }
}
