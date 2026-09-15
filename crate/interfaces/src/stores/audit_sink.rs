//! Durable storage interface for finalised audit events.
//!
//! Each backend owns its recovery policy; the writer owns ids and hashes.

use async_trait::async_trait;
use cosmian_kms_access::audit::AuditEvent;

use crate::InterfaceResult;

/// Position from which the writer resumes an audit hash chain.
#[derive(Debug, Clone, Copy)]
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

/// A durable destination for finalised audit events.
///
/// # Contract
/// * On `write_event_atomic` success, the event is durable. On error, nothing is persisted.
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
    async fn write_event_atomic(&mut self, event: &AuditEvent) -> InterfaceResult<()>;

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
