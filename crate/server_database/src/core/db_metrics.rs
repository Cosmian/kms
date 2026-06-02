//! Recorder trait for database operation metrics.
//!
//! This module defines [`DbMetricsRecorder`], the only interface between
//! `cosmian_kms_server_database` and the OTEL layer.  The trait is
//! implemented by the server crate's `OtelMetrics` type and injected into
//! [`super::Database`] at construction time, keeping the dependency arrow
//! strictly `server → server_database → interfaces` with no reverse edge.

use super::MainDbKind;

/// Observer interface for recording database operation metrics.
///
/// Implementors are expected to be cheap to clone (typically wrapping an
/// `Arc`) and to forward measurements to an OpenTelemetry counter and
/// histogram.  The call happens **after** each facade method returns, so
/// the `outcome` is always known at the call site.
pub trait DbMetricsRecorder: Send + Sync {
    /// Record a completed database operation.
    ///
    /// # Arguments
    /// * `operation`        – low-cardinality label: `"create"`, `"retrieve"`,
    ///   `"retrieve_tags"`, `"update_object"`, `"update_state"`, `"delete"`,
    ///   `"find"`, `"atomic"`, `"list_uids_for_tags"`, `"is_object_owned_by"`,
    ///   `"list_user_ops_granted"`, `"list_object_ops_granted"`,
    ///   `"grant_ops"`, `"remove_ops"`, `"list_user_ops_on_object"`
    /// * `backend`          – typed backend identifier; `as_str()` is called
    ///   inside the implementor so callers cannot pass an arbitrary string.
    ///   Adding a new [`MainDbKind`] variant is a compile error unless
    ///   `MainDbKind::as_str` is updated, which keeps the label set in sync.
    /// * `outcome`          – `"success"` or `"error"`
    /// * `duration_seconds` – wall-clock duration of the operation in seconds
    fn record_operation(
        &self,
        operation: &str,
        backend: MainDbKind,
        outcome: &str,
        duration_seconds: f64,
    );
}
