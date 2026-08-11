//! Retry primitives for transient `PostgreSQL` errors (deadlocks, serialization failures, and
//! connection failures during failover).
//!
//! Shared by the object store's `pg_retry!`/`pg_retry_tx!` macros (`pgsql.rs`) and the audit
//! backend's `PgAuditSink` (`stores/audit/pgsql.rs`), so a failover looks the same to the audit
//! log as it does to the key store — an operator tuning one is tuning both.

use std::{fmt::Display, future::Future, time::Duration};

use cosmian_logger::reexport::tracing;

/// Maximum number of attempts for a transient `PostgreSQL` error before giving up.
pub(crate) const PG_MAX_RETRIES: u32 = 6;

pub(crate) fn is_pg_retryable_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    // Deadlock / serialization (SQLSTATE 40P01, 40001)
    lower.contains("deadlock detected")
        || lower.contains("40p01")
        || lower.contains("serialization failure")
        || lower.contains("40001")
        // Connection errors (failover / network)
        || lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
        || lower.contains("server closed the connection unexpectedly")
        || lower.contains("terminating connection")
        || lower.contains("could not connect to server")
        || lower.contains("08003") // SQLSTATE connection_does_not_exist
        || lower.contains("08006") // SQLSTATE connection_failure
        || lower.contains("57p01") // SQLSTATE admin_shutdown
        || lower.contains("08001") // SQLSTATE connection_exception
        || lower.contains("08004") // SQLSTATE connection_rejected
        || lower.contains("57p02") // SQLSTATE crash_shutdown
        || lower.contains("57p03") // SQLSTATE cannot_connect_now
}

pub(crate) fn pg_retry_backoff_ms(attempt: u32) -> u64 {
    let cap = attempt.min(PG_MAX_RETRIES);
    50_u64 * (1_u64 << cap)
}

/// Runs `op` until it succeeds, hits a non-retryable error, or exhausts [`PG_MAX_RETRIES`],
/// sleeping [`pg_retry_backoff_ms`] between attempts.
///
/// Shares its retry classification with the object store's `pg_retry!` macro so a failover looks
/// the same to the audit log as it does to the key store. (`pg_retry!` itself is not reusable
/// here: it is hard-wired to `InterfaceResult` and to taking a fresh pooled client per attempt.
/// Folding it onto this helper is tracked in `.agents/future_work.md`.)
pub(crate) async fn retry_transient<T, E, F, Fut>(mut op: F) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Display,
{
    let mut attempt = 0_u32;
    loop {
        match op(attempt).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES {
                    let delay_ms = pg_retry_backoff_ms(attempt);
                    tracing::warn!(
                        attempt,
                        delay_ms,
                        error = %e,
                        "PostgreSQL retryable error — retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    attempt += 1;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_pg_retryable_error, pg_retry_backoff_ms};

    #[test]
    fn test_pg_retry_backoff_ms() {
        assert_eq!(pg_retry_backoff_ms(0), 50); // 50 * 2^0
        assert_eq!(pg_retry_backoff_ms(1), 100); // 50 * 2^1
        assert_eq!(pg_retry_backoff_ms(5), 1600); // 50 * 2^5
        assert_eq!(pg_retry_backoff_ms(6), 3200); // 50 * 2^6 (capped at PG_MAX_RETRIES)
        assert_eq!(pg_retry_backoff_ms(100), 3200); // capped
    }

    #[test]
    fn test_is_pg_retryable_error_deadlock_serialization() {
        assert!(is_pg_retryable_error("ERROR: deadlock detected"));
        assert!(is_pg_retryable_error("SQLSTATE 40P01"));
        assert!(is_pg_retryable_error("serialization failure"));
        assert!(is_pg_retryable_error("SQLSTATE 40001"));
    }

    #[test]
    fn test_is_pg_retryable_error_connection() {
        assert!(is_pg_retryable_error("connection refused"));
        assert!(is_pg_retryable_error("connection reset by peer"));
        assert!(is_pg_retryable_error("connection closed"));
        assert!(is_pg_retryable_error("broken pipe"));
        assert!(is_pg_retryable_error(
            "server closed the connection unexpectedly"
        ));
        assert!(is_pg_retryable_error(
            "terminating connection due to administrator command"
        ));
        assert!(is_pg_retryable_error("could not connect to server"));
    }

    #[test]
    fn test_is_pg_retryable_error_sqlstate_codes() {
        assert!(is_pg_retryable_error("SQLSTATE 08001"));
        assert!(is_pg_retryable_error("SQLSTATE 08003"));
        assert!(is_pg_retryable_error("SQLSTATE 08004"));
        assert!(is_pg_retryable_error("SQLSTATE 08006"));
        assert!(is_pg_retryable_error("SQLSTATE 57P01"));
        assert!(is_pg_retryable_error("SQLSTATE 57P02"));
        assert!(is_pg_retryable_error("SQLSTATE 57P03"));
    }

    #[test]
    fn test_is_pg_retryable_error_case_insensitive() {
        assert!(is_pg_retryable_error("DEADLOCK DETECTED"));
        assert!(is_pg_retryable_error("Connection Refused"));
    }

    #[test]
    fn test_is_pg_retryable_error_substring_match() {
        assert!(is_pg_retryable_error(
            "error connecting: SQLSTATE 08001 connection exception"
        ));
        assert!(is_pg_retryable_error(
            "db error: ERROR: deadlock detected while waiting for lock"
        ));
    }

    #[test]
    fn test_is_pg_retryable_error_non_retryable() {
        assert!(!is_pg_retryable_error("unique constraint violation"));
        assert!(!is_pg_retryable_error("syntax error"));
        assert!(!is_pg_retryable_error("permission denied"));
        assert!(!is_pg_retryable_error(""));
    }
}
