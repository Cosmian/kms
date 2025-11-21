//! Metrics collection for the KMS server
//!
//! This module provides comprehensive metrics collection for the KMS server including:
//! - KMIP operation counts (total and per user)
//! - Permission grants per user
//! - Active user tracking
//! - Database operation metrics
//! - HTTP request metrics
//! - Server uptime and health metrics
//!
//! Metrics are exposed in Prometheus text format on the /metrics endpoint
//! and scraped by the OpenTelemetry Collector for export to OTLP backends.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry,
    TextEncoder,
};

use crate::{error::KmsError, result::KResult};

/// Metrics registry and collectors for the KMS server
pub struct Metrics {
    /// The Prometheus registry
    registry: Registry,

    /// Total number of KMIP operations executed
    pub kmip_operations_total: CounterVec,

    /// KMIP operations per user
    pub kmip_operations_per_user: CounterVec,

    /// Duration of KMIP operations in seconds
    pub kmip_operation_duration: HistogramVec,

    /// Number of permissions granted per user
    pub permissions_granted_per_user: CounterVec,

    /// Total number of permissions granted
    pub permissions_granted_total: Counter,

    /// Number of unique active users
    pub active_users: Gauge,

    /// Track unique users (username -> last seen timestamp)
    active_users_tracker: Arc<RwLock<HashMap<String, i64>>>,

    /// Database operation counts
    pub database_operations_total: CounterVec,

    /// Database operation duration in seconds
    pub database_operation_duration: HistogramVec,

    /// HTTP requests total
    pub http_requests_total: CounterVec,

    /// HTTP request duration in seconds
    pub http_request_duration: HistogramVec,

    /// Server uptime in seconds
    pub server_uptime_seconds: Counter,

    /// Server start time (Unix timestamp)
    pub server_start_time: Gauge,

    /// Number of errors by type
    pub errors_total: CounterVec,

    /// Current number of active connections
    pub active_connections: Gauge,

    /// Total number of objects in the KMS
    pub kms_objects_total: GaugeVec,

    /// Cache hit/miss statistics
    pub cache_operations_total: CounterVec,

    /// HSM operation counts (if HSM is enabled)
    pub hsm_operations_total: CounterVec,
}

impl Metrics {
    /// Create a new metrics instance
    ///
    /// # Errors
    ///
    /// Returns `KmsError` if metric registration fails
    ///
    /// # Panics
    ///
    /// May panic if system time is before `UNIX_EPOCH`
    #[allow(clippy::expect_used, clippy::as_conversions)]
    pub fn new() -> KResult<Self> {
        let registry = Registry::new();

        // Helper to convert prometheus errors to KmsError
        let map_err = |e: prometheus::Error| -> KmsError {
            KmsError::ServerError(format!("Metrics error: {e}"))
        };

        // KMIP operations total
        let kmip_operations_total = CounterVec::new(
            Opts::new(
                "kms_kmip_operations_total",
                "Total number of KMIP operations executed",
            ),
            &["operation"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(kmip_operations_total.clone()))
            .map_err(map_err)?;

        // KMIP operations per user
        let kmip_operations_per_user = CounterVec::new(
            Opts::new(
                "kms_kmip_operations_per_user_total",
                "Total number of KMIP operations executed per user",
            ),
            &["user", "operation"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(kmip_operations_per_user.clone()))
            .map_err(map_err)?;

        // KMIP operation duration
        let kmip_operation_duration = HistogramVec::new(
            HistogramOpts::new(
                "kms_kmip_operation_duration_seconds",
                "Duration of KMIP operations in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["operation"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(kmip_operation_duration.clone()))
            .map_err(map_err)?;

        // Permissions granted per user
        let permissions_granted_per_user = CounterVec::new(
            Opts::new(
                "kms_permissions_granted_per_user_total",
                "Total number of permissions granted per user",
            ),
            &["user", "permission_type"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(permissions_granted_per_user.clone()))
            .map_err(map_err)?;

        // Permissions granted total
        let permissions_granted_total = Counter::new(
            "kms_permissions_granted_total",
            "Total number of permissions granted",
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(permissions_granted_total.clone()))
            .map_err(map_err)?;

        // Active users gauge
        let active_users =
            Gauge::new("kms_active_users", "Number of unique active users").map_err(map_err)?;
        registry
            .register(Box::new(active_users.clone()))
            .map_err(map_err)?;

        // Database operations
        let database_operations_total = CounterVec::new(
            Opts::new(
                "kms_database_operations_total",
                "Total number of database operations",
            ),
            &["operation"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(database_operations_total.clone()))
            .map_err(map_err)?;

        // Database operation duration
        let database_operation_duration = HistogramVec::new(
            HistogramOpts::new(
                "kms_database_operation_duration_seconds",
                "Duration of database operations in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["operation"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(database_operation_duration.clone()))
            .map_err(map_err)?;

        // HTTP requests
        let http_requests_total = CounterVec::new(
            Opts::new("kms_http_requests_total", "Total number of HTTP requests"),
            &["method", "path", "status"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(http_requests_total.clone()))
            .map_err(map_err)?;

        // HTTP request duration
        let http_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "kms_http_request_duration_seconds",
                "Duration of HTTP requests in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "path"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(http_request_duration.clone()))
            .map_err(map_err)?;

        // Server uptime
        let server_uptime_seconds =
            Counter::new("kms_server_uptime_seconds", "Server uptime in seconds")
                .map_err(map_err)?;
        registry
            .register(Box::new(server_uptime_seconds.clone()))
            .map_err(map_err)?;

        // Server start time
        let server_start_time = Gauge::new(
            "kms_server_start_time",
            "Server start time as Unix timestamp",
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(server_start_time.clone()))
            .map_err(map_err)?;
        #[allow(clippy::cast_precision_loss)]
        {
            let start_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| KmsError::ServerError(format!("System time error: {e}")))?
                .as_secs() as f64;
            server_start_time.set(start_time);
        }

        // Errors total
        let errors_total = CounterVec::new(
            Opts::new("kms_errors_total", "Total number of errors by type"),
            &["error_type"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(errors_total.clone()))
            .map_err(map_err)?;

        // Active connections
        let active_connections = Gauge::new(
            "kms_active_connections",
            "Current number of active connections",
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(active_connections.clone()))
            .map_err(map_err)?;

        // KMS objects
        let kms_objects_total = GaugeVec::new(
            Opts::new("kms_objects_total", "Total number of objects in the KMS"),
            &["object_type"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(kms_objects_total.clone()))
            .map_err(map_err)?;

        // Cache operations
        let cache_operations_total = CounterVec::new(
            Opts::new(
                "kms_cache_operations_total",
                "Total number of cache operations",
            ),
            &["operation", "result"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(cache_operations_total.clone()))
            .map_err(map_err)?;

        // HSM operations
        let hsm_operations_total = CounterVec::new(
            Opts::new("kms_hsm_operations_total", "Total number of HSM operations"),
            &["operation", "hsm_model"],
        )
        .map_err(map_err)?;
        registry
            .register(Box::new(hsm_operations_total.clone()))
            .map_err(map_err)?;

        Ok(Self {
            registry,
            kmip_operations_total,
            kmip_operations_per_user,
            kmip_operation_duration,
            permissions_granted_per_user,
            permissions_granted_total,
            active_users,
            active_users_tracker: Arc::new(RwLock::new(HashMap::with_capacity(100))),
            database_operations_total,
            database_operation_duration,
            http_requests_total,
            http_request_duration,
            server_uptime_seconds,
            server_start_time,
            errors_total,
            active_connections,
            kms_objects_total,
            cache_operations_total,
            hsm_operations_total,
        })
    }

    /// Record a KMIP operation
    pub fn record_kmip_operation(&self, operation: &str, user: &str) {
        self.kmip_operations_total
            .with_label_values(&[operation])
            .inc();
        self.kmip_operations_per_user
            .with_label_values(&[user, operation])
            .inc();
        self.update_active_user(user);
    }

    /// Record KMIP operation duration
    pub fn record_kmip_operation_duration(&self, operation: &str, duration_seconds: f64) {
        self.kmip_operation_duration
            .with_label_values(&[operation])
            .observe(duration_seconds);
    }

    /// Record a permission grant
    pub fn record_permission_grant(&self, user: &str, permission_type: &str) {
        self.permissions_granted_per_user
            .with_label_values(&[user, permission_type])
            .inc();
        self.permissions_granted_total.inc();
    }

    /// Update active user tracking
    ///
    /// # Panics
    ///
    /// Panics if system time is before `UNIX_EPOCH` or lock is poisoned
    #[allow(
        clippy::cast_possible_wrap,
        clippy::expect_used,
        clippy::as_conversions
    )]
    pub fn update_active_user(&self, user: &str) {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before UNIX_EPOCH")
            .as_secs() as i64;

        let mut tracker = self
            .active_users_tracker
            .write()
            .expect("Active users tracker lock poisoned");
        tracker.insert(user.to_owned(), now);

        // Clean up users inactive for more than 1 hour
        let cutoff = now - 3600;
        tracker.retain(|_, &mut last_seen| last_seen > cutoff);

        // Update gauge
        #[allow(clippy::cast_precision_loss)]
        self.active_users.set(tracker.len() as f64);
    }

    /// Record a database operation
    pub fn record_database_operation(&self, operation: &str) {
        self.database_operations_total
            .with_label_values(&[operation])
            .inc();
    }

    /// Record database operation duration
    pub fn record_database_operation_duration(&self, operation: &str, duration_seconds: f64) {
        self.database_operation_duration
            .with_label_values(&[operation])
            .observe(duration_seconds);
    }

    /// Record an HTTP request
    pub fn record_http_request(&self, method: &str, path: &str, status: &str) {
        self.http_requests_total
            .with_label_values(&[method, path, status])
            .inc();
    }

    /// Record HTTP request duration
    pub fn record_http_request_duration(&self, method: &str, path: &str, duration_seconds: f64) {
        self.http_request_duration
            .with_label_values(&[method, path])
            .observe(duration_seconds);
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.with_label_values(&[error_type]).inc();
    }

    /// Increment active connections
    pub fn increment_active_connections(&self) {
        self.active_connections.inc();
    }

    /// Decrement active connections
    pub fn decrement_active_connections(&self) {
        self.active_connections.dec();
    }

    /// Update object count for a specific type
    pub fn update_object_count(&self, object_type: &str, count: f64) {
        self.kms_objects_total
            .with_label_values(&[object_type])
            .set(count);
    }

    /// Record cache operation
    pub fn record_cache_operation(&self, operation: &str, result: &str) {
        self.cache_operations_total
            .with_label_values(&[operation, result])
            .inc();
    }

    /// Record HSM operation
    pub fn record_hsm_operation(&self, operation: &str, hsm_model: &str) {
        self.hsm_operations_total
            .with_label_values(&[operation, hsm_model])
            .inc();
    }

    /// Update server uptime (should be called periodically)
    pub fn update_uptime(&self) {
        self.server_uptime_seconds.inc();
    }

    /// Gather and encode all metrics in Prometheus text format
    pub fn gather_metrics(&self) -> KResult<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| KmsError::ServerError(format!("Failed to encode metrics: {e}")))?;
        String::from_utf8(buffer)
            .map_err(|e| KmsError::ServerError(format!("Failed to convert metrics to UTF-8: {e}")))
    }

    /// Get a reference to the registry for custom metrics
    #[must_use]
    pub const fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl Default for Metrics {
    /// Create default metrics
    ///
    /// # Panics
    ///
    /// Panics if metric registration fails (should never happen in normal operation)
    #[allow(clippy::expect_used)]
    fn default() -> Self {
        Self::new().expect("Failed to create Metrics")
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new().expect("Failed to create metrics");
        metrics.gather_metrics().expect("Failed to gather metrics");
    }

    #[test]
    fn test_kmip_operation_recording() {
        let metrics = Metrics::new().expect("Failed to create metrics");
        metrics.record_kmip_operation("Create", "user1");
        metrics.record_kmip_operation("Get", "user1");
        metrics.record_kmip_operation("Create", "user2");

        let output = metrics.gather_metrics().expect("Failed to gather metrics");
        assert!(output.contains("kms_kmip_operations_total"));
        assert!(output.contains("kms_kmip_operations_per_user_total"));
    }

    #[test]
    fn test_permission_recording() {
        let metrics = Metrics::new().expect("Failed to create metrics");
        metrics.record_permission_grant("user1", "read");
        metrics.record_permission_grant("user1", "write");
        metrics.record_permission_grant("user2", "read");

        let output = metrics.gather_metrics().expect("Failed to gather metrics");
        assert!(output.contains("kms_permissions_granted_per_user_total"));
        assert!(output.contains("kms_permissions_granted_total"));
    }

    #[test]
    fn test_active_users_tracking() {
        let metrics = Metrics::new().expect("Failed to create metrics");
        metrics.update_active_user("user1");
        metrics.update_active_user("user2");
        metrics.update_active_user("user3");

        assert_eq!(
            metrics
                .active_users_tracker
                .read()
                .expect("Failed to lock tracker")
                .len(),
            3
        );
        assert_eq!(metrics.active_users.get() as usize, 3);
    }

    #[test]
    fn test_operation_duration() {
        let metrics = Metrics::new().expect("Failed to create metrics");
        metrics.record_kmip_operation_duration("Create", 0.123);
        metrics.record_database_operation_duration("insert", 0.045);

        let output = metrics.gather_metrics().expect("Failed to gather metrics");
        assert!(output.contains("kms_kmip_operation_duration_seconds"));
        assert!(output.contains("kms_database_operation_duration_seconds"));
    }
}
