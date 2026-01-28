//! OpenTelemetry metrics for the KMS server
//!
//! This module provides comprehensive metrics collection for the KMS server using
//! OpenTelemetry, which exports metrics via OTLP (gRPC) to configured backends.
//!
//! Metrics include:
//! - KMIP operation counts (total and per user)
//! - Permission grants per user
//! - Active user tracking
//! - Database operation metrics
//! - HTTP request metrics
//! - Server uptime and health metrics

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram, Meter, MeterProvider, UpDownCounter},
};
use opentelemetry_sdk::metrics::SdkMeterProvider;

use crate::{error::KmsError, result::KResult};

/// OpenTelemetry metrics for KMS operations
pub struct OtelMetrics {
    /// The meter used to create instruments
    meter: Meter,

    /// The meter provider (kept for lifecycle management)
    _meter_provider: SdkMeterProvider,

    /// Total number of KMIP operations executed
    pub kmip_operations_total: Counter<u64>,

    /// KMIP operations per user
    pub kmip_operations_per_user: Counter<u64>,

    /// Duration of KMIP operations in seconds
    pub kmip_operation_duration: Histogram<f64>,

    /// Number of permissions granted per user
    pub permissions_granted_per_user: Counter<u64>,

    /// Total number of permissions granted
    pub permissions_granted_total: Counter<u64>,

    /// Number of unique active users
    pub active_users: UpDownCounter<i64>,

    /// Track unique users (username -> last seen timestamp)
    active_users_tracker: Arc<RwLock<HashMap<String, i64>>>,

    /// Database operation counts
    pub database_operations_total: Counter<u64>,

    /// Database operation duration in seconds
    pub database_operation_duration: Histogram<f64>,

    /// HTTP requests total
    pub http_requests_total: Counter<u64>,

    /// HTTP request duration in seconds
    pub http_request_duration: Histogram<f64>,

    /// Server uptime in seconds
    pub server_uptime_seconds: Counter<u64>,

    /// Server start time (Unix timestamp) - using `UpDownCounter` for gauge behavior
    pub server_start_time: UpDownCounter<i64>,

    /// Number of errors by type
    pub errors_total: Counter<u64>,

    /// Current number of active connections
    pub active_connections: UpDownCounter<i64>,

    /// Total number of objects in the KMS
    pub kms_objects_total: UpDownCounter<i64>,

    /// Current number of active keys (absolute count from Locate responses)
    pub active_keys_count: UpDownCounter<i64>,

    /// Mirror of `active_keys_count` for tracking the last set value
    active_keys_count_value: Arc<RwLock<i64>>,

    /// Cache hit/miss statistics
    pub cache_operations_total: Counter<u64>,

    /// HSM operation counts (if HSM is enabled)
    pub hsm_operations_total: Counter<u64>,
}

impl OtelMetrics {
    /// Create a new OpenTelemetry metrics instance
    ///
    /// # Arguments
    ///
    /// * `meter_provider` - The configured `MeterProvider` with OTLP exporter
    ///
    /// # Errors
    ///
    /// Returns `KmsError` if metric creation fails
    ///
    /// # Panics
    ///
    /// May panic if system time is before `UNIX_EPOCH`
    #[allow(
        clippy::too_many_lines,
        clippy::cast_precision_loss,
        clippy::as_conversions
    )]
    pub fn new(meter_provider: SdkMeterProvider) -> KResult<Self> {
        // Get a meter from the provider - use meter() method from MeterProvider trait
        let meter = MeterProvider::meter(&meter_provider, "cosmian_kms");

        // KMIP operations total
        let kmip_operations_total = meter
            .u64_counter("kms.kmip.operations.total")
            .with_description("Total number of KMIP operations executed")
            .with_unit("{operation}")
            .build();

        // KMIP operations per user
        let kmip_operations_per_user = meter
            .u64_counter("kms.kmip.operations.per_user.total")
            .with_description("Total number of KMIP operations executed per user")
            .with_unit("{operation}")
            .build();

        // KMIP operation duration
        let kmip_operation_duration = meter
            .f64_histogram("kms.kmip.operation.duration")
            .with_description("Duration of KMIP operations in seconds")
            .with_unit("s")
            .build();

        // Permissions granted per user
        let permissions_granted_per_user = meter
            .u64_counter("kms.permissions.granted.per_user.total")
            .with_description("Total number of permissions granted per user")
            .with_unit("{permission}")
            .build();

        // Permissions granted total
        let permissions_granted_total = meter
            .u64_counter("kms.permissions.granted.total")
            .with_description("Total number of permissions granted")
            .with_unit("{permission}")
            .build();

        // Active users
        let active_users = meter
            .i64_up_down_counter("kms.active.users")
            .with_description("Number of unique active users")
            .with_unit("{user}")
            .build();

        // Database operations
        let database_operations_total = meter
            .u64_counter("kms.database.operations.total")
            .with_description("Total number of database operations")
            .with_unit("{operation}")
            .build();

        // Database operation duration
        let database_operation_duration = meter
            .f64_histogram("kms.database.operation.duration")
            .with_description("Duration of database operations in seconds")
            .with_unit("s")
            .build();

        // HTTP requests
        let http_requests_total = meter
            .u64_counter("kms.http.requests.total")
            .with_description("Total number of HTTP requests")
            .with_unit("{request}")
            .build();

        // HTTP request duration
        let http_request_duration = meter
            .f64_histogram("kms.http.request.duration")
            .with_description("Duration of HTTP requests in seconds")
            .with_unit("s")
            .build();

        // Server uptime
        let server_uptime_seconds = meter
            .u64_counter("kms.server.uptime")
            .with_description("Server uptime in seconds")
            .with_unit("s")
            .build();

        // Server start time
        let server_start_time = meter
            .i64_up_down_counter("kms.server.start_time")
            .with_description("Server start time as Unix timestamp")
            .with_unit("s")
            .build();

        // Set initial server start time
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| KmsError::ServerError(format!("System time error: {e}")))?
            .as_secs();
        // Use try_into to safely convert u64 to i64
        let start_time_i64 = i64::try_from(start_time)
            .map_err(|e| KmsError::ServerError(format!("Start time conversion error: {e}")))?;
        server_start_time.add(start_time_i64, &[]);

        // Errors total
        let errors_total = meter
            .u64_counter("kms.errors.total")
            .with_description("Total number of errors by type")
            .with_unit("{error}")
            .build();

        // Active connections
        let active_connections = meter
            .i64_up_down_counter("kms.active.connections")
            .with_description("Current number of active connections")
            .with_unit("{connection}")
            .build();

        // KMS objects
        let kms_objects_total = meter
            .i64_up_down_counter("kms.objects.total")
            .with_description("Total number of objects in the KMS")
            .with_unit("{object}")
            .build();

        // Active Keys count (absolute number of keys in Active state)
        let active_keys_count = meter
            .i64_up_down_counter("kms.keys.active.count")
            .with_description("Number of keys in Active state (absolute count based on Locate)")
            .with_unit("{key}")
            .build();
        // Force the time series to exist even when the count is 0.
        // Without at least one measurement, some backends won't expose the metric at all.
        active_keys_count.add(0, &[]);

        // Cache operations
        let cache_operations_total = meter
            .u64_counter("kms.cache.operations.total")
            .with_description("Total number of cache operations")
            .with_unit("{operation}")
            .build();

        // HSM operations
        let hsm_operations_total = meter
            .u64_counter("kms.hsm.operations.total")
            .with_description("Total number of HSM operations")
            .with_unit("{operation}")
            .build();

        Ok(Self {
            meter,
            _meter_provider: meter_provider,
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
            active_keys_count,
            active_keys_count_value: Arc::new(RwLock::new(0)),
            cache_operations_total,
            hsm_operations_total,
        })
    }

    /// Record a KMIP operation
    pub fn record_kmip_operation(&self, operation: &str, user: &str) {
        self.kmip_operations_total
            .add(1, &[KeyValue::new("operation", operation.to_owned())]);
        self.kmip_operations_per_user.add(
            1,
            &[
                KeyValue::new("user", user.to_owned()),
                KeyValue::new("operation", operation.to_owned()),
            ],
        );
        self.update_active_user(user);
    }

    /// Record KMIP operation duration
    pub fn record_kmip_operation_duration(&self, operation: &str, duration_seconds: f64) {
        self.kmip_operation_duration.record(
            duration_seconds,
            &[KeyValue::new("operation", operation.to_owned())],
        );
    }

    /// Record a permission grant
    pub fn record_permission_grant(&self, user: &str, permission_type: &str) {
        self.permissions_granted_per_user.add(
            1,
            &[
                KeyValue::new("user", user.to_owned()),
                KeyValue::new("permission_type", permission_type.to_owned()),
            ],
        );
        self.permissions_granted_total.add(1, &[]);
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

        let previous_len = tracker.len() as i64;
        tracker.insert(user.to_owned(), now);

        // Clean up users inactive for more than 1 hour
        let cutoff = now - 3600;
        tracker.retain(|_, &mut last_seen| last_seen > cutoff);

        // Update gauge - calculate the delta
        let current_len = tracker.len() as i64;
        let delta = current_len - previous_len;
        if delta != 0 {
            self.active_users.add(delta, &[]);
        }
    }

    /// Record a database operation
    pub fn record_database_operation(&self, operation: &str) {
        self.database_operations_total
            .add(1, &[KeyValue::new("operation", operation.to_owned())]);
    }

    /// Record database operation duration
    pub fn record_database_operation_duration(&self, operation: &str, duration_seconds: f64) {
        self.database_operation_duration.record(
            duration_seconds,
            &[KeyValue::new("operation", operation.to_owned())],
        );
    }

    /// Record an HTTP request
    pub fn record_http_request(&self, method: &str, path: &str, status: &str) {
        self.http_requests_total.add(
            1,
            &[
                KeyValue::new("method", method.to_owned()),
                KeyValue::new("path", path.to_owned()),
                KeyValue::new("status", status.to_owned()),
            ],
        );
    }

    /// Record HTTP request duration
    pub fn record_http_request_duration(&self, method: &str, path: &str, duration_seconds: f64) {
        self.http_request_duration.record(
            duration_seconds,
            &[
                KeyValue::new("method", method.to_owned()),
                KeyValue::new("path", path.to_owned()),
            ],
        );
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str) {
        self.errors_total
            .add(1, &[KeyValue::new("error_type", error_type.to_owned())]);
    }

    /// Increment active connections
    pub fn increment_active_connections(&self) {
        self.active_connections.add(1, &[]);
    }

    /// Decrement active connections
    pub fn decrement_active_connections(&self) {
        self.active_connections.add(-1, &[]);
    }

    /// Update object count for a specific type
    pub fn update_object_count(&self, object_type: &str, count: f64) {
        // For UpDownCounter, we need to track the delta
        // This is a simplified implementation - in production you might want to track previous values
        // Round the f64 to avoid truncation issues
        #[allow(clippy::cast_possible_wrap)]
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::as_conversions)]
        let count_i64 = count.round() as i64;
        self.kms_objects_total.add(
            count_i64,
            &[KeyValue::new("object_type", object_type.to_owned())],
        );
    }

    /// Set the current active keys count from an absolute Locate response
    ///
    /// OTLP instrument is an `UpDownCounter`, so we compute the delta from
    /// the previously observed value and add it. The last value is mirrored
    /// internally for subsequent updates and optional inspection.
    pub fn update_active_keys_count(&self, absolute_count: i64) {
        if let Ok(mut last) = self.active_keys_count_value.write() {
            let delta = absolute_count - *last;
            if delta != 0 {
                self.active_keys_count.add(delta, &[]);
                *last = absolute_count;
            }
        }
    }

    /// Record cache operation
    pub fn record_cache_operation(&self, operation: &str, result: &str) {
        self.cache_operations_total.add(
            1,
            &[
                KeyValue::new("operation", operation.to_owned()),
                KeyValue::new("result", result.to_owned()),
            ],
        );
    }

    /// Record HSM operation
    pub fn record_hsm_operation(&self, operation: &str, hsm_model: &str) {
        self.hsm_operations_total.add(
            1,
            &[
                KeyValue::new("operation", operation.to_owned()),
                KeyValue::new("hsm_model", hsm_model.to_owned()),
            ],
        );
    }

    /// Update server uptime (should be called periodically)
    pub fn update_uptime(&self) {
        self.server_uptime_seconds.add(1, &[]);
    }

    /// Get a reference to the meter for custom metrics
    #[must_use]
    pub const fn meter(&self) -> &Meter {
        &self.meter
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

    fn create_test_meter_provider() -> SdkMeterProvider {
        // Create a simple no-op meter provider for testing
        // We don't need to actually export metrics in tests
        opentelemetry_sdk::metrics::SdkMeterProvider::builder().build()
    }

    #[test]
    fn test_metrics_creation() {
        let meter_provider = create_test_meter_provider();
        let _metrics = OtelMetrics::new(meter_provider).expect("Failed to create metrics");
    }

    #[test]
    fn test_kmip_operation_recording() {
        let meter_provider = create_test_meter_provider();
        let metrics = OtelMetrics::new(meter_provider).expect("Failed to create metrics");

        metrics.record_kmip_operation("Create", "user1");
        metrics.record_kmip_operation("Get", "user1");
        metrics.record_kmip_operation("Create", "user2");

        // Metrics are recorded, actual verification would require checking the exporter
    }

    #[test]
    fn test_permission_recording() {
        let meter_provider = create_test_meter_provider();
        let metrics = OtelMetrics::new(meter_provider).expect("Failed to create metrics");

        metrics.record_permission_grant("user1", "read");
        metrics.record_permission_grant("user1", "write");
        metrics.record_permission_grant("user2", "read");
    }

    #[test]
    fn test_active_users_tracking() {
        let meter_provider = create_test_meter_provider();
        let metrics = OtelMetrics::new(meter_provider).expect("Failed to create metrics");

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
    }

    #[test]
    fn test_operation_duration() {
        let meter_provider = create_test_meter_provider();
        let metrics = OtelMetrics::new(meter_provider).expect("Failed to create metrics");

        metrics.record_kmip_operation_duration("Create", 0.123);
        metrics.record_database_operation_duration("insert", 0.045);
    }
}
