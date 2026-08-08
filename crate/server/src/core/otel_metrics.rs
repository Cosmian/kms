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

use std::sync::Arc;

use cosmian_kms_server_database::{DbMetricsRecorder, MainDbKind};
use dashmap::DashMap;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Gauge, Histogram, Meter, MeterProvider, UpDownCounter},
};
use opentelemetry_sdk::metrics::SdkMeterProvider;

use crate::{error::KmsError, result::KResult};

/// Maximum number of distinct user identities tracked in the active-users window.
///
/// If this limit is reached, new users are not inserted into the tracker and the
/// per-user metric label for the current operation is substituted with
/// `"__overflow__"`.  This limits Prometheus timeseries cardinality for the
/// `kms.kmip.operations.per_user.total` and
/// `kms.permissions.granted.per_user.total` metrics.
///
/// Raise this constant if your deployment legitimately has more than `10_000`
/// distinct users active within any 1-hour window.
pub(crate) const MAX_TRACKED_CARDINALITY: usize = 10_000;

/// Sentinel label value emitted when the cardinality cap is reached.
const OVERFLOW_USER_LABEL: &str = "__overflow__";

/// One-liner builder for an OpenTelemetry metric instrument.
/// Usage: `metric!(meter, u64_counter, "name", "description", "unit")`
macro_rules! metric {
    ($meter:expr,u64_counter, $name:literal, $desc:literal, $unit:literal) => {
        $meter
            .u64_counter($name)
            .with_description($desc)
            .with_unit($unit)
            .build()
    };
    ($meter:expr,f64_histogram, $name:literal, $desc:literal, $unit:literal) => {
        $meter
            .f64_histogram($name)
            .with_description($desc)
            .with_unit($unit)
            .build()
    };
    ($meter:expr,i64_up_down_counter, $name:literal, $desc:literal, $unit:literal) => {
        $meter
            .i64_up_down_counter($name)
            .with_description($desc)
            .with_unit($unit)
            .build()
    };
    ($meter:expr,i64_gauge, $name:literal, $desc:literal, $unit:literal) => {
        $meter
            .i64_gauge($name)
            .with_description($desc)
            .with_unit($unit)
            .build()
    };
}

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
    active_users_tracker: Arc<DashMap<String, i64>>,

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

    /// Total number of objects in the KMS (gauge — records absolute count directly)
    pub kms_objects_total: Gauge<i64>,

    /// Current number of active keys in Active state (gauge — records absolute count directly)
    pub active_keys_count: Gauge<i64>,

    /// Cache hit/miss statistics
    pub cache_operations_total: Counter<u64>,

    /// HSM operation counts (if HSM is enabled)
    pub hsm_operations_total: Counter<u64>,

    /// Count of automatic key rotations triggered by the background scheduler.
    ///
    /// Labelled with `uid`, `algorithm`, and `outcome` (`"success"` / `"failure"`).
    pub key_auto_rotation_total: Counter<u64>,

    /// Count of rotation renewal warnings emitted by the background scheduler.
    ///
    /// Labelled with `uid`, `algorithm`, and `threshold` (1, 7, or 30 days).
    pub key_rotation_warning_total: Counter<u64>,
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
    #[allow(clippy::cast_precision_loss, clippy::as_conversions)] // metric values are counters/durations well within f64 precision range
    pub fn new(meter_provider: SdkMeterProvider) -> KResult<Self> {
        let meter = MeterProvider::meter(&meter_provider, "cosmian_kms");

        let kmip_operations_total = metric!(
            meter,
            u64_counter,
            "kms.kmip.operations.total",
            "Total number of KMIP operations executed",
            "{operation}"
        );
        let kmip_operations_per_user = metric!(
            meter,
            u64_counter,
            "kms.kmip.operations.per_user.total",
            "Total number of KMIP operations executed per user",
            "{operation}"
        );
        let kmip_operation_duration = metric!(
            meter,
            f64_histogram,
            "kms.kmip.operation.duration",
            "Duration of KMIP operations in seconds",
            "s"
        );
        let permissions_granted_per_user = metric!(
            meter,
            u64_counter,
            "kms.permissions.granted.per_user.total",
            "Total number of permissions granted per user",
            "{permission}"
        );
        let permissions_granted_total = metric!(
            meter,
            u64_counter,
            "kms.permissions.granted.total",
            "Total number of permissions granted",
            "{permission}"
        );
        let active_users = metric!(
            meter,
            i64_up_down_counter,
            "kms.active.users",
            "Number of unique active users",
            "{user}"
        );
        let database_operations_total = metric!(
            meter,
            u64_counter,
            "kms.database.operations.total",
            "Total number of database operations",
            "{operation}"
        );
        let database_operation_duration = metric!(
            meter,
            f64_histogram,
            "kms.database.operation.duration",
            "Duration of database operations in seconds",
            "s"
        );
        let http_requests_total = metric!(
            meter,
            u64_counter,
            "kms.http.requests.total",
            "Total number of HTTP requests",
            "{request}"
        );
        let http_request_duration = metric!(
            meter,
            f64_histogram,
            "kms.http.request.duration",
            "Duration of HTTP requests in seconds",
            "s"
        );
        let server_uptime_seconds = metric!(
            meter,
            u64_counter,
            "kms.server.uptime",
            "Server uptime in seconds",
            "s"
        );
        let server_start_time = metric!(
            meter,
            i64_up_down_counter,
            "kms.server.start_time",
            "Server start time as Unix timestamp",
            "s"
        );
        let errors_total = metric!(
            meter,
            u64_counter,
            "kms.errors.total",
            "Total number of errors by type",
            "{error}"
        );
        let active_connections = metric!(
            meter,
            i64_up_down_counter,
            "kms.active.connections",
            "Current number of active connections",
            "{connection}"
        );
        let kms_objects_total = metric!(
            meter,
            i64_gauge,
            "kms.objects.total",
            "Total number of objects in the KMS",
            "{object}"
        );
        let active_keys_count = metric!(
            meter,
            i64_gauge,
            "kms.keys.active.count",
            "Number of non-destroyed key objects across all backends",
            "{key}"
        );
        let cache_operations_total = metric!(
            meter,
            u64_counter,
            "kms.cache.operations.total",
            "Total number of cache operations",
            "{operation}"
        );
        let hsm_operations_total = metric!(
            meter,
            u64_counter,
            "kms.hsm.operations.total",
            "Total number of HSM operations",
            "{operation}"
        );
        let key_auto_rotation_total = metric!(
            meter,
            u64_counter,
            "kms.key.auto_rotation",
            "Total number of automatic key rotations triggered by the background scheduler",
            "{rotation}"
        );
        let key_rotation_warning_total = metric!(
            meter,
            u64_counter,
            "kms.key.rotation_warning",
            "Total number of rotation renewal warnings emitted by the background scheduler",
            "{warning}"
        );

        // Seed server start time on startup
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| KmsError::ServerError(format!("System time error: {e}")))?
            .as_secs();
        let start_time_i64 = i64::try_from(start_time)
            .map_err(|e| KmsError::ServerError(format!("Start time conversion error: {e}")))?;
        server_start_time.add(start_time_i64, &[]);

        // Seed the time series so it is visible in the backend from server start.
        active_keys_count.record(0, &[]);

        Ok(Self {
            meter,
            _meter_provider: meter_provider,
            kmip_operations_total,
            kmip_operations_per_user,
            kmip_operation_duration,
            permissions_granted_per_user,
            permissions_granted_total,
            active_users,
            active_users_tracker: Arc::new(DashMap::with_capacity(100)),
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
            cache_operations_total,
            hsm_operations_total,
            key_auto_rotation_total,
            key_rotation_warning_total,
        })
    }

    /// Record a KMIP operation
    pub fn record_kmip_operation(&self, operation: &str, user: &str) {
        self.kmip_operations_total
            .add(1, &[KeyValue::new("operation", operation.to_owned())]);
        let effective_user = self.bounded_user_label(user);
        self.kmip_operations_per_user.add(
            1,
            &[
                KeyValue::new("user", effective_user),
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
        let effective_user = self.bounded_user_label(user);
        self.permissions_granted_per_user.add(
            1,
            &[
                KeyValue::new("user", effective_user),
                KeyValue::new("permission_type", permission_type.to_owned()),
            ],
        );
        self.permissions_granted_total.add(1, &[]);
    }

    /// Returns the user label to use for per-user metrics.
    ///
    /// Returns the real user string if the cardinality cap has not been reached,
    /// or `"__overflow__"` when it has.
    fn bounded_user_label(&self, user: &str) -> String {
        if self.active_users_tracker.contains_key(user)
            || self.active_users_tracker.len() < MAX_TRACKED_CARDINALITY
        {
            user.to_owned()
        } else {
            OVERFLOW_USER_LABEL.to_owned()
        }
    }

    /// Update active user tracking.
    ///
    /// Uses `DashMap` for lock-free concurrent shard access — no global write
    /// lock that would serialize all KMIP operations.
    ///
    /// Cleanup of stale users (inactive > 1 hour) is performed inline but only
    /// touches the shard containing each stale key, so concurrent operations on
    /// other shards proceed unblocked.
    ///
    /// # Panics
    ///
    /// Panics if system time is before `UNIX_EPOCH` (only possible on systems
    /// with a misconfigured clock; safe to treat as unrecoverable).
    #[allow(clippy::expect_used)] // documented panic: only fails on a misconfigured system clock before UNIX_EPOCH
    pub fn update_active_user(&self, user: &str) {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("System time before UNIX_EPOCH")
                .as_secs(),
        )
        .unwrap_or(i64::MAX);

        // Enforce cardinality cap: do not track new users beyond the limit.
        if !self.active_users_tracker.contains_key(user)
            && self.active_users_tracker.len() >= MAX_TRACKED_CARDINALITY
        {
            return;
        }

        let previous_len = self.active_users_tracker.len();
        self.active_users_tracker.insert(user.to_owned(), now);

        // Clean up users inactive for more than 1 hour.
        let cutoff = now - 3600;
        self.active_users_tracker
            .retain(|_, last_seen| *last_seen > cutoff);

        // Update gauge — calculate the delta.
        let current_len = self.active_users_tracker.len();
        let delta = i64::try_from(current_len).unwrap_or(i64::MAX)
            - i64::try_from(previous_len).unwrap_or(i64::MAX);
        if delta != 0 {
            self.active_users.add(delta, &[]);
        }
    }

    /// Record a database operation (count + duration in one call).
    ///
    /// # Arguments
    /// * `operation` – low-cardinality label (`"create"`, `"retrieve"`, …)
    /// * `backend`   – typed database backend; `as_str()` is called here so
    ///   no free-form string can sneak in through this method.
    /// * `outcome`   – `"success"` or `"error"`
    /// * `duration_seconds` – wall-clock duration of the operation
    pub fn record_database_operation(
        &self,
        operation: &str,
        backend: MainDbKind,
        outcome: &str,
        duration_seconds: f64,
    ) {
        let backend_str = backend.as_str();
        self.database_operations_total.add(
            1,
            &[
                KeyValue::new("operation", operation.to_owned()),
                KeyValue::new("backend", backend_str),
                KeyValue::new("outcome", outcome.to_owned()),
            ],
        );
        self.database_operation_duration.record(
            duration_seconds,
            &[
                KeyValue::new("operation", operation.to_owned()),
                KeyValue::new("backend", backend_str),
                KeyValue::new("outcome", outcome.to_owned()),
            ],
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
    pub fn record_http_request_duration(
        &self,
        method: &str,
        path: &str,
        status: &str,
        duration_seconds: f64,
    ) {
        self.http_request_duration.record(
            duration_seconds,
            &[
                KeyValue::new("method", method.to_owned()),
                KeyValue::new("path", path.to_owned()),
                KeyValue::new("status", status.to_owned()),
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

    /// Set the current active keys count from an absolute Locate response.
    pub fn update_active_keys_count(&self, absolute_count: i64) {
        self.active_keys_count.record(absolute_count, &[]);
    }

    /// Set `kms.objects.total` to the current absolute object count.
    ///
    /// Called once at server startup (seeding from the real DB count) and
    /// every 30 s by the metrics cron task.
    pub fn update_objects_total(&self, absolute_count: i64) {
        self.kms_objects_total.record(absolute_count, &[]);
    }

    /// Record cache operation
    ///
    /// Both `operation` and `result` must be `'static` string literals (e.g. `"get"`, `"hit"`).
    /// Using `&'static str` avoids a `String` allocation on every call since
    /// all current call sites already use compile-time constants.
    pub fn record_cache_operation(&self, operation: &'static str, result: &'static str) {
        self.cache_operations_total.add(
            1,
            &[
                KeyValue::new("operation", operation),
                KeyValue::new("result", result),
            ],
        );
    }

    /// Record an automatic key rotation attempt.
    ///
    /// - `uid` — the key being rotated (high cardinality; use with care)
    /// - `algorithm` — cryptographic algorithm label (e.g. `"Aes"`, `"Rsa"`)
    /// - `outcome` — `"success"` or `"failure"`
    pub fn record_key_auto_rotation(&self, uid: &str, algorithm: &str, outcome: &str) {
        self.key_auto_rotation_total.add(
            1,
            &[
                KeyValue::new("uid", uid.to_owned()),
                KeyValue::new("algorithm", algorithm.to_owned()),
                KeyValue::new("outcome", outcome.to_owned()),
            ],
        );
    }

    /// Record a rotation renewal warning.
    ///
    /// - `uid` — the key approaching its rotation deadline
    /// - `algorithm` — cryptographic algorithm label (e.g. `"Aes"`, `"Rsa"`)
    /// - `threshold` — the warning threshold that was matched (1, 7, or 30 days)
    pub fn record_rotation_warning(&self, uid: &str, algorithm: &str, threshold: i64) {
        self.key_rotation_warning_total.add(
            1,
            &[
                KeyValue::new("uid", uid.to_owned()),
                KeyValue::new("algorithm", algorithm.to_owned()),
                KeyValue::new("threshold_days", threshold.to_string()),
            ],
        );
    }

    /// Record HSM operation.
    ///
    /// `operation` must be a `'static` literal (e.g. `Op::OP_NAME`, `"Wrap"`, `"Unwrap"`).
    /// `hsm_model` is a runtime label from `hsm_model_from_prefix` and still requires allocation.
    pub fn record_hsm_operation(&self, operation: &'static str, hsm_model: &str) {
        self.hsm_operations_total.add(
            1,
            &[
                KeyValue::new("hsm_model", hsm_model.to_owned()),
                KeyValue::new("operation", operation),
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

impl DbMetricsRecorder for OtelMetrics {
    fn record_operation(
        &self,
        operation: &str,
        backend: MainDbKind,
        outcome: &str,
        duration_seconds: f64,
    ) {
        self.record_database_operation(operation, backend, outcome, duration_seconds);
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
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter, PeriodicReader,
        data::{AggregatedMetrics, GaugeDataPoint, Metric, MetricData, ScopeMetrics, SumDataPoint},
    };

    use super::*;

    // No-op provider — cheap, used only where value assertions aren't needed
    fn create_test_meter_provider() -> SdkMeterProvider {
        SdkMeterProvider::builder().build()
    }

    // Observing setup: real exporter, values assertable after force_flush()

    fn setup_observing_metrics() -> (OtelMetrics, SdkMeterProvider, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let provider_ref = provider.clone();
        let metrics = OtelMetrics::new(provider).expect("metrics init");
        (metrics, provider_ref, exporter)
    }

    /// Sum of all data-point values for a u64 counter metric in the last exported batch.
    fn last_counter_u64(exporter: &InMemoryMetricExporter, name: &str) -> u64 {
        let batches = exporter.get_finished_metrics().unwrap_or_default();
        let Some(last) = batches.last() else {
            return 0;
        };
        for sm in last.scope_metrics() {
            for metric in sm.metrics() {
                if metric.name() == name {
                    if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
                        return sum.data_points().map(SumDataPoint::value).sum();
                    }
                }
            }
        }
        0
    }

    /// Net value of an i64 `UpDownCounter` (`Sum<i64>`) in the last exported batch.
    fn last_updown_i64(exporter: &InMemoryMetricExporter, name: &str) -> i64 {
        let batches = exporter.get_finished_metrics().unwrap_or_default();
        let Some(last) = batches.last() else {
            return 0;
        };
        for sm in last.scope_metrics() {
            for metric in sm.metrics() {
                if metric.name() == name {
                    if let AggregatedMetrics::I64(MetricData::Sum(sum)) = metric.data() {
                        return sum.data_points().map(SumDataPoint::value).sum();
                    }
                }
            }
        }
        0
    }

    /// Last recorded value of an i64 Gauge in the last exported batch.
    fn last_gauge_i64(exporter: &InMemoryMetricExporter, name: &str) -> i64 {
        let batches = exporter.get_finished_metrics().unwrap_or_default();
        let Some(last) = batches.last() else {
            return 0;
        };
        for sm in last.scope_metrics() {
            for metric in sm.metrics() {
                if metric.name() == name {
                    if let AggregatedMetrics::I64(MetricData::Gauge(g)) = metric.data() {
                        return g.data_points().last().map_or(0, GaugeDataPoint::value);
                    }
                }
            }
        }
        0
    }

    /// Collects every `user` attribute value recorded for a `u64` counter metric
    /// across all data points in the last exported batch.
    fn user_labels(exporter: &InMemoryMetricExporter, name: &str) -> Vec<String> {
        let batches = exporter.get_finished_metrics().unwrap_or_default();
        let Some(last) = batches.last() else {
            return vec![];
        };
        let mut labels = vec![];
        for sm in last.scope_metrics() {
            for metric in sm.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
                    for dp in sum.data_points() {
                        for kv in dp.attributes() {
                            if kv.key.as_str() == "user" {
                                labels.push(kv.value.to_string());
                            }
                        }
                    }
                }
            }
        }
        labels
    }

    // ── Smoke tests (construction + no-panic; no value assertions needed) ─────

    #[test]
    fn test_metrics_creation() {
        let _metrics = OtelMetrics::new(create_test_meter_provider()).expect("creation");
    }

    #[test]
    fn test_active_users_tracking() {
        let metrics = OtelMetrics::new(create_test_meter_provider()).expect("creation");
        metrics.update_active_user("user1");
        metrics.update_active_user("user2");
        metrics.update_active_user("user3");
        assert_eq!(metrics.active_users_tracker.len(), 3);
    }

    // ── Tests with value assertions ───────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_kmip_operation_recording() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_kmip_operation("Create", "user1");
        metrics.record_kmip_operation("Get", "user1");
        metrics.record_kmip_operation("Create", "user2");
        provider.force_flush().expect("flush");
        assert_eq!(last_counter_u64(&exporter, "kms.kmip.operations.total"), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_per_user_metric_labels() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_kmip_operation("Create", "alice");
        metrics.record_kmip_operation("Get", "bob");
        provider.force_flush().expect("flush");
        let mut labels = user_labels(&exporter, "kms.kmip.operations.per_user.total");
        labels.sort();
        assert_eq!(labels, vec!["alice".to_owned(), "bob".to_owned()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_per_user_cardinality_overflow() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        // Fill the tracker to the cardinality cap directly, avoiding the cost
        // of `MAX_TRACKED_CARDINALITY` real `record_kmip_operation` calls.
        for i in 0..MAX_TRACKED_CARDINALITY {
            metrics
                .active_users_tracker
                .insert(format!("user{i}"), i64::MAX);
        }
        metrics.record_kmip_operation("Create", "new_user");
        provider.force_flush().expect("flush");
        let labels = user_labels(&exporter, "kms.kmip.operations.per_user.total");
        assert_eq!(labels, vec![OVERFLOW_USER_LABEL.to_owned()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_permission_recording() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_permission_grant("user1", "read");
        metrics.record_permission_grant("user1", "write");
        metrics.record_permission_grant("user2", "read");
        provider.force_flush().expect("flush");
        assert_eq!(
            last_counter_u64(&exporter, "kms.permissions.granted.total"),
            3
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_operation_duration_exports_histogram_names() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_kmip_operation_duration("Create", 0.123);
        metrics.record_database_operation("insert", MainDbKind::Sqlite, "success", 0.045);
        provider.force_flush().expect("flush");
        let batches = exporter.get_finished_metrics().unwrap_or_default();
        let names: Vec<&str> = batches.last().map_or(vec![], |rm| {
            rm.scope_metrics()
                .flat_map(ScopeMetrics::metrics)
                .map(Metric::name)
                .collect()
        });
        assert!(
            names.contains(&"kms.kmip.operation.duration"),
            "kmip histogram not exported"
        );
        assert!(
            names.contains(&"kms.database.operation.duration"),
            "db histogram not exported"
        );
    }

    // ── New tests for previously-untested methods ─────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_record_http_request_increments_counter() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_http_request("POST", "/kmip/2_1", "200");
        metrics.record_http_request("GET", "/health", "200");
        metrics.record_http_request("POST", "/kmip/2_1", "422");
        provider.force_flush().expect("flush");
        assert_eq!(last_counter_u64(&exporter, "kms.http.requests.total"), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_record_cache_operation_increments_counter() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_cache_operation("get", "miss");
        metrics.record_cache_operation("insert", "ok");
        metrics.record_cache_operation("get", "hit");
        provider.force_flush().expect("flush");
        assert_eq!(last_counter_u64(&exporter, "kms.cache.operations.total"), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_record_hsm_operation_increments_counter() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_hsm_operation("Encrypt", "softhsm2");
        metrics.record_hsm_operation("Decrypt", "softhsm2");
        provider.force_flush().expect("flush");
        assert_eq!(last_counter_u64(&exporter, "kms.hsm.operations.total"), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_update_objects_total_sets_gauge() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.update_objects_total(42);
        provider.force_flush().expect("flush");
        assert_eq!(last_gauge_i64(&exporter, "kms.objects.total"), 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_active_connections_up_down() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.increment_active_connections();
        metrics.increment_active_connections();
        metrics.decrement_active_connections();
        provider.force_flush().expect("flush");
        assert_eq!(last_updown_i64(&exporter, "kms.active.connections"), 1);
    }

    // ── MainDbKind::as_str correctness ────────────────────────────────────────

    #[test]
    fn test_main_db_kind_as_str() {
        assert_eq!(MainDbKind::Sqlite.as_str(), "sqlite");
        assert_eq!(MainDbKind::Postgres.as_str(), "postgresql");
        assert_eq!(MainDbKind::Mysql.as_str(), "mysql");
        #[cfg(feature = "non-fips")]
        assert_eq!(MainDbKind::RedisFindex.as_str(), "redis");
    }
}
