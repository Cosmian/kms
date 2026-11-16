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
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
};

use cosmian_kms_server_database::{
    Database, DbMetricsRecorder, MainDbKind, reexport::cosmian_kms_interfaces::KeyInventoryBucket,
};
use cosmian_logger::{debug, warn};
use dashmap::DashMap;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Gauge, Histogram, Meter, MeterProvider, UpDownCounter},
};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use time::{Duration, OffsetDateTime};

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

/// Maximum distinct `kms.keys.active.count` attribute sets.
///
/// Kept below the OpenTelemetry SDK's default per-instrument limit (2000),
/// which would otherwise merge extra buckets into its own
/// `otel.metric.overflow` series before ours applies.
const MAX_KEY_BUCKETS: usize = 1_000;

/// Label value used when a key-inventory dimension is not set on the object.
const UNKNOWN_LABEL: &str = "unknown";

/// Look-ahead windows, in days, of `kms.keys.expiring_soon.count`. The
/// windows are cumulative: a key expiring in 3 days is counted in all three.
pub(crate) const EXPIRY_WINDOWS_DAYS: [i64; 3] = [7, 30, 90];

/// `outcome` label value of a KMIP or HSM operation result: `"success"` or `"error"`.
pub(crate) const fn outcome_label<T, E>(result: &Result<T, E>) -> &'static str {
    if result.is_ok() { "success" } else { "error" }
}

/// `object_type`, `algorithm`, `key_length`, `state` label values of one
/// `kms.keys.active.count` series.
type KeyBucketLabels = [String; 4];

/// Number of hex characters kept from the SHA-256 digest used for the `user`
/// metric label (64 bits — negligible collision risk at `MAX_TRACKED_CARDINALITY`
/// scale, short enough to stay readable in dashboards).
const USER_LABEL_HASH_HEX_LEN: usize = 16;

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

    /// Non-destroyed keys per `object_type`/`algorithm`/`key_length`/`state`
    /// (gauge — records absolute counts directly).
    pub active_keys_count: Gauge<i64>,

    /// Label sets reported by the last `kms.keys.active.count` update, so a
    /// bucket that empties out is reset to 0 instead of keeping its last
    /// value forever (cumulative gauges never forget an attribute set).
    active_keys_buckets: Mutex<HashSet<KeyBucketLabels>>,

    /// `PreActive`/`Active` keys whose `DeactivationDate` falls within the
    /// next N days, labelled with `days_until_expiry`.
    pub keys_expiring_soon_count: Gauge<i64>,

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
        let keys_expiring_soon_count = metric!(
            meter,
            i64_gauge,
            "kms.keys.expiring_soon.count",
            "Number of active or pre-active keys whose deactivation date falls within the window",
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
            active_keys_buckets: Mutex::new(HashSet::new()),
            keys_expiring_soon_count,
            cache_operations_total,
            hsm_operations_total,
            key_auto_rotation_total,
            key_rotation_warning_total,
        })
    }

    /// Record a KMIP operation.
    ///
    /// `outcome` (`"success"` / `"error"`) labels `kms.kmip.operations.total`
    /// only, to keep the per-user series count unchanged.
    /// `user` is only ever used to update the in-process active-user tracker
    /// and, hashed, as the `kms.kmip.operations.per_user.total` label — see
    /// [`Self::bounded_user_label`].
    pub fn record_kmip_operation(&self, operation: &str, user: &str, outcome: &'static str) {
        // One shared allocation for both label sets.
        let operation: Arc<str> = Arc::from(operation);
        self.kmip_operations_total.add(
            1,
            &[
                KeyValue::new("operation", Arc::clone(&operation)),
                KeyValue::new("outcome", outcome),
            ],
        );
        let effective_user = self.bounded_user_label(user);
        self.kmip_operations_per_user.add(
            1,
            &[
                KeyValue::new("user", effective_user),
                KeyValue::new("operation", operation),
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

    /// Record a permission grant.
    ///
    /// `user` is only ever used, hashed, as the
    /// `kms.permissions.granted.per_user.total` label — see
    /// [`Self::bounded_user_label`].
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

    /// Returns the `user` label to use for per-user metrics.
    ///
    /// The raw username is never exported: this returns a non-reversible,
    /// truncated SHA-256 hash of the user identity if the cardinality cap has
    /// not been reached, or the literal `"__overflow__"` sentinel when it has.
    /// Real user identity is recorded only in the audit log
    /// (`middlewares/audit.rs`), never in OTEL metrics.
    fn bounded_user_label(&self, user: &str) -> String {
        if self.active_users_tracker.contains_key(user)
            || self.active_users_tracker.len() < MAX_TRACKED_CARDINALITY
        {
            Self::hash_user(user)
        } else {
            OVERFLOW_USER_LABEL.to_owned()
        }
    }

    /// Hashes a user identity into a short, non-reversible hex digest suitable
    /// for use as a metric label (per OTEL's `user.hash` semantic convention).
    fn hash_user(user: &str) -> String {
        let digest = openssl::sha::sha256(user.as_bytes());
        let full_hex = hex::encode(digest);
        full_hex
            .get(..USER_LABEL_HASH_HEX_LEN)
            .unwrap_or(&full_hex)
            .to_owned()
    }

    /// Update active user tracking.
    ///
    /// Uses `DashMap` for lock-free concurrent shard access — no global write
    /// lock that would serialize all KMIP operations.
    ///
    /// Cleanup of stale users (inactive > 1 hour) is performed inline but only
    /// touches the shard containing each stale key, so concurrent operations on
    /// other shards proceed unblocked.
    pub fn update_active_user(&self, user: &str) {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
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
        operation: &'static str,
        backend: MainDbKind,
        outcome: &'static str,
        duration_seconds: f64,
    ) {
        let backend_str = backend.as_str();
        let attributes = [
            KeyValue::new("operation", operation),
            KeyValue::new("backend", backend_str),
            KeyValue::new("outcome", outcome),
        ];
        self.database_operations_total.add(1, &attributes);
        self.database_operation_duration
            .record(duration_seconds, &attributes);
    }

    /// Record an HTTP request
    pub fn record_http_request(
        &self,
        method: Cow<'static, str>,
        path: &'static str,
        status: Cow<'static, str>,
    ) {
        self.http_requests_total.add(
            1,
            &[
                KeyValue::new("method", method),
                KeyValue::new("path", path),
                KeyValue::new("status", status),
            ],
        );
    }

    /// Record HTTP request duration
    pub fn record_http_request_duration(
        &self,
        method: Cow<'static, str>,
        path: &'static str,
        status: Cow<'static, str>,
        duration_seconds: f64,
    ) {
        self.http_request_duration.record(
            duration_seconds,
            &[
                KeyValue::new("method", method),
                KeyValue::new("path", path),
                KeyValue::new("status", status),
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

    /// Set `kms.keys.active.count` from a key inventory.
    ///
    /// Unset dimensions are labelled `"unknown"`. Beyond
    /// [`MAX_KEY_BUCKETS`] distinct buckets, the remaining counts are
    /// folded into an all-`"__overflow__"` bucket so the total stays exact.
    /// The largest buckets are kept, in a deterministic order, so the same
    /// series survive every update instead of accumulating in the SDK.
    /// Buckets reported by the previous update but absent now are set to 0.
    pub fn update_active_keys_breakdown(&self, inventory: &[(KeyInventoryBucket, u64)]) {
        let mut ordered: Vec<&(KeyInventoryBucket, u64)> = inventory.iter().collect();
        ordered.sort_unstable_by(|(a, a_count), (b, b_count)| {
            b_count.cmp(a_count).then_with(|| a.cmp(b))
        });
        let mut current: HashMap<KeyBucketLabels, i64> = HashMap::new();
        for (bucket, count) in ordered {
            let mut labels = [
                bucket.object_type.clone(),
                bucket
                    .algorithm
                    .as_deref()
                    .unwrap_or(UNKNOWN_LABEL)
                    .to_owned(),
                bucket
                    .key_length
                    .map_or_else(|| UNKNOWN_LABEL.to_owned(), |l| l.to_string()),
                bucket.state.as_deref().unwrap_or(UNKNOWN_LABEL).to_owned(),
            ];
            if current.len() >= MAX_KEY_BUCKETS && !current.contains_key(&labels) {
                labels = std::array::from_fn(|_| OVERFLOW_USER_LABEL.to_owned());
            }
            let entry = current.entry(labels).or_default();
            *entry = entry.saturating_add(i64::try_from(*count).unwrap_or(i64::MAX));
        }

        let mut previous = self
            .active_keys_buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for stale in previous.iter().filter(|l| !current.contains_key(*l)) {
            self.active_keys_count
                .record(0, &key_bucket_attributes(stale));
        }
        for (labels, count) in &current {
            self.active_keys_count
                .record(*count, &key_bucket_attributes(labels));
        }
        *previous = current.into_keys().collect();
    }

    /// Refresh `kms.keys.active.count` and `kms.keys.expiring_soon.count` from
    /// the database (all registered stores, no ACL filtering).
    ///
    /// Failures are logged at `warn`, not returned: a persistently failing
    /// query (e.g. a backend-specific SQL bug) must be visible without debug
    /// logging, but must not stop the caller (startup or the metrics cron).
    pub async fn sync_key_gauges(&self, database: &Database) {
        match database.key_inventory().await {
            Ok(inventory) => {
                debug!(
                    "[metrics] kms.keys.active.count synced: {} bucket(s)",
                    inventory.len()
                );
                self.update_active_keys_breakdown(&inventory);
            }
            Err(e) => warn!("[metrics] Failed to sync kms.keys.active.count: {e}"),
        }
        match database.key_deactivation_dates().await {
            Ok(dates) => self.update_keys_expiring_soon(OffsetDateTime::now_utc(), &dates),
            Err(e) => warn!("[metrics] Failed to sync kms.keys.expiring_soon.count: {e}"),
        }
    }

    /// Set `kms.keys.expiring_soon.count` for every window of
    /// [`EXPIRY_WINDOWS_DAYS`] from the deactivation dates of the
    /// `PreActive`/`Active` keys.
    pub fn update_keys_expiring_soon(
        &self,
        now: OffsetDateTime,
        deactivation_dates: &[OffsetDateTime],
    ) {
        for (days, count) in expiring_soon_counts(now, deactivation_dates) {
            self.keys_expiring_soon_count.record(
                count,
                &[KeyValue::new("days_until_expiry", days.to_string())],
            );
        }
    }

    /// Set `kms.objects.total` to the current absolute object count.
    ///
    /// Called once at server startup (seeding from the real DB count) and
    /// every `metrics_count_interval_secs` by the metrics cron task (0 disables both).
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
    /// `outcome` is `"success"` or `"error"`.
    pub fn record_hsm_operation(
        &self,
        operation: &'static str,
        hsm_model: &str,
        outcome: &'static str,
    ) {
        self.hsm_operations_total.add(
            1,
            &[
                KeyValue::new("hsm_model", hsm_model.to_owned()),
                KeyValue::new("operation", operation),
                KeyValue::new("outcome", outcome),
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

/// `kms.keys.active.count` attributes of one bucket.
fn key_bucket_attributes(labels: &KeyBucketLabels) -> [KeyValue; 4] {
    let [object_type, algorithm, key_length, state] = labels.clone();
    [
        KeyValue::new("object_type", object_type),
        KeyValue::new("algorithm", algorithm),
        KeyValue::new("key_length", key_length),
        KeyValue::new("state", state),
    ]
}

/// Number of dates in `(now, now + days]` for every window of
/// [`EXPIRY_WINDOWS_DAYS`]. Dates already past are not "expiring soon": the
/// key is (or is about to be) deactivated.
fn expiring_soon_counts(
    now: OffsetDateTime,
    deactivation_dates: &[OffsetDateTime],
) -> [(i64, i64); EXPIRY_WINDOWS_DAYS.len()] {
    EXPIRY_WINDOWS_DAYS.map(|days| {
        let horizon = now.saturating_add(Duration::days(days));
        let count = deactivation_dates
            .iter()
            .filter(|date| **date > now && **date <= horizon)
            .count();
        (days, i64::try_from(count).unwrap_or(i64::MAX))
    })
}

impl DbMetricsRecorder for OtelMetrics {
    fn record_operation(
        &self,
        operation: &'static str,
        backend: MainDbKind,
        outcome: &'static str,
        duration_seconds: f64,
    ) {
        self.record_database_operation(operation, backend, outcome, duration_seconds);
    }
}

#[cfg(test)]
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
                if metric.name() == name
                    && let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data()
                {
                    return sum.data_points().map(SumDataPoint::value).sum();
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
                if metric.name() == name
                    && let AggregatedMetrics::I64(MetricData::Sum(sum)) = metric.data()
                {
                    return sum.data_points().map(SumDataPoint::value).sum();
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
                if metric.name() == name
                    && let AggregatedMetrics::I64(MetricData::Gauge(g)) = metric.data()
                {
                    return g.data_points().last().map_or(0, GaugeDataPoint::value);
                }
            }
        }
        0
    }

    /// Sorted `(key, value)` attribute pairs, for comparing data points.
    fn attrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut v: Vec<_> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        v.sort();
        v
    }

    /// Value of every data point of an i64 gauge or u64 counter in the last
    /// exported batch, keyed by its sorted attributes.
    fn data_points(
        exporter: &InMemoryMetricExporter,
        name: &str,
    ) -> HashMap<Vec<(String, String)>, i64> {
        fn key<'a>(kvs: impl Iterator<Item = &'a KeyValue>) -> Vec<(String, String)> {
            let mut v: Vec<_> = kvs
                .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                .collect();
            v.sort();
            v
        }
        let batches = exporter.get_finished_metrics().unwrap_or_default();
        let mut points = HashMap::new();
        let Some(last) = batches.last() else {
            return points;
        };
        for sm in last.scope_metrics() {
            for metric in sm.metrics().filter(|m| m.name() == name) {
                match metric.data() {
                    AggregatedMetrics::I64(MetricData::Gauge(g)) => {
                        for dp in g.data_points() {
                            points.insert(key(dp.attributes()), dp.value());
                        }
                    }
                    AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                        for dp in sum.data_points() {
                            points.insert(
                                key(dp.attributes()),
                                i64::try_from(dp.value()).unwrap_or(i64::MAX),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        points
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
        metrics.record_kmip_operation("Create", "user1", "success");
        metrics.record_kmip_operation("Get", "user1", "error");
        metrics.record_kmip_operation("Create", "user2", "success");
        provider.force_flush().expect("flush");
        assert_eq!(last_counter_u64(&exporter, "kms.kmip.operations.total"), 3);

        let labels = user_labels(&exporter, "kms.kmip.operations.per_user.total");
        assert_ne!(labels.len(), 0);
        assert!(
            labels.iter().all(|l| l != "user1" && l != "user2"),
            "raw username must never appear in the `user` metric label: {labels:?}"
        );
        assert!(
            labels.iter().all(|l| l.len() == USER_LABEL_HASH_HEX_LEN),
            "expected {USER_LABEL_HASH_HEX_LEN}-hex-char hash labels: {labels:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_per_user_metric_labels() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_kmip_operation("Create", "alice", "success");
        metrics.record_kmip_operation("Get", "bob", "success");
        provider.force_flush().expect("flush");
        let mut labels = user_labels(&exporter, "kms.kmip.operations.per_user.total");
        labels.sort();
        let mut expected = vec![
            OtelMetrics::hash_user("alice"),
            OtelMetrics::hash_user("bob"),
        ];
        expected.sort();
        assert_eq!(labels, expected);
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
        metrics.record_kmip_operation("Create", "new_user", "success");
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

        let labels = user_labels(&exporter, "kms.permissions.granted.per_user.total");
        assert_ne!(labels.len(), 0);
        assert!(
            labels.iter().all(|l| l != "user1" && l != "user2"),
            "raw username must never appear in the `user` metric label: {labels:?}"
        );
    }

    #[test]
    fn test_user_label_hash_is_deterministic() {
        assert_eq!(
            OtelMetrics::hash_user("alice@example.com"),
            OtelMetrics::hash_user("alice@example.com")
        );
        assert_ne!(
            OtelMetrics::hash_user("alice@example.com"),
            OtelMetrics::hash_user("bob@example.com")
        );
        assert_eq!(
            OtelMetrics::hash_user("alice@example.com").len(),
            USER_LABEL_HASH_HEX_LEN
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_user_label_overflow_stays_literal_sentinel() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        // Fill the tracker to the cap directly instead of issuing
        // `MAX_TRACKED_CARDINALITY` real `record_kmip_operation` calls: that
        // many distinct `user` attribute values would also trip the OTel SDK's
        // own default per-instrument cardinality limit (2000), which merges
        // everything past it into an attribute-less SDK overflow point —
        // masking our own `"__overflow__"` sentinel before it can be observed.
        for i in 0..MAX_TRACKED_CARDINALITY {
            metrics
                .active_users_tracker
                .insert(format!("user{i}"), i64::MAX);
        }
        metrics.record_kmip_operation("Create", "new_user", "success");
        provider.force_flush().expect("flush");
        let labels = user_labels(&exporter, "kms.kmip.operations.per_user.total");
        assert!(
            labels.iter().any(|l| l == OVERFLOW_USER_LABEL),
            "expected literal overflow sentinel once cardinality cap is exceeded: {labels:?}"
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
        metrics.record_http_request(Cow::Borrowed("POST"), "/kmip/2_1", Cow::Borrowed("200"));
        metrics.record_http_request(Cow::Borrowed("GET"), "/health", Cow::Borrowed("200"));
        metrics.record_http_request(Cow::Borrowed("POST"), "/kmip/2_1", Cow::Borrowed("422"));
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
        metrics.record_hsm_operation("Encrypt", "softhsm2", "success");
        metrics.record_hsm_operation("Decrypt", "softhsm2", "error");
        provider.force_flush().expect("flush");
        assert_eq!(last_counter_u64(&exporter, "kms.hsm.operations.total"), 2);
        let points = data_points(&exporter, "kms.hsm.operations.total");
        assert_eq!(
            points.get(&attrs(&[
                ("hsm_model", "softhsm2"),
                ("operation", "Decrypt"),
                ("outcome", "error"),
            ])),
            Some(&1)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_kmip_operation_outcome_label() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.record_kmip_operation("Encrypt", "alice", "success");
        metrics.record_kmip_operation("Encrypt", "alice", "success");
        metrics.record_kmip_operation("Encrypt", "alice", "error");
        provider.force_flush().expect("flush");
        let points = data_points(&exporter, "kms.kmip.operations.total");
        assert_eq!(
            points.get(&attrs(&[("operation", "Encrypt"), ("outcome", "success")])),
            Some(&2)
        );
        assert_eq!(
            points.get(&attrs(&[("operation", "Encrypt"), ("outcome", "error")])),
            Some(&1)
        );
    }

    fn bucket(
        object_type: &str,
        algorithm: Option<&str>,
        key_length: Option<i32>,
        state: Option<&str>,
    ) -> KeyInventoryBucket {
        KeyInventoryBucket {
            object_type: object_type.to_owned(),
            algorithm: algorithm.map(str::to_owned),
            key_length,
            state: state.map(str::to_owned),
        }
    }

    fn key_attrs(
        object_type: &str,
        algorithm: &str,
        key_length: &str,
        state: &str,
    ) -> Vec<(String, String)> {
        attrs(&[
            ("algorithm", algorithm),
            ("key_length", key_length),
            ("object_type", object_type),
            ("state", state),
        ])
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_active_keys_breakdown_labels_and_zeroes_vanished_buckets() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        metrics.update_active_keys_breakdown(&[
            (
                bucket("SymmetricKey", Some("AES"), Some(256), Some("Active")),
                3,
            ),
            (
                bucket("PrivateKey", Some("RSA"), Some(2048), Some("Active")),
                1,
            ),
            (bucket("SymmetricKey", None, None, None), 2),
        ]);
        provider.force_flush().expect("flush");
        let points = data_points(&exporter, "kms.keys.active.count");
        assert_eq!(points.len(), 3, "no unlabelled seed series: {points:?}");
        assert_eq!(
            points.get(&key_attrs("SymmetricKey", "AES", "256", "Active")),
            Some(&3)
        );
        assert_eq!(
            points.get(&key_attrs("SymmetricKey", "unknown", "unknown", "unknown")),
            Some(&2)
        );

        metrics.update_active_keys_breakdown(&[(
            bucket("SymmetricKey", Some("AES"), Some(256), Some("Active")),
            4,
        )]);
        provider.force_flush().expect("flush");
        let points = data_points(&exporter, "kms.keys.active.count");
        assert_eq!(
            points.get(&key_attrs("SymmetricKey", "AES", "256", "Active")),
            Some(&4)
        );
        assert_eq!(
            points.get(&key_attrs("PrivateKey", "RSA", "2048", "Active")),
            Some(&0)
        );
        assert_eq!(points.values().sum::<i64>(), 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_active_keys_breakdown_folds_overflow_buckets() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        let inventory: Vec<_> = (0..=MAX_KEY_BUCKETS)
            .map(|i| {
                (
                    bucket(
                        "SymmetricKey",
                        Some("AES"),
                        Some(i32::try_from(i).expect("small")),
                        Some("Active"),
                    ),
                    1,
                )
            })
            .chain([(bucket("PublicKey", Some("EC"), None, Some("Active")), 5)])
            .collect();
        metrics.update_active_keys_breakdown(&inventory);
        provider.force_flush().expect("flush");
        let points = data_points(&exporter, "kms.keys.active.count");
        assert_eq!(points.len(), MAX_KEY_BUCKETS + 1);
        // The largest bucket is kept; the two smallest-ordered 1-key buckets overflow.
        assert_eq!(
            points.get(&key_attrs("PublicKey", "EC", "unknown", "Active")),
            Some(&5)
        );
        let overflow = key_attrs(
            OVERFLOW_USER_LABEL,
            OVERFLOW_USER_LABEL,
            OVERFLOW_USER_LABEL,
            OVERFLOW_USER_LABEL,
        );
        assert_eq!(points.get(&overflow), Some(&2));
        let total = i64::try_from(MAX_KEY_BUCKETS).expect("small") + 6;
        assert_eq!(points.values().sum::<i64>(), total);

        // Same inventory in another order: the same buckets survive, so no
        // series accumulate across updates.
        let reversed: Vec<_> = inventory.into_iter().rev().collect();
        metrics.update_active_keys_breakdown(&reversed);
        provider.force_flush().expect("flush");
        let points = data_points(&exporter, "kms.keys.active.count");
        assert_eq!(points.len(), MAX_KEY_BUCKETS + 1);
        assert_eq!(points.get(&overflow), Some(&2));
    }

    #[test]
    fn test_expiring_soon_counts_cumulative_windows() {
        let now = time::macros::datetime!(2026-01-01 00:00 UTC);
        let dates = [
            now - Duration::days(1),
            now,
            now + Duration::days(3),
            now + Duration::days(7),
            now + Duration::days(20),
            now + Duration::days(90),
            now + Duration::days(91),
        ];
        assert_eq!(
            expiring_soon_counts(now, &dates),
            [(7, 2), (30, 3), (90, 4)]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_update_keys_expiring_soon_records_each_window() {
        let (metrics, provider, exporter) = setup_observing_metrics();
        let now = OffsetDateTime::now_utc();
        metrics.update_keys_expiring_soon(now, &[now + Duration::days(3)]);
        provider.force_flush().expect("flush");
        let points = data_points(&exporter, "kms.keys.expiring_soon.count");
        for days in ["7", "30", "90"] {
            assert_eq!(points.get(&attrs(&[("days_until_expiry", days)])), Some(&1));
        }
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
