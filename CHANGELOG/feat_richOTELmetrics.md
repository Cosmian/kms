# Changelog — feat/richOTELmetrics

## Features

### Database Metrics Wiring (Step 1)

- Wire `kms.database.operations.total` (counter) and `kms.database.operation.duration`
  (histogram) at the `Database` facade layer with `operation`, `backend`, and `outcome`
  attributes, covering all 11 object-store and 5 permission-store methods.
- Introduce `DbMetricsRecorder` trait in `cosmian_kms_server_database` for
  dependency-inversion: the `server_database` crate emits metrics via a trait object
  without depending on `cosmian_kms_server` (avoids crate cycle).
- `OtelMetrics` in `cosmian_kms_server` implements `DbMetricsRecorder`; the recorder
  `Arc` is injected into `Database::instantiate` at KMS startup.
- `MainDbKind::as_str()` provides canonical backend labels
  (`"sqlite"`, `"postgresql"`, `"mysql"`, `"redis"`).

### HTTP Metrics Wiring (Step 2)

- Add `OtelHttpMetrics` Actix-web middleware (`crate/server/src/middlewares/otel_http_middleware.rs`)
  that records `kms.http.requests.total` (counter with `method`, `path`, `status`
  attributes), `kms.http.request.duration` (histogram with `method`, `path`), and
  `kms.active.connections` (in-flight up-down counter) for every HTTP request.
- Middleware is installed as the outermost `App`-level wrap to measure true
  client-perceived latency including all inner middleware.
- `normalize_path()` maps raw request paths to low-cardinality labels
  (e.g. `/ui/assets/index-Ab3Cd.js` → `/ui/{static}`) to prevent cardinality
  explosion from hashed asset filenames and per-UID path segments.
- Zero overhead when OTLP is not configured: `Option<Arc<OtelMetrics>>` is `None`
  and no allocation occurs per request.

### Object Count Metric — `kms.objects.total` (Step 3)

- Add `ObjectsStore::count_all_non_destroyed(&self) -> InterfaceResult<u64>` default
  method to the `ObjectsStore` trait.  The default returns `Ok(0)` so existing backends
  compile without change; concrete implementations override it.
- Implement `count_all_non_destroyed` for SQLite, PostgreSQL, and MySQL via named SQL
  queries (`count-non-destroyed-objects`) that scan the full `objects` table without
  user/permission filters — a privileged metrics-only operation.
- Add `TODO(redis)` comment in `RedisWithFindex`; Redis remains on the default `Ok(0)`
  pending a `SCAN do::*`-based implementation.
- Add `DbMetricsRecorder::record_object_delta(delta: i64)` method to the recorder trait,
  allowing the database facade to push incremental object-count changes to OTEL without
  a crate-cycle dependency.
- Wire `record_object_delta` in the `Database` facade:
  - `+1` on successful `create()`
  - `-1` on successful `delete()`
  - Pre-computed delta on `atomic()` with Upsert pre-read to distinguish insert vs update;
    TOCTOU drift is corrected by the periodic absolute sync.
- Add `OtelMetrics::objects_total_mirror: Arc<RwLock<i64>>` and
  `update_objects_total(absolute: i64)` using the mirror pattern (same as
  `update_active_keys_count`) to simulate a gauge on `UpDownCounter`.
- Seed `kms.objects.total` at server startup from `count_all_non_destroyed_objects()`
  so the gauge is correct from second 0, not after the first cron tick.
- Add 30-second periodic absolute sync in `cron.rs` alongside the active-keys refresh;
  corrects any drift from TOCTOU races or Redis backends.
- Add `Database::count_all_non_destroyed_objects()` facade that sums counts across all
  registered stores with `saturating_add`, tolerating partial failures.