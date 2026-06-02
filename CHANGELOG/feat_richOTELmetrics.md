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
  method to the `ObjectsStore` trait.  The default logs a `warn!` and returns `Ok(0)`,
  making it visible when a new backend forgets to implement it.
- Add explicit silent `Ok(0)` overrides to `RedisWithFindex` and `HsmStore` to suppress
  the warning for intentionally deferred implementations.
- Implement `count_all_non_destroyed` for SQLite, PostgreSQL, and MySQL via named SQL
  queries (`count-non-destroyed-objects`) that scan the full `objects` table without
  user/permission filters — a privileged metrics-only operation.
- Change `kms_objects_total` and `active_keys_count` from `UpDownCounter<i64>` to
  `Gauge<i64>` — the semantically correct OTEL instrument for an absolute current value.
  This eliminates the `objects_total_mirror` and `active_keys_count_value` `Arc<RwLock>`
  mirror fields; `update_objects_total` and `update_active_keys_count` now call
  `gauge.record(absolute, &[])` directly.
- Remove `DbMetricsRecorder::record_object_delta` and all per-operation delta wiring
  (`+1` on create, `-1` on delete, Upsert pre-read in atomic) — the gauge is updated
  exclusively by the startup seed and the 30-second cron absolute sync, which is
  sufficient accuracy for a metrics gauge.
- Seed `kms.objects.total` at server startup from `count_all_non_destroyed_objects()`
  so the gauge is correct from second 0, not after the first cron tick.
- Add 30-second periodic absolute sync in `cron.rs` alongside the active-keys refresh.
- Add `Database::count_all_non_destroyed_objects()` facade that sums counts across all
  registered stores with `saturating_add`, tolerating partial failures.

### Object Count Metric — Redis-findex backend (Step 3, continued)

- Implement `count_all_non_destroyed` for the `RedisWithFindex` backend using an
  O(1) counter key (`kms::metrics::live_object_count`) instead of a full key scan.
- **`ObjectsDB`**: add 4 new methods — `adjust_live_count(delta)` (`INCRBY`),
  `get_live_count()` (`GET`, returns `None` when key absent), `set_live_count(count)`
  (`SET`, bootstrap only), and `scan_count_non_destroyed()` (one-time SCAN+decrypt
  to establish the baseline on first boot or after `FLUSHDB`).
- **`RedisWithFindex`**: add `is_live(state) -> bool` helper; wire `adjust_live_count`
  into `create` (+1), `update_state` (±1 on boundary cross), `delete` (-1 for live
  objects only), and `atomic` (accumulate `live_delta` for the batch, emit one
  `INCRBY` after the transaction succeeds).
- **`count_all_non_destroyed`**: fast path reads the counter key (O(1), no
  decryption); if absent it falls back to `scan_count_non_destroyed`, persists the
  result, then returns it.  After the first call the fast path is always taken.
- **Test** (`test_live_count_counter`): 6-step integration test covering create →
  destroy → delete-live → delete-destroyed → fast-path count → bootstrap-SCAN count.
  Registered in `test_db_redis_with_findex`.
  Tagged `#[ignore = "Requires a running Redis instance"]`.