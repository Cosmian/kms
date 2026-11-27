# Changelog — feat/richOTELmetrics

## Features

### Database Metrics Wiring — `kms.database.operations.total`, `kms.database.operation.duration` (Step 1)

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

### HTTP Metrics Wiring — `kms.http.requests.total`, `kms.http.request.duration`, `kms.active.connections` (Step 2)

- Add `OtelHttpMetrics` Actix-web middleware (`crate/server/src/middlewares/otel_http_middleware.rs`)
  that records `kms.http.requests.total` (counter with `method`, `path`, `status`
  attributes), `kms.http.request.duration` (histogram with `method`, `path`, `status`), and
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

### Object Count Metric — `kms.objects.total`, Redis-findex backend (Step 3, continued)

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

### Active Key Count Metric — `kms.keys.active.count` V2 (Step 3.bis)

Replace the previous Locate-based implementation with a privileged backend count
that returns the number of non-destroyed key objects (`SymmetricKey`, `PrivateKey`,
`PublicKey`, `SplitKey`) across all backends.  "Non-destroyed" means the object
state is not `Destroyed` or `Destroyed_Compromised`.

- **`ObjectsStore` trait** (`crate/interfaces`): add two new default methods —
  `count_non_destroyed_keys()` (default: `warn!` + `Ok(0)`) and `reconcile_counts()`
  (default: no-op `Ok(())`), keeping all existing backends compilable without changes.
- **SQL backends** (SQLite / PostgreSQL / MySQL): add named SQL queries
  (`count-non-destroyed-keys-sqlite`, `count-non-destroyed-keys-pg`,
  `count-non-destroyed-keys`) that filter `objects` by `ObjectType IN (...)` and
  `state NOT IN ('Destroyed', 'Destroyed_Compromised')` using backend-specific
  JSON extraction syntax.
- **HSM store — `count_non_destroyed_keys`**: implemented by iterating all available
  slots via `hsm.find(slot_id, HsmObjectFilter::Any)` and summing results.  All HSM
  objects are non-destroyed active keys by definition (deleted keys are removed from
  the device, not marked Destroyed).
- **HSM store — `count_all_non_destroyed` bug fix**: the previous `Ok(0)` stub
  (incorrect comment: "HSMs do not expose a key-count API") is replaced with a
  delegation to `count_non_destroyed_keys()`.  PKCS#11 `C_FindObjects` is sufficient
  to count objects.  `kms.objects.total` now correctly includes HSM-backed keys.
- **Redis-findex — `ObjectsDB`**: add O(1) counter key `kms::metrics::active_key_count`
  with helpers `adjust_active_key_count(delta)`, `get_active_key_count()`,
  `set_active_key_count(count)`, and `scan_count_non_destroyed_keys()` (bootstrap SCAN).
- **Redis-findex — `RedisWithFindex`**: add `is_key_type(ObjectType) -> bool` helper;
  wire `adjust_active_key_count` into `create`, `update_state`, `delete`, and `atomic`
  mirroring the existing `live_delta` pattern. Implement `count_non_destroyed_keys`
  (O(1) fast path / bootstrap SCAN fallback) and `reconcile_counts` (scans both
  `live_object_count` and `active_key_count` counters atomically).
- **Database facade** (`crate/server_database`): add `count_non_destroyed_key_objects()`
  and `reconcile_all_object_counts()` aggregating across all registered stores.
- **Cron** (`crate/server/src/cron.rs`): remove dead Locate-based implementation;
  replace with `database.count_non_destroyed_key_objects()` on the 30-second tick and
  a 5-minute `reconcile_all_object_counts()` tick for counter drift correction.
- **Startup seed** (`crate/server/src/core/kms/mod.rs`): seed `kms.keys.active.count`
  at startup from `count_non_destroyed_key_objects()` (non-fatal, same pattern as
  `kms.objects.total`).
- **Test** (`test_active_key_count_counter`): 6-step integration test for the Redis
  counter lifecycle — create 2 keys, create non-key object, deactivate, destroy,
  delete, bootstrap-SCAN reconcile.  Tagged `#[ignore = "Requires a running Redis instance"]`.
- **Test** (`test_count_all_non_destroyed_delegates_to_count_non_destroyed_keys`):
  pure in-process unit test using a `MockHsm` (2 slots, 3+2 keys) that verifies
  `count_all_non_destroyed` returns 5 and equals `count_non_destroyed_keys`.
  Runs without any hardware.  Added `tokio` as a dev-dependency to
  `cosmian_kms_interfaces`.


### Cache and HSM Operation Metrics — `kms.cache.operations.total`, `kms.hsm.operations.total` (Step 4)


- Add `hsm_model_from_prefix(hsm_instances, prefix) -> &str` to
  `crate/server/src/core/uid_utils.rs`.  Looks up the human-readable HSM model
  label (e.g. `"softhsm2"`, `"utimaco"`) from the configured `hsm_instances`
  slice and falls back to the prefix string itself when no matching instance is
  found, ensuring the metric label is always non-empty.
- Export `HsmInstanceParams` from `crate/server/src/config/mod.rs` (re-exported
  through `params/mod.rs`) so that `uid_utils` and future callers can reference
  it without reaching into private sub-modules.
- Wire `kms.cache.operations.total` in `get_unwrapped()`
  (`crate/server/src/core/kms/other_kms_methods.rs`): emit `record_cache_operation("get", "hit")`
  on a cache hit, `record_cache_operation("get", "miss")` on a miss, and
  `record_cache_operation("insert", "ok")` after a successful cache population.
- Wire `kms.hsm.operations.total` at three dispatch points:
  - `perform_crypto_operation()` in `key_ops/crypto_op.rs` — covers all six
    oracle-routed operations (Encrypt, Decrypt, Sign, SignatureVerify, MAC,
    MACVerify) via the `ResolvedKey::Oracle` arm.  Uses `Op::OP_NAME` as the
    operation label and `hsm_model_from_prefix` for the model label.
  - `wrap_using_crypto_oracle()` in `core/wrapping/wrap.rs` — emits
    `record_hsm_operation("Wrap", model)` after the oracle `encrypt` call.
  - `unwrap_using_crypto_oracle()` in `core/wrapping/unwrap.rs` — emits
    `record_hsm_operation("Unwrap", model)` after the oracle `decrypt` call.
- Add 4 unit tests in `core::uid_utils::tests` covering legacy `"hsm"` prefix,
  new `"hsm::softhsm2"` format, multi-instance selection, and unknown-prefix
  fallback.  All tests are sync, require no async runtime, and pass without
  hardware.

## Testing

### Mockall test infrastructure

- Add `mockall = "0.13"` as a dev-dependency of `cosmian_kms_interfaces`.
- Replace the 130-line hand-rolled `MockHsm` struct (with full `impl HSM`) in
  `crate/interfaces/src/hsm/hsm_store.rs` with a `mockall::mock!`-generated
  `MockHsm` (~20 lines of method signatures).  The macro generates expectation
  machinery for all 14 async methods; `hsm_lib` is a concrete no-op `{ None }`
  to sidestep mockall's limitation with `&self`-bound reference return types.
- The `test_count_all_non_destroyed_delegates_to_count_non_destroyed_keys` test
  now uses `mock.expect_get_available_slot_list()` / `mock.expect_find()` with
  `returning(...)` closures instead of a bespoke `HashMap`-based data structure.
- `MockRecorder` in `crate/server_database` is retained as-is: it is a stateful
  recorder (collects `(op, backend, outcome)` triples in a `Vec`) where mockall
  would add complexity without reducing code.
