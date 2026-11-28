# 5.25.0 release notes (full text)

Full text of the `## [5.25.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.25.0] - 2026-07-09

### 🚀 Features

#### Key Rotation ([#968](https://github.com/Cosmian/kms/pull/968))

- Implement KMIP `ReKey` (symmetric), `ReKeyKeyPair` (RSA, EC, ML-KEM, ML-DSA, SLH-DSA, X25519, secp256k1), and `ReCertify` (certificate rotation, §4.8)
- Implement keyset resolution with `name@latest`, `name@first`, `name@N` syntax; try-each-key decryption walks the chain newest→oldest for `Decrypt`, `SignatureVerify`, `MACVerify`
- KMIP 2.1 §3.31 state-based key selection (Deactivated/Compromised accepted for processing ops) and §4.57 auto-deactivation when `DeactivationDate` is reached
- HSM keyset support: metadata stored in `CKA_LABEL` (`name::gen::base_id[::latest]`); Re-Key on HSM UIDs generates a new HSM key
- `--keyset-warn-depth` flag (default: 5) returning `X-KMS-Keyset-Depth` response header; traversal unbounded (cycle-detection only)
- CLI: `ckms sym/ec/rsa/pqc keys re-key`, `set-rotation-policy`, `get-rotation-policy` subcommands; `--rotation-name`, `--rotation-interval`, `--rotation-offset` flags on all `keys create` commands
- Web UI: **Rotation Policy** top-level sidebar section; Set/Get/Re-Key pages for all 4 key types; PQC entry hidden in FIPS mode

#### Auto-rotation Scheduler ([#970](https://github.com/Cosmian/kms/pull/970))

- `run_auto_rotation()` queries `find_due_for_rotation(now)`, routes to `ReKey` or `ReKeyKeyPair`, skips HSM-resident keys (`hsm::` prefix)
- `dispatch_renewal_warnings()` emits `info!` logs at [30, 7, 1]-day thresholds before next rotation deadline
- `kms.key.auto_rotation` OpenTelemetry counter with `uid`, `algorithm`, `outcome` labels

#### JWKS Endpoint

- `GET /.well-known/jwks.json` unauthenticated public-key discovery (RFC 7517); serves RSA, EC P-256/P-384/P-521, Ed25519 (non-FIPS); ETag + HTTP 304 caching; `X-JWKS-Truncated` header on overflow
- New config flags: `--jwks-endpoint-enabled` (default: `false`), `--jwks-endpoint-max-keys` (default: 50), `--jwks-endpoint-auto-tag` (default: `true`)

#### Performance ([#1016](https://github.com/Cosmian/kms/pull/1016), [#1020](https://github.com/Cosmian/kms/pull/1020))

- In-memory object cache (`ObjectCache`) backed by `moka` — lock-free sharded reads with TTI eviction and configurable LRU capacity
- Dedicated CEK cache for JOSE `/encrypt`/`/decrypt` endpoints
- Binary TTLV bytes serializer/deserializer (`TTLVBytesSerializer` / `TTLVBytesDeserializer`) for zero-copy wire encoding
- `--unwrapped-cache-max-size` (env: `KMS_UNWRAPPED_CACHE_MAX_SIZE`, default: 1000; was hardcoded 100)
- `--http-workers` (env: `KMS_HTTP_WORKERS`); SQLite 64 MiB page cache + 256 MiB mmap window; PostgreSQL `prepare_cached` for tag-list queries
- `ckms bench` subcommand: TTLV bytes, TTLV JSON, JOSE, and HTTP load benchmarks

#### Web UI / Search Objects ([#968](https://github.com/Cosmian/kms/pull/968))

- Locate table: Crypto Algorithm and Crypto Length columns (sortable); sort controls on all columns; Date defaults to descending; horizontal scroll; pagination default raised to 50 (options: 50/100/500/1000)
- `HashMapDisplay` filters empty/null/undefined entries so certificate maps show only populated fields

### 🐛 Bug Fixes

#### Database

- Add `objects(owner)`, `objects(state)`, `read_access(userid)`, `objects(wrapping_key_id)` indexes to PostgreSQL and MySQL (were SQLite-only)
- PostgreSQL: set `RecyclingMethod::Verified` to eliminate dead-connection races after primary failover; add `tracing::warn!` at every `pg_retry!` / `pg_retry_tx!` retry point ([#1039](https://github.com/Cosmian/kms/pull/1039))

#### KMIP / Key Rotation ([#968](https://github.com/Cosmian/kms/pull/968))

- Fix RSA/EC `ReKeyKeyPair` in FIPS mode: propagate `CryptographicUsageMask` from the old key pair into the new `CreateKeyPair` request
- Fix HSM self-wrap: skip `hsm::` UID prefix during server-wide KEK wrapping to prevent infinite recursion
- Fix `setup_object_lifecycle`: date-based Active/PreActive transitions and `activation_date` storage for PreActive keys

#### Web UI ([#968](https://github.com/Cosmian/kms/pull/968))

- Fix Date column: dates now returned as milliseconds; Locate sorter normalizes all timestamps to the same unit
- Fix Certificate Issuance page Option 3 to call `ReCertify` (new UID + replacement links) instead of `Certify` (in-place upsert)

#### WASM

- Fix build broken by `tracing-appender 0.2.5` / `symlink` crate incompatible with `wasm32-unknown-unknown`; resolved by upgrading to `cosmian_logger 0.7.2` ([#1020](https://github.com/Cosmian/kms/pull/1020))

### 📚 Documentation

- Key auto-rotation spec: 6 rotation scenarios, policy attributes, server-side scheduler, and implementation roadmap ([#968](https://github.com/Cosmian/kms/pull/968))
- `integrations/jose/jwks_endpoint.md` — JWKS quickstart, sequence diagram, key selection, and rotation guide
- `configuration/object-cache.md` — Object & Unwrapped Caches reference ([#1016](https://github.com/Cosmian/kms/pull/1016))
- `configuration/log-reference.md` — per-component log call-site directory with interactive level-filter UI

### ⚙️ CI / Build

- Fix `test_iris.sh` / `test_edb_tde.sh` empty-port assignment (missing `source kms_server.sh`); gate Windows tests to pull requests only
- `crate/crypto/build.rs`: emit `cargo:rerun-if-env-changed=CFLAGS` ([#1016](https://github.com/Cosmian/kms/pull/1016))
- Add `log-index-check` CI job: fails build when `log-reference.md` is out of sync with source call-sites
