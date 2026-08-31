---
title: "ADR-0003: Two-Tier Cache Architecture for KMS Object Retrieval"
status: "Accepted"
date: "2026-07-08"
authors: "contributors, security architects, operators"
tags: ["architecture", "decision", "performance", "security", "cache"]
supersedes: "0001-unwrapped-cache-configurable-max-size.md"
superseded_by: ""
---

# ADR-0003: Two-Tier Cache Architecture for KMS Object Retrieval

## Status

Accepted

## Context

The Eviden KMS serves as an encryption-as-a-service backend: callers repeatedly
request the same key object for bulk encrypt/decrypt workloads. Without caching,
every cryptographic operation requires:

1. A database round-trip to fetch the wrapped `ObjectWithMetadata` (SQLite: ~1 ms;
   PostgreSQL over TCP: ~5–20 ms).
2. An asymmetric or symmetric key-unwrap operation against the KEK
   (RSA-OAEP 2048-bit: ~1–2 ms; AES-256 key-wrap: ~0.05 ms).

In production workloads (e.g. AWS XKS, Google CSE, JOSE decrypt) the same handful
of keys account for >95% of traffic. The combined per-call overhead of 2–22 ms
creates a hard throughput ceiling that cannot be addressed by adding CPU cores.

The KMS distinguishes two structurally different objects:

- **Wrapped objects** — KMIP `ObjectWithMetadata` as stored in the database.
  Key material is encrypted with a KEK; these are safe to cache without additional
  zeroization requirements.
- **Unwrapped objects** — Plaintext key material (AES round-keys, RSA private
  exponents, EC scalars) produced after KEK decryption. These must be treated as
  cryptographic secrets with strict exposure-window requirements.

Mixing the two in a single cache would conflate different security properties and
make it impossible to apply targeted controls (e.g. zeroization on eviction,
disabling plaintext caching without disabling the DB cache).

## Decision

Implement a **two-tier in-memory cache** backed by
[`moka::future::Cache`](https://docs.rs/moka/latest/moka/future/struct.Cache.html)
(lock-free sharded concurrent hash map):

**Tier 1 — `ObjectCache`** (`crate/server_database/src/core/object_cache.rs`):

- Caches `Arc<ObjectWithMetadata>` (wrapped objects) keyed by UID.
- Consulted on every `retrieve_object` / `retrieve_object_arc` call.
- Invalidated explicitly on `update_object`; validated lazily via TTLV fingerprint
  comparison on `validate_cache`.
- No zeroization on eviction: wrapped objects carry no plaintext secret.

**Tier 2 — `UnwrappedCache`** (`crate/server_database/src/core/unwrapped_cache.rs`):

- Caches plaintext `Object` (unwrapped key material) keyed by UID.
- Each entry stores the TTLV fingerprint of the **wrapped** object it originated
  from. `peek()` rejects an entry when the fingerprint of the current wrapped
  object does not match, automatically handling KEK rotation and re-wrapping.
- Zeroization on eviction: `CachedObject::drop` calls `Object::zeroize()` before
  releasing memory, zeroing all `Zeroizing<Vec<u8>>` byte buffers and `SafeBigInt`
  fields (RSA/EC private-key components).
- Configurable absolute TTL (`--unwrapped-cache-max-ttl`) in addition to TTI
  (`--unwrapped-cache-max-age`) to enforce compliance-required plaintext-key
  exposure windows.
- Fully disableable via `--disable-unwrapped-cache` for high-security deployments
  where per-operation KEK unwrap latency is acceptable.

Both caches use `moka::future::Cache` to provide **lock-free concurrent reads**
across Actix-web worker threads with no serialization overhead.

## Consequences

### Positive

- **POS-001**: Database round-trips eliminated for hot keys — typical throughput
  improvement 10–100× for bulk workloads hitting the same key repeatedly.
- **POS-002**: KEK unwrap operations eliminated for hot keys — RSA-OAEP overhead
  (~2 ms/call) does not accumulate across consecutive decrypts of the same key.
- **POS-003**: Lock-free concurrent reads via moka sharding — no global `RwLock`
  serializes Actix worker threads; throughput scales linearly with CPU count.
- **POS-004**: Security properties are separated by tier — operators can disable
  the unwrapped cache independently of the object cache without sacrificing DB
  performance.
- **POS-005**: Fingerprint-based staleness detection catches out-of-band DB
  mutations (direct DB writes from migration tools, another process) without
  requiring an explicit cache flush API.
- **POS-006**: Zeroization-on-eviction limits the window during which plaintext
  key material could be recovered from freed memory pages (cold-boot, memory
  forensics).

### Negative

- **NEG-001**: Additional memory footprint. With default sizes (1000 entries each)
  and typical 256-byte key objects, peak overhead is ~2 MiB for `ObjectCache`
  and ~2 MiB for `UnwrappedCache`.
- **NEG-002**: TTI (`time_to_idle`) resets on every access — a continuously
  accessed hot key is never evicted by TTI alone. Operators must set
  `--unwrapped-cache-max-ttl` to enforce an absolute exposure ceiling for
  compliance environments.
- **NEG-003**: CPU microarchitectural side-channel risk (CacheFX, Prime+Probe).
  Plaintext key material in `UnwrappedCache` occupies resident DRAM pages whose
  cache-line access patterns can be observed by co-resident processes on a shared
  host. Mitigated by short TTL, hardware isolation (SEV-SNP, TDX), or by
  disabling the unwrapped cache entirely.
- **NEG-004**: Concurrent cold-start double-unwrap. Two workers racing on a cold
  key both perform the KEK unwrap; the second `insert()` overwrites the first.
  One unwrap is wasted. Serializing on a per-key mutex would reintroduce lock
  contention — the tradeoff favors throughput.

## Alternatives Considered

### Single unified cache (wrapped objects only)

- **ALT-001 Description**: Cache `ObjectWithMetadata` after the DB fetch; always
  perform the KEK unwrap from the cached wrapped object on each call.
- **ALT-002 Rejection Reason**: Eliminates DB overhead but not crypto overhead.
  For RSA-OAEP KEKs, a 2 ms per-call unwrap cost is the dominant bottleneck in
  bulk workloads. This approach provides no benefit for the most expensive path.

### Single unified cache (unwrapped objects only)

- **ALT-003 Description**: Cache plaintext `Object` directly; skip both DB fetch
  and KEK unwrap on cache hits. Do not maintain a wrapped-object cache.
- **ALT-004 Rejection Reason**: Requires every cache miss to go DB → unwrap in a
  single uninterruptible path. The wrapped-object cache independently eliminates
  DB latency for non-crypto operations (attribute reads, `Locate`, etc.) which
  are cache-hits but not unwrap candidates. Removing it would degrade these
  paths unnecessarily.

### `std::sync::RwLock<HashMap>` (global lock)

- **ALT-005 Description**: Replace moka with a process-wide `RwLock<HashMap>`
  holding all cached entries.
- **ALT-006 Rejection Reason**: A global `RwLock` serializes every read under
  write pressure. With Actix-web using one thread per CPU core, a single
  `update_object` write-lock stalls all concurrent `retrieve_object` reads.
  Profiling confirmed this as a bottleneck under the XKS workload pattern that
  motivated the cache introduction.

### `dashmap::DashMap` (sharded `RwLock`)

- **ALT-007 Description**: Use `DashMap` — a sharded `RwLock`-based concurrent
  hash map — instead of moka.
- **ALT-008 Rejection Reason**: `DashMap` provides no built-in TTL or LRU eviction.
  Implementing eviction correctly in an async context (background task, wake-up
  scheduling) duplicates functionality that moka provides out-of-the-box, tested,
  and tuned. moka also supports both TTI and TTL independently, which is required
  for the compliance use-case (see NEG-002 mitigation above).

### Per-operation fresh fetch (no cache)

- **ALT-009 Description**: Disable caching entirely; every operation hits DB and
  performs a full KEK unwrap.
- **ALT-010 Rejection Reason**: Unacceptable throughput for production workloads.
  Available via `--disable-unwrapped-cache` for operators who require it for
  security policy compliance.

## Implementation Notes

- **IMP-001**: Both caches are constructed inside `Database::new()` in
  `crate/server_database/src/core/mod.rs` and held as fields on the `Database`
  struct. They share lifecycle with the database connection pool.
- **IMP-002**: `UnwrappedCache::disabled = true` short-circuits both `peek()` and
  `insert()` with an immediate return — no lock acquisition, no hash computation.
  This means the flag carries zero runtime overhead when disabled.
- **IMP-003**: The TTLV fingerprint used for cache validation is computed by
  `Fingerprinter` (`crate/server_database/src/core/fingerprinter.rs`) using
  `xxhash` on the TTLV-serialized form of the object. Collision probability is
  negligible for cache-validation purposes (not a cryptographic hash).
- **IMP-004**: `Object::zeroize()` is implemented in
  `crate/kmip/src/kmip_2_1/kmip_objects.rs`; it delegates to `KeyBlock::zeroize()`
  → `KeyValue::zeroize()` → `KeyMaterial::zeroize()`. `SafeBigInt::zeroize()` is
  called for all RSA/EC private-key integer components.
- **IMP-005**: The `moka` absolute TTL (`time_to_live`) and TTI (`time_to_idle`)
  can be set simultaneously on the same builder; moka evicts entries at
  `min(last_access + TTI, insert_time + TTL)`.
- **IMP-006**: Success criteria — the XKS benchmark at 100 rps on a single 4-core
  instance should show ≥80% reduction in average latency for the decrypt path with
  warm cache vs. cold start.

## References

- **REF-001**: ADR-0001 — Configurable `UnwrappedCache` max size (superseded by
  this ADR which generalizes all cache configuration parameters).
- **REF-002**: [moka crate documentation](https://docs.rs/moka/latest/moka/future/struct.Cache.html)
- **REF-003**: [CacheFX paper — Cache Side-Channels in Key Management Systems](https://arxiv.org/abs/2010.02432)
  — motivates the `--disable-unwrapped-cache` flag and absolute TTL.
- **REF-004**: Relevant source files:
  `crate/server_database/src/core/object_cache.rs`,
  `crate/server_database/src/core/unwrapped_cache.rs`,
  `crate/server_database/src/core/mod.rs`,
  `crate/kmip/src/kmip_2_1/kmip_objects.rs`,
  `documentation/docs/configuration/object-cache.md`
