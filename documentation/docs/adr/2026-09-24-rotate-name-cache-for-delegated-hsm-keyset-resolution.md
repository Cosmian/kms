---
title: "ADR-2026-09-24: Short-TTL Cache for `find_by_rotate_name` Keyset Resolution"
status: "Accepted"
date: "2026-09-24"
authors: "Performance Engineering Team, HSM Integration, contributors"
tags: ["architecture", "decision", "performance", "hsm", "pkcs11", "cache"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-09-24: Short-TTL Cache for `find_by_rotate_name` Keyset Resolution

## Status

Accepted

## Context

`mise bench:load-pkcs11 --delegated --mode sign-verify` (ECDSA-P256 + Ed25519,
concurrency 1/2/4/8) against a SoftHSM2-backed KMS server on commit `4e5ddbb78`
("perf(hsm): optimize PKCS#11 concurrent scaling with session pooling and
spawn_blocking") showed every `verify` operation and `eddsa` sign **peaking at
concurrency=4 and regressing ~10–13% at concurrency=8** — a real, reproducible
saturation point, not measurement noise. Only the two ECDSA sign paths kept
scaling to 8.

A `perf record -F 500 --call-graph dwarf,32768` profile of the running server
(`bench` profile: `opt-level=3`, `debug=2`, `strip=none`) across the full sweep
(617,094 samples) showed self-time dominated by the glibc allocator (`malloc`/
`_int_malloc`/`free` family, ~12% combined) and lock/futex churn
(`pthread_mutex_lock`/`unlock`, `_raw_spin_lock`, ~7% combined) — not by any
cryptographic primitive. `EVP_*` calls and SoftHSM2's own `C_Sign`/`C_Verify`
internals summed to **under 2% self-time total**. The cumulative (children) view
traced the churn to a single call chain present on *every* delegated Sign/Verify
request:

- `Session::call_get_attribute*` — 62.9% children (PKCS#11 `C_GetAttributeValue`)
- `Database::*` / `HsmStore::*` — ~33% children each
- `crypto_op` dispatcher → `walk_keyset_chain` (17.6%) / `resolve_keyset_to_single_uid` (15.6%)
- `SlotManager::checkout_session` — **0.09%** children (the session-pooling fix
  from `4e5ddbb78` already works; this is not a session-contention regression)

Root cause, confirmed by source: `parse_keyset_identifier`
(`crate/server/src/core/uid_utils.rs`) treats **every** plain
`hsm::<slot>::<uuid>` unique identifier (no `@N` suffix) as a bare keyset
reference, by design — this is what makes `Sign`/`Encrypt` on a bare HSM UID
always resolve to the *latest* rotation generation and `Verify`/`Decrypt` walk
the full chain. That routes every single delegated crypto call through
`Database::find_by_rotate_name`, even when the key has never been rotated.
For the HSM-backed `ObjectsStore` (`crate/interfaces/src/hsm/hsm_store.rs`)
this query is implemented as a **full `C_FindObjects` scan of the slot followed
by a `C_GetAttributeValue` round-trip for every object found** — on every
sign/verify call, regardless of concurrency. Concurrent threads all hitting
this scan simultaneously is exactly the saturation point measured at
concurrency=8.

## Decision

Add `RotateNameCache` (`crate/server_database/src/core/rotate_name_cache.rs`),
a `moka::future::Cache`-backed, 2-second-TTL cache in front of
`Database::find_by_rotate_name`, keyed by `(name, generation, owner)`. On a
cache hit the full multi-store scan (SQL query or HSM slot scan) is skipped
entirely; on a miss, the result is computed as before and cached.

The 2-second TTL matches the bounded revalidation window already established
by `ObjectCache` (`crate/server_database/src/core/object_cache.rs`,
`DEFAULT_REVALIDATION_INTERVAL`) — this codebase's existing, accepted
trade-off between hot-path throughput and cross-node consistency. Rather than
rely on the TTL alone for a security-relevant "which generation is current"
resolution, the actual rotation commit paths explicitly invalidate the
specific cache entry so a freshly rotated key is visible immediately:

- `execute_rekey` (`crate/server/src/core/operations/rekey/common.rs`) — the
  single shared orchestrator for SQL-backed `ReKey`, `ReKeyKeyPair`, and
  `ReCertify` (and, transitively, scheduled auto-rotation) — invalidates every
  replacement's `rotate_name` immediately after the atomic commit.
- `rekey_hsm_symmetric` (`crate/server/src/core/operations/rekey/symmetric/hsm.rs`)
  — the dedicated HSM-resident rotation path, which bypasses `execute_rekey`
  entirely (HSM key material is generated directly via `C_GenerateKey`, not
  through `AtomicOperation::Create`) — invalidates the cache immediately after
  both the old and new key's `CKA_LABEL` are updated, the actual point at
  which the new generation becomes the keyset's head.

`ReKeyKeyPair` has no HSM path (`reject_hsm_uid` rejects HSM UIDs outright for
both the symmetric and keypair SQL rekeyers), so no additional call site was
needed there.

## Consequences

### Positive

- **POS-001**: Eliminates a full HSM slot scan (`C_FindObjects` +
  `C_GetAttributeValue` per object) from the per-operation hot path for every
  delegated Sign/Verify/Encrypt/Decrypt call on a non-rotated (or
  recently-resolved) HSM-resident key.
- **POS-002**: Re-running the identical benchmark sweep post-fix: all six
  operation/algorithm combinations now scale **monotonically** through
  concurrency=8 (the 4→8 regression is gone), and absolute throughput improved
  roughly 4–14× across the board — e.g. `verify/ecdsa-p256` at concurrency=8:
  816 → 8,657 ops/s.
- **POS-003**: Uniform fix — `Database::find_by_rotate_name` is the single
  chokepoint used by SQL, HSM, and (non-FIPS) Redis-Findex stores alike, so no
  per-backend special-casing was required.
- **POS-004**: Explicit invalidation on the two real rotation-commit points
  bounds staleness to effectively zero for the common case, with the 2s TTL
  as a safety net for any path not yet covered (e.g. a future rotation
  mechanism), consistent with existing `ObjectCache` precedent.

### Negative

- **NEG-001**: A worst-case 2-second staleness window exists for any rotation
  path that does not explicitly call `invalidate_rotate_name_cache` (mitigated
  today for the only two real HSM/SQL rotation-commit points that exist).
- **NEG-002**: Additional memory footprint — bounded at 10,000 cached
  `(name, generation, owner)` entries by default, each holding a `Vec<(String,
  Attributes)>` (typically 1 entry per keyset generation).
- **NEG-003**: `SetAttribute`'s `RotateName` assignment (first-time keyset
  enrollment) does not explicitly invalidate the cache. This is judged safe:
  the attribute is validated to always equal a fixed derived value (the
  object's own UID for SQL, or its base UID for HSM) — it is not a free-form
  rename that could shadow a different, already-cached name — so any staleness
  is bounded by the same 2s TTL and cannot resolve to a *different* object.

## Alternatives Considered

### Cache only at the HSM store layer (`HsmStore::find_by_rotate_name`)

- **ALT-001 Description**: Add caching inside `crate/interfaces/src/hsm/hsm_store.rs`
  only, since that is where the expensive `C_FindObjects` scan lives.
- **ALT-002 Rejection Reason**: `Database::find_by_rotate_name` already fans
  out across every registered store (SQL default store + one or more HSM
  stores) per call; caching one layer down would still repeat the SQL query
  (which, while cheaper, is a wholly unnecessary DB round-trip for the common
  case) and would need to be duplicated per backend implementation instead of
  once at the point every caller actually goes through.

### Remove keyset semantics for bare HSM UIDs entirely

- **ALT-003 Description**: Change `parse_keyset_identifier` so a plain
  `hsm::<slot>::<uuid>` UID is *never* treated as a keyset reference — only
  `@N`/`@latest` suffixed identifiers would trigger resolution.
- **ALT-004 Rejection Reason**: This is the documented, intentional design
  (see `parse_keyset_identifier`'s own doc comment and
  `ADR-2026-06-30-key-auto-rotation-keyset-chain-design.md`): a bare HSM base
  UID *is* the keyset name, so that `Sign`/`Encrypt` against it always resolve
  to the current head without requiring callers to track generation numbers.
  Removing this would be a breaking behavioral change to the rotation model,
  not a performance fix.

### Exhaustive invalidation at every `rotate_name`-touching call site

- **ALT-005 Description**: Thread explicit `invalidate_rotate_name_cache`
  calls into all 15+ code paths that read or write `Attributes::rotate_name`
  (`create`, `create_key_pair`, `attributes/{add,set,delete,modify}`,
  `recertify`, `auto_rotate`, both rekey SQL rekeyers, both rekey HSM paths).
- **ALT-006 Rejection Reason**: Disproportionate risk for the marginal
  benefit — most of those sites only *read* `rotate_name` for validation or
  set it to a value that must already equal what is cached (see NEG-003); only
  the two paths that actually mint a *new* generation
  (`execute_rekey` and `rekey_hsm_symmetric`) can make a cached "latest" answer
  wrong. Instrumenting every read site would multiply the chance of silently
  missing one, for no additional correctness benefit over the 2s TTL bound
  that already covers it.

### TTL-only (no explicit invalidation)

- **ALT-007 Description**: Rely solely on the 2-second TTL for all staleness,
  matching `ObjectCache`'s stated precedent, and add no invalidation calls at
  all.
- **ALT-008 Rejection Reason**: This is a FIPS-140-3 KMS; a resolvable window
  in which Sign/Verify could route to a stale key generation after an explicit
  administrative rotation is a correctness/security concern, not just a
  performance one. Given the two rotation-commit points are few, well-defined,
  and already had to be touched or read for this investigation, explicit
  invalidation there is essentially free and removes the window entirely for
  the case operators actually exercise.

## Implementation Notes

- **IMP-001**: `RotateNameCache` lives in
  `crate/server_database/src/core/rotate_name_cache.rs`, constructed in
  `Database::new()` (`crate/server_database/src/core/mod.rs`) alongside
  `ObjectCache`/`UnwrappedCache`, and re-exported at the crate root
  (`crate/server_database/src/lib.rs`) to satisfy `unreachable_pub`.
- **IMP-002**: `Database::find_by_rotate_name`
  (`crate/server_database/src/core/database_objects.rs`) checks the cache
  first, falls through to the existing multi-store scan on miss, and
  populates the cache before returning. `Database::invalidate_rotate_name_cache`
  is the public invalidation entry point.
- **IMP-003**: Cache key is `(name, generation, owner)`; invalidation clears
  only the `generation: None` ("bare"/"latest") entry, since that is the only
  entry `resolve_keyset_to_single_uid` (`SingleLatest`/`Bare`/`Latest`) and
  `walk_keyset_chain` populate for the delegated Sign/Verify hot path this fix
  targets. Explicit `@N` generation lookups are comparatively rare (direct
  historical-generation addressing) and remain bounded by the TTL.
- **IMP-004**: `NonZeroUsize::new(N).unwrap_or(NonZeroUsize::MIN)` as a `const`
  is not const-evaluable in this toolchain (`Option::unwrap_or` is not yet a
  stable const fn); `DEFAULT_MAX_CAPACITY` is a plain `usize` constant,
  converted to `NonZeroUsize` at runtime inside `RotateNameCache::new()` —
  no `unsafe` required.
- **IMP-005**: Verification: `cargo test -p cosmian_kms_server_database` (58
  tests, including 3 new `rotate_name_cache` tests: hit/miss/key-isolation,
  invalidation, TTL-expiry) and the `uid_utils`/`rekey`/`recertify`/
  `auto_rotate` suites in `cosmian_kms_server` (37 tests) pass unchanged.
  `cargo clippy --all-targets -- -D warnings` clean on both crates.
- **IMP-006**: Success criteria — re-ran the exact reproducing benchmark
  (`mise bench:load-pkcs11 --delegated --mode sign-verify --algorithm
  ecdsa,eddsa --concurrency 1,2,4,8`) against a rebuilt server: the
  concurrency 4→8 regression is gone on all six operation/algorithm
  combinations, and `documentation/docs/benchmarks/ckms_bench_pkcs11_delegated/report.md`
  reflects the post-fix numbers.

## References

- **REF-001**: [ADR-2026-07-08: Two-Tier Cache Architecture for KMS Object
  Retrieval](2026-07-08-two-tier-cache-architecture.md) — establishes the
  `moka`-backed, bounded-revalidation caching convention this ADR reuses.
- **REF-002**: [ADR-2026-06-30: Key Auto-Rotation Keyset Chain
  Design](2026-06-30-key-auto-rotation-keyset-chain-design.md) — the keyset
  semantics (`rotate_name`, generation chains) that make bare HSM UIDs
  resolve through `find_by_rotate_name` on every call.
- **REF-003**: Relevant source files:
  `crate/server_database/src/core/rotate_name_cache.rs`,
  `crate/server_database/src/core/database_objects.rs`,
  `crate/server_database/src/core/mod.rs`,
  `crate/server/src/core/operations/rekey/common.rs`,
  `crate/server/src/core/operations/rekey/symmetric/hsm.rs`,
  `crate/interfaces/src/hsm/hsm_store.rs`,
  `crate/server/src/core/uid_utils.rs`.
- **REF-004**: `documentation/docs/benchmarks/ckms_bench_pkcs11_delegated/report.md`
  — before/after throughput data for this fix.
