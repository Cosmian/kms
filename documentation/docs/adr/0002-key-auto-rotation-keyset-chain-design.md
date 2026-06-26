---
title: "ADR-0002: KMIP-Compliant Key Auto-Rotation with Keyset Chain Design"
status: "Accepted"
date: "2026-06-21"
authors: "contributors, security architects, HSM operators"
tags: ["architecture", "decision", "cryptography", "kmip", "key-management"]
supersedes: ""
superseded_by: ""
---

# ADR-0002: KMIP-Compliant Key Auto-Rotation with Keyset Chain Design

## Status

Accepted

## Context

The Cosmian KMS must support systematic cryptographic key rotation — replacing old key material with
new material on a schedule or on demand — while satisfying several hard constraints:

1. **KMIP 2.1 compliance**: rotation must be exposed as standard `Re-Key` (§6.1.46),
   `Re-Key Key Pair` (§6.1.47), and `ReCertify` (§4.8) operations, not as KMS-proprietary APIs.
2. **Backward decryption compatibility**: ciphertexts encrypted under generation N must remain
   decryptable after the key is rotated to generation N+1. The rotation chain must be walkable.
3. **Wrapping-key cascades**: rotating a wrapping key must atomically re-wrap all objects currently
   protected by it; partial re-wrap leaves objects unreadable.
4. **HSM-resident keys**: PKCS#11 keys are non-extractable; rotation must happen inside the HSM via
   `C_GenerateKey`, not via software key material manipulation.
5. **Automated scheduling**: operators must be able to set a rotation interval (seconds) and an
   optional offset so the server auto-rotates keys on a background cron task.
6. **Multi-backend portability**: the design must work across SQLite, PostgreSQL, MySQL, and
   Redis-Findex without database-specific rotation code in the operation handlers.
7. **Security invariants**: only the latest generation in a chain may be re-keyed; rotation
   attributes such as `rotate_generation` and `rotate_date` must be server-managed (read-only from
   the client's perspective).

Prior to this change the KMS had no rotation primitives at all; every key was a standalone object
with no chain membership concept.

## Decision

### 1 — Keyset identity via KMIP attributes

A **keyset** is a named sequence of key generations identified by six KMIP attributes stored
directly on every key object:

| Attribute (`Attribute` enum variant) | Rust struct field | Type | Semantics |
|---|---|---|---|
| `RotateName` | `rotate_name` | `TextString` | Keyset name shared by all generations |
| `RotateGeneration` | `rotate_generation` | `Integer` | Monotonically increasing counter (0 = initial) |
| `RotateLatest` | `rotate_latest` | `Boolean` | `true` only on the newest generation |
| `RotateDate` | `rotate_date` | `DateTime` | Server-set timestamp of last successful rotation |
| `RotateInterval` | `rotate_interval` | `Integer` | Auto-rotation period in seconds (0 = disabled) |
| `RotateOffset` | `rotate_offset` | `Integer` | Offset added to `initial_date` for first activation |

These are native KMIP `Attribute` enum variants (not vendor attributes); they are serialised as
standard KMIP TTLV attributes. There is no separate "keyset" object in the database.

Keyset members are addressed via an extended `UniqueIdentifier` syntax:
`<name>@latest`, `<name>@first`, `<name>@<N>` (resolved server-side before the operation
executes). `@latest` and bare `<name>` both resolve to the key with the highest
`RotateGeneration` value.

### 2 — `RekeyOperation` trait and two-phase commit

A `RekeyOperation` trait unifies the rotation logic for symmetric keys, key pairs, and
certificates:

```text
Phase 1 — Prepare new key:
  validate()            → verify permissions, lifecycle, no crypto-param change
  generate_replacement() → create new key material (or new certificate)
  detect_wrapping()     → determine if old key was wrapped
  persist_new_key()     → insert new object with rotate_generation+1, rotate_latest=true

Phase 2 — Commit:
  retire_old_key()      → rotate_latest=false, set deactivation date on old key
  rewrap_dependants()   → find all keys wrapped by old key, re-wrap with new key
  finalize_dependants() → update wrapping-key links on dependant objects
```

The `execute_rekey()` orchestrator in `common.rs` runs these phases in order.
If Phase 2 fails the new key has already been persisted; the old key remains `Active` so no
ciphertext is unreadable. A future cleanup pass can detect and complete the commit
(see IMP-001).

### 3 — `ObjectsStore` trait extensions for keyset queries

Two new methods are added to the `ObjectsStore` trait with default no-op implementations
(enabling gradual rollout and backward-compatible trait evolution):

- `find_wrapped_by(wrapping_key_uid, owner)` — returns all keys wrapped by a given key.
  SQL backends use a JSON path query on the serialised object column;
  Redis-Findex uses a Findex keyword index `wrapped_by::<uid>`.
- `find_by_rotate_name(name, generation, owner)` — returns all generations of a keyset.
  SQL backends use a JSON path query on the attributes column (`$.RotateName`);
  HSM backends enumerate PKCS#11 objects by `CKA_LABEL` and call `parse_label_metadata()`;
  Redis-Findex uses a Findex keyword index `rotate_name::<name>`.
- `find_due_for_rotation(now)` — returns UIDs of Active keys with `rotate_interval > 0`
  whose next rotation instant (`rotate_date + rotate_interval` or
  `initial_date + rotate_interval + rotate_offset`) is ≤ `now`.

### 4 — HSM keyset via `CKA_LABEL`

HSM-resident keys cannot carry arbitrary KMIP attributes; PKCS#11 offers only a fixed
attribute set. Keyset metadata is encoded in `CKA_LABEL` using the convention:

```text
<rotate_name>::<generation>::<base_key_id>[::latest]
```

- `SetAttribute(RotateName)` on an HSM key writes `CKA_LABEL = "<name>::0::<key_id>::latest"`
  (generation 0, `::latest` suffix present on initial creation).
- `SetAttribute(RotateInterval)` writes `CKA_START_DATE`/`CKA_END_DATE` (ceiling-day conversion;
  intervals below 86400 s are rejected; `0` clears the dates).
- `Re-Key` on an HSM UID calls `C_GenerateKey`, computes `new_gen = old_gen + 1`, then writes:
    - old key: `CKA_LABEL = "<name>::<old_gen>::<base_id>"` (no `::latest` suffix)
    - new key: `CKA_LABEL = "<name>::<new_gen>::<base_id>"` (no `::latest` suffix)

The `::latest` suffix written on initial creation is accepted by `parse_label_metadata()` for
backward compatibility but is **not written by Re-Key**; the latest generation is determined by
comparing `RotateGeneration` values, not by the suffix.

`find_by_rotate_name` enumerates PKCS#11 objects, parses their `CKA_LABEL` via
`parse_label_metadata()`, filters by name prefix, and sorts by `rotate_generation`.

### 5 — Try-each keyset decryption

`Decrypt`, `SignatureVerify`, and `MACVerify` support a bare keyset name as the
`UniqueIdentifier`. The server resolves it via `walk_keyset_chain()`, which orders generations
newest→oldest and tries each key in turn until one succeeds. A configurable
`--keyset-warn-depth` threshold (default: 5) causes a server-side `warn!` log entry when the
successful key is at depth ≥ the threshold, prompting operators to re-encrypt old ciphertexts.
No response header is added to the client response.

### 6 — Background rotation scheduler

`cron.rs` (`spawn_auto_rotation_cron`) spawns a dedicated native thread that owns a single-
threaded Tokio runtime. On each tick (driven by `tokio::time::interval`) it calls
`run_auto_rotation(kms)`, which queries `find_due_for_rotation(now)` and dispatches a
`Re-Key` or `Re-Key Key Pair` for each due UID. The thread is started only when
`auto_rotation_check_interval_secs > 0` (disabled by default); the minimum allowed interval
is 60 s.

The cron wiring and scheduler infrastructure are fully implemented. The rotation dispatch
inside `run_auto_rotation` (i.e. triggering the actual `Re-Key` operation per UID) is
marked as a TODO stub and is not yet implemented.

### 7 — Security guardrails enforced server-side

- `RotateGeneration`, `RotateDate`, and `RotateLatest` are rejected in AddAttribute,
  SetAttribute, ModifyAttribute, and DeleteAttribute — they are written exclusively by
  rotation operations.
- Only the key with the highest `RotateGeneration` and `RotateLatest = true` may be the
  subject of a `Re-Key` request; attempting to rotate a retired generation returns an
  explicit error.
- `Re-Key` and `ReCertify` accept only `Active` or `Deactivated` source objects; `PreActive`,
  `Compromised`, `Destroyed`, and `Destroyed_Compromised` are rejected per KMIP §6.1.46.
- `RotateName` values containing `@` are rejected to prevent keyset versioning syntax injection.

## Consequences

### Positive

- **POS-001**: Full KMIP 2.1 compliance — `Re-Key`, `Re-Key Key Pair`, and `ReCertify` are
  standard operations; any KMIP-conformant client can trigger rotation without KMS-proprietary
  extensions.
- **POS-002**: Backward decryption compatibility is maintained transparently; existing ciphertexts
  remain decryptable through the rotation chain without client-side key-management changes.
- **POS-003**: Wrapping-key cascades are atomic at the application level — no orphaned wrapped keys
  after rotation.
- **POS-004**: HSM keyset support is achieved without modifying PKCS#11 key storage; keyset
  metadata is carried entirely in `CKA_LABEL`.
- **POS-005**: The `RekeyOperation` trait makes it straightforward to add new key-type rotation
  (e.g. Covercrypt, JOSE) by implementing only the type-specific `validate` and
  `generate_replacement` methods.
- **POS-006**: Automated scheduling is fully server-side; operators set a policy once and rotation
  happens without external cron jobs or CA intervention.

### Negative

- **NEG-001**: The two-phase commit is not truly atomic at the database level. A process crash
  between Phase 1 (new key persisted) and Phase 2 (old key retired) leaves the database in a
  state where both generations have `rotate_latest = true`. A recovery sweep is not yet
  implemented.
- **NEG-002**: `find_by_rotate_name` and `find_wrapped_by` use JSON path queries on serialised
  object columns (SQL backends). These queries are not indexed and will degrade on very large
  object counts without adding a materialised index column for `rotate_name`.
- **NEG-003**: The `@version` keyset resolution syntax is applied at the KMIP
  `UniqueIdentifier` layer as a KMS extension. KMIP-conformant clients that validate the
  `UniqueIdentifier` format strictly may reject these identifiers before sending them to the
  server.
- **NEG-004**: HSM `rotate_offset` is not supported (HSM rotation scheduling uses
  `CKA_START_DATE`/`CKA_END_DATE`); attempting to set it returns `NotSupported`.

## Alternatives Considered

### Re-import pattern (external rotation)

- **ALT-001 Description**: Revoke the old key; generate new key material outside the KMS;
  import the new key; update all client references to the new UID.
- **ALT-002 Rejection Reason**: Breaks backward decryption compatibility (old ciphertexts
  become unreadable). Requires clients to track UID changes. Not compatible with non-extractable
  HSM keys. No KMIP-standard way to express the replacement relationship.

### Generation suffix in UID

- **ALT-003 Description**: Embed the generation counter directly in the object UUID
  (e.g. `base-uuid-gen-2`), making the UID opaque-but-structured.
- **ALT-004 Rejection Reason**: Violates KMIP §3.1 ("Unique Identifier is opaque to clients").
  Requires all clients to understand the suffix convention. Breaks existing object references
  stored in external systems.

### KMIP `ReplacedObjectLink` chain

- **ALT-005 Description**: Use the standard KMIP `ReplacedObjectLink` / `ReplacementObjectLink`
  link types to form a singly-linked list of generations; walk the chain for decryption.
- **ALT-006 Rejection Reason**: Requires O(N) sequential DB lookups to walk a chain of N
  generations. No efficient batch query for "all members of keyset X". Does not cleanly address
  HSM objects where KMIP links cannot be persisted. The `rotate_name` attribute approach allows
  O(1) lookup of the latest generation and efficient batch retrieval.

### Separate rotation microservice

- **ALT-007 Description**: Implement rotation as a sidecar or external service that polls the
  KMS and issues standard KMIP `Re-Key` requests.
- **ALT-008 Rejection Reason**: Adds operational complexity (separate deployment unit, secret
  management for the sidecar's KMS credentials). Does not address the wrapping-key cascade
  problem (the sidecar would need full read/write access to re-wrap dependants). Latency
  between the sidecar and KMS creates a window where old and new keys coexist without the new
  key being committed.

## Implementation Notes

- **IMP-001**: The `execute_rekey()` two-phase commit should be hardened with a `PendingRotation`
  table or a monotonic `rotate_commit_token` attribute so that crashed Phase-1-only rotations can
  be detected and completed or rolled back by the scheduler.
- **IMP-002**: For SQL backends, consider adding a materialised `rotate_name` column to the
  `objects` table and a composite index `(rotate_name, rotate_generation)` to avoid full-table
  JSON scans as keyset sizes grow.
- **IMP-003**: The server-side `warn!` log emitted at `keyset_warn_depth` should be forwarded
  to an OTEL log exporter and monitored to track re-encryption debt across deployments.
  A future improvement is to expose this as an OTEL counter `kms.keyset_decrypt_depth`.
- **IMP-004**: HSM keyset recovery after a `Re-Key` crash must update `CKA_LABEL` on both the
  old key (strip `::latest` suffix if present) and the new key; key ordering relies on the
  parsed `rotate_generation` integer in the label, not the `::latest` suffix.

## References

- **REF-001**: ADR-0001 — Unwrapped-cache configurable max size
  (`documentation/docs/adr/0001-unwrapped-cache-configurable-max-size.md`)
- **REF-002**: KMIP 2.1 specification §6.1.46 (Re-Key), §6.1.47 (Re-Key Key Pair), §4.8
  (ReCertify), §3.31 (Key state lifecycle), §3.1 (Unique Identifier)
- **REF-003**: Key auto-rotation design document
  (`documentation/docs/kmip_support/key_rotation/index.md`)
- **REF-004**: `RekeyOperation` trait and orchestrator
  (`crate/server/src/core/operations/rekey/common.rs`)
- **REF-005**: `ObjectsStore` trait extensions
  (`crate/interfaces/src/stores/objects_store.rs`)
- **REF-006**: Background rotation scheduler
  (`crate/server/src/cron.rs`)
- **REF-007**: HSM keyset implementation
  (`crate/interfaces/src/hsm/hsm_store.rs`)
- **REF-008**: SQL keyset queries
  (`crate/server_database/src/stores/sql/query.sql`,
   `crate/server_database/src/stores/sql/query_mysql.sql`)
- **REF-009**: PKCS#11 specification v2.40 — `CKA_LABEL`, `CKA_START_DATE`, `CKA_END_DATE`
- **REF-010**: PR #968 — auto-rotation feature implementation
  (`https://github.com/Cosmian/kms/pull/968`)
