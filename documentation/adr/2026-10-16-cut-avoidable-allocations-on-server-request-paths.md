---
title: "ADR-2026-10-16: Cut Avoidable Heap Allocations on the KMIP Codec and Server Request Paths"
status: "Proposed"
date: "2026-10-16"
authors: "KMS contributors, performance engineers, operators, security auditors"
tags: ["architecture", "decision", "performance", "kmip", "ttlv", "allocations", "breaking-change"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-16: Cut Avoidable Heap Allocations on the KMIP Codec and Server Request Paths

## Status

**Proposed** | Accepted | Rejected | Superseded | Deprecated

## Context

Every KMIP request through `POST /kmip` (binary TTLV) and `POST /kmip/2_1` (TTLV-JSON) goes through the same
codec pipeline in `crate/kmip`, then through the server skeleton, the object cache and the database layer:

```text
request:  bytes | JSON -> TTLV tree -> from_ttlv -> RequestMessage -> dispatch -> operation
response: ResponseMessage -> to_ttlv -> TTLV tree -> to_bytes | JSON
```

Measured on the PR's merge-base (`77beb3827`, `develop`), the codec and per-request copying dominated the
server-side cost of a small KMIP operation, and the KMIP endpoints were noticeably slower than the JOSE
endpoint (`/v1/crypto`) for the same operation. Causes found by reading the code and counting allocations:

**Codec (`crate/kmip`)**

- `TtlvDeserializer` owned the TTLV tree, so `from_ttlv` and every nested walker (structure, enum, array,
  adjacently tagged, untagged) cloned whole subtrees to hand a child to the next deserializer.
- `ByteString` decoding opened a tracing span and evaluated `cosmian_logger::trace!` once **per byte**. That
  macro resolves the caller name even when tracing is disabled.
- `ByteString` values went through an intermediate `String` (hex) in both directions.
- `TTLV::to_bytes` serialized each Structure into a temporary buffer and copied it into its parent, once per
  nesting level.
- Header time stamps were serialized as a 9-integer tuple; the wire decoder over-reserved child slots and
  allocated for padding.
- Every TTLV node owned its `tag: String`, and every enumeration its `name: String`, although both are almost
  always static KMIP names.

**Handlers and server core (`crate/server`)**

- The binary handler decoded the request twice (audit hooks, then dispatch) and decoded the **response** bytes
  a third time for the audit hooks although it already held the response TTLV. `/kmip/2_1` took the body as a
  `String`.
- `Database::retrieve_object` deep-cloned `Object` + `Attributes` on every object-cache hit although the cache
  stores an `Arc`; `retrieve_object_for_operation` deep-cloned each candidate again after the permission check.
- Many operations cloned a whole `Object`/`Attributes` from an owned value that was dead afterwards (Activate,
  Revoke, Get/Export, key-pair creation, attribute operations) or copied key material that could be borrowed
  (`KeyBlock::key_bytes()` in symmetric Decrypt, FPE, MAC, split/join and derive key).
- Smaller per-request costs: per-request label `String`s in OpenTelemetry metrics, a `HashSet` built per
  role check, JWK cloning on every token check, protected-header parsing through `serde_json::Value` in JOSE,
  a double-collected body in the AWS XKS SigV4 middleware, a canonical-bytes `Vec` + `String` per audit event.

**Persistence (`crate/server_database`)**

- SQLite deep-cloned every `AtomicOperation` to build an owned, `'static` copy for the writer closure and
  re-converted each SQL string (`$N` → `?N`) on every execution. PostgreSQL went through `serde_json::Value`
  for every JSON column read and write; MySQL used `to_string_pretty` plus `Value`.

The server must keep its wire output byte-identical: KMIP clients, test vectors and persisted audit hashes
depend on it.

While auditing the `Get`/`Export` clone sites, a separate defect surfaced: the write-back of the `Fresh`
bit could persist an auto-unwrapped key (COSMIAN-2026-031, see Decision 10).

## Decision

Remove avoidable copies and allocations on request paths without changing the wire format. Changes are
grouped by area; the first two groups carry most of the measured effect.

### Codec

- **1. Borrow the TTLV tree when deserializing.** `TtlvDeserializer<'a>` holds `&'a TTLV` and exposes the
  constructor `TtlvDeserializer::from_ttlv(&'a TTLV)`. Walkers pass child references instead of cloning
  subtrees. The free function `from_ttlv<'a, T>(s: TTLV)` keeps its **by-value** signature (about 160 call
  sites, annotated `#[expect(clippy::needless_pass_by_value)]`) and borrows internally.
- **2. Decode `ByteString` directly**, without an intermediate `String` and without the per-byte tracing span.
- **3. Exact-size TTLV encoding.** `TTLV::to_bytes` computes every Structure length first and writes into one
  buffer of the exact size. Padding is read into a stack buffer; at most 4 child slots are reserved per
  Structure when decoding.
- **4. Direct `DateTime` encoding** of whole-second header time stamps through a `$KmipDateTime` newtype marker
  (same technique as `Interval`), instead of a 9-integer tuple.
- **5. `TTLV.tag` and `KmipEnumerationVariant.name` become `Cow<'static, str>`.** Serializers and the binary
  decoder borrow static names (`strum::IntoStaticStr`, via a bound on `KmipTag`); the JSON deserializer
  stores known KMIP 2.1 tag names as borrowed values, but it still allocates the tag `String` while parsing
  (it is dropped when the name is known), so the `/kmip/2_1` request decode saves no allocation from this. This is a **breaking change of the `cosmian_kmip` public API**
  (`x.tag.as_str()` → `&*x.tag` / `x.tag.as_ref()`; build tags with `.into()`).

### Handlers and server core

- **6. Decode once in the handlers.** The binary handler decodes the request once and passes the TTLV on; the
  audit hooks receive the response TTLV that dispatch already produced. `/kmip/2_1` takes `Bytes` and parses
  a borrowed `&str`.
- **7. Share cached objects.** `Database::retrieve_objects` and `retrieve_object_for_operation` return
  `Arc<ObjectWithMetadata>` and deep-clone only when an operation mutates (`Arc::make_mut` /
  `Arc::unwrap_or_clone`). `ObjectWithMetadata::into_parts` moves `id`/`object`/`attributes` out of an owned
  value.
- **8. Borrow and move.** Key material is borrowed with `KeyBlock::key_bytes_ref()` in symmetric Decrypt, FPE,
  MAC, split/join and derive key; Activate, Revoke, Get/Export, key-pair creation and the attribute operations
  move instead of cloning; audit `AuditResult::as_canonical_str` returns `Cow` and the row hash is streamed
  (canonical bytes unchanged); middlewares, JOSE headers, AWS XKS SigV4 body, Google CSE and the
  rotate-name cache drop per-request copies.

### Persistence

- **9. SQL layers.** SQLite converts each query once and serializes objects/attributes before entering the
  writer closure; PostgreSQL reads and writes `Json<T>`; MySQL drops the intermediate `Value`.

### Security fix landed with the refactor

- **10. COSMIAN-2026-031.** `export_get` snapshotted the *already unwrapped* object as "the DB form" and wrote it
  back to flip the `Fresh` bit. It now reads the stored object (cache) for the write-back. See `SECURITY.md`
  and the regression tests in `crate/server/src/tests/security_regression.rs`. It sits in this PR because
  the clone-to-move refactor of `export_get` is where it was found and fixed; it is not a performance change.

## Measured Effect

### Method

A throwaway integration test in `crate/kmip` with a counting `#[global_allocator]`, copied unchanged into three
worktrees and run with `cargo test -p cosmian_kmip --release --test alloc_measure -- --nocapture`:

| Column | Tree |
|---|---|
| Base | `77beb3827` (merge-base with `develop`) |
| C1 | `d70bf88b2` (commit 1: codec and handler changes, decisions 1–4 and 6) |
| Head | `bc49681f1` (measured tree; code unchanged through HEAD `ccc23ffc3`) |

It encodes and decodes a KMIP 2.1 `Encrypt` request and `EncryptResponse` (64 B and 4096 B payloads). The
`/kmip` rows read `TTLV::from_bytes` + `from_ttlv`; the `/kmip/2_1` rows read `serde_json::from_slice` +
`from_ttlv`, as the handler does. Allocation counts are exact (one warm-up call, then one counted call). Times
are the mean of 3000 single-threaded iterations: treat them as ±10 % (shared machine, no CPU pinning). The
harness was deleted afterwards. Test fixtures are fixed, so the three trees produce comparable output.

### Wire output is byte-identical

The harness hashed (FNV-1a 64) the encoded request and response, binary and JSON, for both payload sizes. The
8 distinct hashes (4 artifacts × 2 sizes) are identical on all three trees (Base, C1, Head), e.g. 4 KiB: `req_bin 00da6cf0f59a05bb`, `res_bin ce7e5b09a27441f6`, `req_json 0bc3a94011d00079`,
`res_json 1e44ce30f9eda498`. A semantic round trip (`bytes → TTLV → RequestMessage == original`) also passed on
each tree. This covers `Encrypt`/`EncryptResponse` only; the broader guarantee rests on the existing wire,
round-trip and TTLV vector tests (`cargo test -p cosmian_kmip --lib`: 236 passed; workspace lib suites passed in
FIPS and non-FIPS).

### Whole-path codec work per request (sum of the stages a request actually executes)

`/kmip` (binary): request decode + response encode, plus the response re-decode for audit on Base only.

| Payload | Allocations Base → C1 → Head | Allocated bytes Base → C1 → Head | Time Base → C1 → Head |
|---|---|---|---|
| 64 B | 197 → 86 → **32** | 21 073 → 9 066 → **8 356** | 19.7 → 11.8 → **11.3 µs** |
| 4096 B | 204 → 86 → **32** | 88 337 → 29 226 → **28 516** | 188.5 → 29.6 → **29.2 µs** |

`/kmip/2_1` (JSON): request decode + response encode.

| Payload | Allocations Base → C1 → Head | Allocated bytes Base → C1 → Head | Time Base → C1 → Head |
|---|---|---|---|
| 64 B | 183 → 101 → **59** | 15 660 → 11 027 → **10 484** | 23.4 → 17.1 → **18.7 µs** |
| 4096 B | 197 → 111 → **69** | 98 658 → 61 907 → **61 364** | 242.9 → 77.5 → **81.0 µs** |

Reading the numbers:

- Binary path: **−84 % allocations**, **−68 % bytes**, and **6.5× less time at 4 KiB** (1.7× at 64 B) versus
  Base. The 4 KiB time gain comes almost entirely from removing the per-byte `trace!`/span in `ByteString`
  decoding (commit 1).
- The `Cow` tag change (decision 5) removes about 54 more allocations per binary request and about 42 per JSON
  request (86 → 32, 111 → 69). All of the JSON saving is on the response encode (66 → 24); the JSON request
  decode is unchanged (41 allocations at 4 KiB on C1 and Head) but almost no bytes and **no measurable time** (Head vs C1 differences are inside
  the ±10 % noise). It is justified by allocator pressure, not latency.
- JSON path: −65 % allocations, −38 % bytes, 3× less time at 4 KiB. The JSON response encode still allocates
  28 times (4 KiB), dominated by `serde_json` output buffers.

### Server-level figures (from the former `CHANGELOG/rust_reduce_allocs.md`, consolidated into `CHANGELOG.md` 5.29.0 and kept in git history; not independently reproduced)

Single sample, debug build, counting allocator, base `20274da5b` vs this branch (reported by the author of
the change): `retrieve_object_for_operation` on a cached key 36 → 3 allocations (42 823 → 13 264 B);
SQLite `atomic(UpdateObject)` 57 → 39 allocations (12 713 → 7 391 B).

### Not measured

- End-to-end request latency or throughput through Actix, TLS and the database. The saved codec time (about
  160 µs for a 4 KiB `Encrypt`, about 8 µs for a small request) is small against a network round trip and must
  not be read as a percentage of total latency.
- PostgreSQL and MySQL reads/writes, the middlewares, JOSE, AWS XKS, Google CSE, audit hashing, the
  `/kmip/2_1` body `String` → `Bytes` change, `key_bytes_ref()` in `Encrypt` (one key-sized copy, by
  inspection) and the `HttpClient` retry change.
- Multi-threaded allocator contention, which lower allocation counts should only help.

## Consequences

### Positive

- **POS-001**: About 84 % fewer allocations and 68 % fewer allocated bytes in the codec work of a binary
  `Encrypt`; about 65 % fewer allocations on the JSON path.
- **POS-002**: Decoding a 4 KiB binary `Encrypt` request is about 15× faster (167 µs → 11 µs), which removes
  most of the codec gap between the KMIP and JOSE endpoints.
- **POS-003**: The response TTLV is no longer re-decoded for audit, and a cache hit no longer deep-clones the
  object, which shortens the lifetime of plaintext key copies in memory.
- **POS-004**: Wire output is byte-identical (verified for `Encrypt` on three trees), so no client, vector or
  persisted-audit migration is needed.
- **POS-005**: A real defect (COSMIAN-2026-031, plaintext write-back of an unwrapped key) was found and fixed
  in the same pass.

### Negative

- **NEG-001**: **Breaking API change in `cosmian_kmip`**: `TTLV.tag` and `KmipEnumerationVariant.name` are
  `Cow<'static, str>`. Downstream crates must migrate (`.as_str()`, `"X".to_owned()` constructors); every use
  in this workspace was migrated in this PR.
- **NEG-002**: `TtlvDeserializer` carries a lifetime parameter that spreads to every walker type in
  `crate/kmip/src/ttlv/kmip_ttlv_deserializer/`.
- **NEG-003**: The `$KmipDateTime` marker is a second private serializer convention next to `Interval`.
- **NEG-004**: Shared `Arc<ObjectWithMetadata>` makes mutation sites explicit (`make_mut`/`unwrap_or_clone`);
  a missed clone-before-mutate would leak a mutation into the cache. COSMIAN-2026-015 (never persist unwrapped
  key material) constrains every such site.
- **NEG-005**: SQLite now serializes before entering the writer closure, so a serialization error surfaces
  before the transaction starts (same error text).
- **NEG-006**: Allocation work remains: `ByteString` payloads are still copied once into the tree, and the
  JSON response encode still allocates 28 times for a 4 KiB response.
- **NEG-007**: The review surface is large (about 145 files under `crate/`), which raises merge-conflict and
  review risk compared with area-by-area PRs.

## Alternatives Considered

### Keep `String` tags and only fix the internal codec copies

- **ALT-001 Description**: Stop at decisions 1–4 and 6 (commit 1), with no public API break.
- **ALT-002 Rejection Reason**: Left about 54 avoidable allocations per binary request (86 vs 32) and the
  per-node `String` for every tag. The API break is mechanical and was accepted because the tag names are
  already `'static` at every producer.

### Skip the TTLV tree and deserialize bytes straight into the request types

- **ALT-003 Description**: A streaming serde `Deserializer` over the wire bytes would avoid building a tree.
- **ALT-004 Rejection Reason**: Large rewrite of a spec-bound codec used by KMIP 1.4, 2.1, JSON and XML. The
  tree is also needed for audit extraction and normalization. The borrowed tree captured most of the gain at a
  fraction of the risk.

### Pool or arena allocators

- **ALT-005 Description**: Reuse buffers per worker or use a bump allocator for the request lifetime.
- **ALT-006 Rejection Reason**: Adds lifetime and zeroization complexity for key material and hides copies
  rather than removing them. Revisit only if profiling shows allocator contention after removing the copies.

### Split into area-by-area PRs

- **ALT-007 Description**: One PR per area (codec, handlers, DB layers), following the repository's
  server → CLI → UI cascade.
- **ALT-008 Rejection Reason**: Not rejected on merit. All changes live in server, `cosmian_kmip` and database
  crates and share the `Arc<ObjectWithMetadata>` and `Cow` contracts, so a single PR keeps the workspace
  compiling at each step; it still trades review ease (NEG-007) for that.

### Leave the pipeline as it was

- **ALT-009 Description**: Accept the cost.
- **ALT-010 Rejection Reason**: The per-byte tracing and repeated subtree copies were pure overhead with no
  behavioral purpose.

## Implementation Notes

- **IMP-001**: Commits: `d70bf88b2` (codec, handlers, `HttpClient`), `73697fd32` (`Cow` tags, `Arc` object
  sharing, borrow/move, SQL layers, audit, middlewares, COSMIAN-2026-031), `bc49681f1` (ADR and
  `HttpClient::send` fix), `ccc23ffc3` (docs and security updates). Changelog entries: the former `CHANGELOG/rust_cleanup.md` and `CHANGELOG/rust_reduce_allocs.md`, consolidated into `CHANGELOG.md` 5.29.0 (full text in git history).
- **IMP-002**: **Lesson learned**: the first allocation commit (`20274da5b`, rewritten as `d70bf88b2`) left
  `HttpClient::send` unable to compile: `retry_req` was referenced after the request had been moved into the
  client, and the client crate did not build at that revision (CI run 38884335018). The URI is now cloned
  before sending (`http::Uri` is reference counted, so the clone is O(1)). Allocation refactors must be built
  with `cargo build --workspace --all-targets` (not only the touched crate) before pushing.
- **IMP-003**: Verification: `cargo test -p cosmian_kmip --lib` (236 passed), `cargo test -p cosmian_kms_client
  --lib` (62 passed), `cargo clippy -p cosmian_kms_client --all-targets -- -D warnings`, and
  `cargo test --workspace --lib` in FIPS and non-FIPS all pass locally.
- **IMP-004**: Success criterion for follow-up work: reproduce the tables above with a counting allocator before
  and after; any change to the TTLV codec must keep the encoded bytes identical.
- **IMP-005**: Known CI observation on the PR head: the `psql - non-fips` job's `ckms --lib` process exited
  with SIGSEGV after all 296 tests had passed; it did not reproduce in more than 10 local runs (including
  postgres, 2-CPU throttling and the exact workspace command) and the other database jobs on the same commit
  passed. Treat it as an exit-time flake until a CI re-run says otherwise; it is not attributed to this change.

## References

- **REF-001**: the former `CHANGELOG/rust_cleanup.md` and `CHANGELOG/rust_reduce_allocs.md`, consolidated into `CHANGELOG.md` 5.29.0 (breaking change, security,
  refactor and performance entries; full text in git history).
- **REF-002**: `crate/kmip/src/ttlv/` (`ttlv_struct.rs`, `serialize.rs`, `deserialize.rs`, `date_time.rs`,
  `kmip_ttlv_deserializer/`, `wire/`).
- **REF-003**: `crate/server/src/routes/kmip/handlers.rs`, `crate/server/src/core/retrieve_object_utils.rs`,
  `crate/server/src/core/operations/export_get.rs`, `crate/server_database/src/core/database_objects.rs`,
  `crate/server_database/src/stores/sql/`.
- **REF-004**: `SECURITY.md` — COSMIAN-2026-031 (this change) and the COSMIAN-2026-015 invariant it must keep.
- **REF-005**: KMIP 2.1 specification, TTLV encoding (OASIS): the wire format that must not change.
- **REF-006**: `documentation/adr/2026-09-24-hsm-delegated-benchmarking-infrastructure.md` (benchmarking
  conventions).
