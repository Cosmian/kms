---
title: "ADR-2026-10-16: Reduce Per-Request Heap Allocations on the KMIP TTLV Path"
status: "Proposed"
date: "2026-10-16"
authors: "KMS contributors, performance engineers, operators"
tags: ["architecture", "decision", "performance", "kmip", "ttlv", "allocations"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-16: Reduce Per-Request Heap Allocations on the KMIP TTLV Path

## Status

**Proposed** | Accepted | Rejected | Superseded | Deprecated

## Context

Every KMIP request through `POST /kmip` (binary TTLV) and `POST /kmip/2_1` (TTLV-JSON) goes through the same
codec pipeline in `crate/kmip`:

```text
request:  bytes | JSON text -> TTLV tree -> from_ttlv -> RequestMessage
response: ResponseMessage -> to_ttlv -> TTLV tree -> to_bytes | JSON
```

A 4 KiB `Encrypt` request measured on the commit before this work (`2c176d6a6`) showed that the codec,
not the cryptography, dominated the server-side cost of a KMIP request, and that the KMIP endpoints were
noticeably slower than the JOSE endpoint (`/v1/crypto`) for the same operation. Causes found by reading the
code and by counting allocations:

- `TtlvDeserializer` owned the TTLV tree, so `from_ttlv` and every nested walker (structure, enum, array,
  adjacently tagged, untagged) cloned whole subtrees to hand a child to the next deserializer.
- `ByteString` decoding opened a tracing span and evaluated `cosmian_logger::trace!` once **per byte**. That
  macro resolves the caller name even when tracing is disabled.
- `ByteString` values went through an intermediate `String` (hex) in both directions.
- `TTLV::to_bytes` serialized each Structure into a temporary buffer and copied it into its parent, once per
  nesting level, so large payloads were copied several times.
- Header time stamps were serialized as a 9-integer tuple, and the wire decoder over-reserved child slots and
  allocated for padding.
- The binary handler decoded the request bytes for the audit hooks and again for dispatch, and decoded the
  **response** bytes a second time for the audit hooks although it already held the response TTLV.
- The `/kmip/2_1` handler took the body as `String` (an extra copy of the request) and symmetric `Encrypt`
  copied the key with `KeyBlock::key_bytes()`.
- `HttpClient` built a request up front and kept a second copy only to be able to retry.

The server must keep its wire output byte-identical: KMIP clients, test vectors and persisted audit data
depend on it.

## Decision

Remove avoidable copies and allocations on the codec and handler path without changing the wire format or any
public behavior, in the order of measured impact:

1. **Borrow the TTLV tree when deserializing.** `TtlvDeserializer<'a>` holds `&'a TTLV` and exposes
   `TtlvDeserializer::from_ttlv(&TTLV)`. Walkers pass child references instead of cloning subtrees. The free
   function `from_ttlv(TTLV)` keeps its by-value signature (about 160 call sites) and borrows internally.
2. **Decode `ByteString` directly.** `ByteString` values are hex-encoded and decoded without an intermediate
   `String`, and the per-byte tracing span and `trace!` evaluation are removed.
3. **Exact-size TTLV encoding.** `TTLV::to_bytes` computes every Structure length first, then writes into one
   buffer of the exact size. Padding is read into a stack buffer and at most 4 child slots are reserved per
   Structure when decoding.
4. **Direct `DateTime` encoding.** Header time stamps that are whole UTC seconds serialize to a TTLV
   `DateTime` node through a `$KmipDateTime` newtype marker (same technique as the existing `Interval`
   marker) instead of a 9-integer tuple. `serialize_with = crate::ttlv::date_time::serialize` is applied to
   `ResponseMessageHeader.time_stamp`.
5. **Decode once in the handlers.** The binary handler decodes the request bytes once and passes the parsed
   TTLV to the dispatcher; the audit hooks receive the response TTLV that dispatch already produced instead of
   decoding the response bytes again. `/kmip/2_1` takes `Bytes` and parses `&str` borrowed from it.
6. **Borrow key material.** Symmetric `Encrypt` uses `KeyBlock::key_bytes_ref()`. `HttpClient` rebuilds a
   request only on a connection retry (`post_bytes` takes `impl Into<Bytes>`).

The decision does **not** change the `cosmian_kmip` public data model (`TTLV.tag` and
`KmipEnumerationVariant.name` stay `String`).

## Measured Effect

Method: a throwaway integration test in `crate/kmip` with a counting `#[global_allocator]`, built from the
same source on both revisions (`2c176d6a6` as base, this branch as head), run with
`cargo test -p cosmian_kmip --release --test alloc_measure -- --nocapture`. It encodes and decodes a KMIP 2.1
`Encrypt` request and `EncryptResponse` with 64 B and 4096 B payloads. Allocation counts are exact (one
warm-up call, then one counted call). Times are the mean of 2000 single-threaded iterations; treat them as
±10 % (shared machine, no CPU pinning). The harness was deleted after the run.

### Per stage, 4096-byte payload

| Stage | Allocs base → head | Bytes base → head | Time base → head |
|---|---|---|---|
| `/kmip` request: bytes → TTLV → `RequestMessage` | 83 → 12 | 39 476 → 12 556 | 177 µs → 11.0 µs |
| `/kmip/2_1` request: JSON text → TTLV → `RequestMessage` | 114 → 41 | 48 668 → 17 065 | 213 µs → 45.9 µs |
| Response: `ResponseMessage` → TTLV | 73 → 19 | 13 237 → 11 624 | 18.2 µs → 16.1 µs |
| Response: TTLV → bytes (`to_bytes`) | 22 → 1 | 26 060 → 4 336 | 3.4 µs → 3.2 µs |
| Response: TTLV → JSON | 10 → 9 | 36 753 → 32 675 | 26.2 µs → 22.7 µs |
| Audit hook: response bytes → TTLV (binary path only) | 26 → 0 | 9 564 → 0 | 1.3 µs → 0 |

### Whole `/kmip` codec work per request (sum of the four binary-path stages)

| Payload | Allocs base → head | Bytes base → head | Time base → head |
|---|---|---|---|
| 64 B | 197 → 32 (−84 %) | 21 073 → 8 356 (−60 %) | 20.2 µs → 10.8 µs (1.9×) |
| 4096 B | 204 → 32 (−84 %) | 88 337 → 28 516 (−68 %) | 202 µs → 30.9 µs (6.5×) |

The 4 KiB time gain comes almost entirely from the removed per-byte `trace!`/span in `ByteString` decoding;
the allocation gain comes from the borrowed deserializer and the exact-size encoder.

### Not measured

- End-to-end request latency or throughput through Actix, TLS and the database. The saved codec time
  (about 170 µs for a 4 KiB `Encrypt`, about 10 µs for small requests) is small against a network round trip
  and cannot be read off these numbers as a percentage of total latency.
- The `/kmip/2_1` body `String` → `Bytes` change, the `key_bytes_ref()` change in `Encrypt` (one key-sized
  allocation and copy per request, by inspection) and the `HttpClient` retry change (client-side).
- Multi-threaded allocator contention, which lower allocation counts should only help.

## Consequences

### Positive

- **POS-001**: About 84 % fewer allocations and 60–68 % fewer allocated bytes in the codec work of a binary
  `Encrypt`, for small and large payloads alike.
- **POS-002**: Decoding a 4 KiB binary `Encrypt` request (bytes → `RequestMessage`) is about 16× faster
  (177 µs → 11 µs), which removes most of the codec gap between the KMIP and JOSE endpoints.
- **POS-003**: The response TTLV is no longer re-decoded for audit, so audit capture on the binary path costs
  no extra parse.
- **POS-004**: Wire output is byte-identical, so no client, vector or persisted-audit migration is needed.
- **POS-005**: Less transient copying of key material (`key_bytes_ref()`), which shortens the lifetime of
  plaintext key copies in memory.

### Negative

- **NEG-001**: `TtlvDeserializer` now carries a lifetime parameter, which spreads to every walker type in
  `crate/kmip/src/ttlv/kmip_ttlv_deserializer/`.
- **NEG-002**: The `$KmipDateTime` marker is a second private serializer convention next to `Interval`;
  contributors must know it exists when adding TTLV time stamps.
- **NEG-003**: Allocation work remains: serialization still allocates one `String` per TTLV node tag
  (`to_ttlv`: 19 allocations for a 1-item `EncryptResponse`) and `ByteString` values are still copied once into
  the tree. The `/kmip/2_1` JSON path still allocates 41 times for a 4 KiB request.
- **NEG-004**: Time gains for small requests are modest (about 2×); the benefit is mainly allocator pressure
  and large-payload latency.

## Alternatives Considered

### Change `TTLV.tag` and `KmipEnumerationVariant.name` to `Cow<'static, str>`

- **ALT-001 Description**: Borrow static serde names and `strum::IntoStaticStr` tag names instead of
  allocating a `String` per node. This would remove most of the remaining `to_ttlv` allocations.
- **ALT-002 Rejection Reason**: Not rejected on merit, but deferred. It is a public `cosmian_kmip` API break
  touching about 600 sites across the server, clients, HSM and WASM crates and needs its own breaking-change
  entry and PR. It is the recommended next step (see NEG-003) and is not part of this decision.

### Skip the TTLV tree and deserialize bytes straight into the request types

- **ALT-003 Description**: A streaming serde `Deserializer` over the wire bytes would avoid building a tree.
- **ALT-004 Rejection Reason**: Large rewrite of a spec-bound codec used by KMIP 1.4, 2.1, JSON and XML. The
  tree is also needed for audit extraction and normalization. The borrowed tree captured most of the gain at a
  fraction of the risk.

### Pool or arena allocators

- **ALT-005 Description**: Reuse buffers per worker or use a bump allocator for the request lifetime.
- **ALT-006 Rejection Reason**: Adds lifetime and zeroization complexity for key material and hides the
  copies rather than removing them. Revisit only if profiling shows allocator contention after removing the
  copies.

### Leave the pipeline as it was

- **ALT-007 Description**: Accept the cost.
- **ALT-008 Rejection Reason**: The per-byte tracing and repeated subtree copies were pure overhead with no
  behavioral purpose.

## Implementation Notes

- **IMP-001**: Landed in commit `20274da5b` (`crate/kmip/src/ttlv/**`, `crate/kmip/src/kmip_0/kmip_messages.rs`,
  `crate/server/src/routes/kmip/handlers.rs`, `crate/server/src/core/operations/encrypt.rs`,
  `crate/clients/client/src/http_client/client.rs`). Changelog entries are in `CHANGELOG/rust_cleanup.md`.
- **IMP-002**: That commit left `HttpClient::send` unable to compile (`retry_req` referenced after the request
  was moved into the client). The URI is now cloned before sending (`http::Uri` is reference counted, so the
  clone is O(1)); error text is unchanged.
- **IMP-003**: Verification: `cargo test -p cosmian_kmip --lib` (236 passed), `cargo test -p cosmian_kms_client
  --lib` (62 passed), `cargo clippy -p cosmian_kms_client --all-targets -- -D warnings` (clean), and the full
  `cargo test --workspace --lib` run in FIPS and non-FIPS (all passed).
- **IMP-004**: Success criterion for follow-up work: reproduce the table above with a counting allocator
  before and after; any change to the TTLV codec must keep wire bytes identical (existing wire, vector and
  round-trip tests cover this).
- **IMP-005**: Per-request savings outside the codec (`retrieve_object` deep clones, per-call `HashSet`
  rebuilds in algorithm policy, SQL query string conversion, audit extension clones) were surveyed but are not
  part of this decision. They belong to a separate record.

## References

- **REF-001**: `CHANGELOG/rust_cleanup.md` (entries for the TTLV-JSON path, the binary path and `ByteString`
  decoding).
- **REF-002**: `crate/kmip/src/ttlv/` (`ttlv_struct.rs`, `serialize.rs`, `deserialize.rs`, `date_time.rs`,
  `kmip_ttlv_deserializer/`, `wire/`).
- **REF-003**: `crate/server/src/routes/kmip/handlers.rs`, `crate/server/src/core/operations/encrypt.rs`,
  `crate/clients/client/src/http_client/client.rs`.
- **REF-004**: KMIP 2.1 specification, TTLV encoding (OASIS): the wire format that must not change.
- **REF-005**: `documentation/adr/2026-09-24-hsm-delegated-benchmarking-infrastructure.md` (benchmarking
  conventions).
