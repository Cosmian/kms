---
title: "ADR-2026-09-24: HSM-Delegated Benchmarking Infrastructure"
status: "Proposed"
date: "2026-09-24"
authors: "Performance Engineering Team, HSM Integration"
tags: ["architecture", "benchmarking", "hsm", "metadata", "tagging"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-09-24: HSM-Delegated Benchmarking Infrastructure

## Status

**Proposed** | Accepted | Rejected | Superseded | Deprecated

## Context

The KMS benchmark suite needed to measure cryptographic performance on hardware security modules (HSMs), specifically for the PKCS#11 workflow where keys are generated and managed directly on the HSM rather than in software.

### Problem Statement

1. **No HSM Key Tracking**: The benchmark harness could generate HSM-resident keys but had no way to:
   - Identify which keys it created
   - Clean up test keys after runs
   - Query keys by metadata (algorithm, curve, key length)
   - Aggregate performance metrics by key properties

2. **Disconnected HSM Interfaces**: The `ObjectsStore` and `CryptoOracle` trait implementations for HSM backends had stub methods that always returned empty results:
   - `retrieve_tags()` → always `HashSet::new()`
   - `list_uids_for_tags()` → always `HashSet::new()`
   - Tags parameter ignored in `create()` and `create_keypair()`

3. **Limited Curve Support**: EC curve support was limited to FIPS-approved NIST curves, missing secp256k1 (common in blockchain workloads).

4. **Metadata Flow Broken**: CryptoOracle didn't expose key metadata (curve, length, tags) to callers, preventing benchmark harness from making intelligent decisions about workload generation.

5. **Remote Benchmarking Gap**: No standard mechanism to run benchmarks against a remote KMS server, limiting the ability to test production deployments or shared HSM infrastructure.

### Constraints

- FIPS 140-3 compliance must be maintained for FIPS-approved algorithms
- Non-FIPS curves (secp256k1, Ed25519, etc.) must remain feature-gated behind `#[cfg(feature = "non-fips")]`
- Backward compatibility with existing key labels and PKCS#11 persistent storage
- No changes to public key material or key derivation algorithms
- Tag format must persist across HSM session boundaries and restarts

### Stakeholders

- **Performance Engineers**: Need accurate HSM throughput measurements, key tracking, cleanup
- **HSM Integration Team**: Must implement tagging serialization, metadata queries
- **Operations**: Need to run benchmarks against remote KMS servers in production
- **Security Auditors**: Must verify tag format doesn't leak sensitive information
- **Contributors**: Must understand new trait contracts (interfaces, HSM)

## Decision

Implement a comprehensive HSM-delegated benchmarking infrastructure across three layers:

### 1. Base HSM Layer (`crate/hsm/base_hsm`)

**Key Tagging Infrastructure** via JSON-serialized labels:
- Implement `serialize_tagged_label()` and `deserialize_tagged_label()` in `session/mod.rs`
- Format: `cosmian-kms-tags-v1|JSON(tags,id)|key_id` in PKCS#11 `CKA_LABEL`
- Backward compatible: plain labels still work (deserialize returns empty tag set)
- Tags persist across HSM session/restart cycles

**Session Operations Updated**:
- `create_key(tags)` → encode tags in label
- `create_keypair(HsmKeyPairIds, tags)` → encode tags for both private and public keys
- `get_key_metadata()` → deserialize and return tags

### 2. Interfaces Layer (`crate/interfaces`)

**Trait Contracts Expanded**:

**HsmObject struct**:
```rust
pub struct HsmObject {
    key_material: KeyMaterial,
    id: String,
    tags: HashSet<String>,  // ← NEW
}
```

**EcCurve enum**:
- Add `#[cfg(feature = "non-fips")] Secp256k1` for non-FIPS ECDSA signing
- Enables benchmark to test diverse cryptographic algorithms

**HsmKeyPairIds struct** (NEW):
```rust
pub struct HsmKeyPairIds<'a> {
    pub private: &'a [u8],
    pub public: &'a [u8],
}
```
- Type-safe reference to HSM keypair components
- Prevents accidental private/public key confusion

**CryptoOracle trait**:
- `KeyMetadata` struct: add `tags: HashSet<String>` field
- `encrypt()`: add `iv_counter_nonce: Option<&[u8]>` parameter (for reproducible benchmarks)
- `signature_verify()`: add `input_is_digest: bool` parameter (for Ed25519/ECDSA digest optimization)

### 3. HSM Store Layer (`crate/interfaces/src/hsm/hsm_store.rs`)

**Implement Real HSM Tagging** (was previously all stubs):

- `retrieve_tags(uid)` → Call HSM, deserialize tagged label, return tags
- `list_uids_for_tags(tags)` → Scan all HSM slots, filter by tag membership, return UIDs
- `create(tags)` → Pass tags through to base_hsm layer
- `create_keypair(tags)` → Add system tags (`SYSTEM_TAG_PRIVATE_KEY`, `SYSTEM_TAG_PUBLIC_KEY`), pass to HSM
- `find()` → Support tag filtering in KMIP search attributes

**Result**: Complete metadata flow from KMS server → HSM backend → PKCS#11 and back.

### 4. Remote Benchmarking Support (`.mise/tasks/bench/_default`)

- Add `--server-url <url>` flag for targeting remote KMS servers
- Auto-detect REMOTE_MODE: skip HSM-resident tasks (incompatible with remote execution)
- Gate incompatible benchmarks gracefully with honest messaging
- Allow `mise bench --server-url http://192.168.1.17:9090 --sanity` to measure software baseline on remote servers

### 5. Benchmark Report Architecture Diagrams (`.mise/scripts/bench/plot_version_compare.py`)

- Add `_render_architecture_section()` function with 5 Mermaid diagrams:
  1. Software Baseline (ckms → KMIP → Crypto → Database)
  2. HSM KEK-Wrapped (ckms → KMIP → Crypto + HSM-KEK → Storage)
  3. HSM-Delegated (ckms → KMIP → CryptoOracle → PKCS#11 → HSM)
  4. PKCS#11 Software (ckms PKCS#11 → Provider → KMIP → KMS)
  5. PKCS#11 HSM (ckms PKCS#11 → Provider → KMIP → CryptoOracle → HSM)
- Auto-inject architecture section (between Environment and Protocols) in `generate_report()`
- Diagrams selected based on `is_hsm`, `is_hsm_kek`, `is_pkcs11` flags

## Consequences

### Positive

- **POS-001**: Benchmark harness can now track HSM-resident keys via tags
  - `list_uids_for_tags(["bench"])` returns all test keys generated in a run
  - Enables deterministic key cleanup and lifecycle management

- **POS-002**: Complete metadata flow enables intelligent workload generation
  - CryptoOracle exposes curve, key length, algorithm via KeyMetadata
  - Benchmark can report "Ed25519 signing: 1000 ops/sec" with curve context
  - Enables filtering and aggregation by algorithm properties

- **POS-003**: Remote benchmarking support unlocks production scenarios
  - `mise bench --server-url` measures throughput against any HTTP KMS server
  - Enables HSM infrastructure validation without local SoftHSM
  - Supports load testing on shared HSM backends

- **POS-004**: Architecture diagrams make benchmark methodology transparent
  - Diagrams auto-generated with each benchmark run
  - Clear visualization of data flow for each benchmark type
  - Documentation automatically stays current (no manual updates needed)

- **POS-005**: Backward compatible with existing key storage
  - Plain PKCS#11 labels still deserialize correctly
  - Tagged labels transparently upgraded on first read
  - No key migration required

- **POS-006**: Supports diverse cryptographic algorithms
  - secp256k1 support for blockchain/Ethereum workloads
  - Curve support matrix expanded for non-FIPS builds
  - Feature-gated correctly to maintain FIPS compliance

### Negative

- **NEG-001**: Performance overhead of tag serialization/deserialization
  - JSON parsing on every key load (mitigated: typically once per benchmark run)
  - PKCS#11 label size increases slightly

- **NEG-002**: Complexity added to HsmStore interface
  - More trait methods to implement for new HSM backends
  - Deprecated pattern: previous stubs removed, implementations now required

- **NEG-003**: Tag query scalability on large HSM instances
  - `list_uids_for_tags()` scans all slots and keys (linear complexity)
  - Not efficient for HSMs with millions of keys (out of scope for benchmarking)

- **NEG-004**: HSM-delegated benchmarking still has limits
  - Cannot measure remote PKCS#11 operations (architectural limitation)
  - Software baseline benchmarks work remotely; HSM-resident must be local

## Alternatives Considered

### [Alternative 1: In-Memory Key Registry]

- **ALT-001 Description**: Keep a separate in-memory registry of benchmark-created keys instead of tagging in HSM
- **ALT-002 Rejection Reason**: 
  - Registry is lost on process restart
  - Doesn't scale across multiple concurrent benchmark runs
  - Doesn't leverage HSM's persistent storage
  - Rejected in favor of persistent HSM tagging

### [Alternative 2: Time-Based Key Discovery]

- **ALT-003 Description**: Query HSM for keys created after timestamp T
- **ALT-004 Rejection Reason**:
  - PKCS#11 has no standard "list keys created after time T" operation
  - Clock synchronization issues on distributed HSM clusters
  - Tags provide explicit, deterministic filtering
  - Rejected in favor of tag-based filtering

### [Alternative 3: Remote Benchmarking via SSH]

- **ALT-005 Description**: SSH into remote host, run benchmark locally
- **ALT-006 Rejection Reason**:
  - Requires SSH access to production KMS servers
  - Tightly couples benchmark logic to remote environment
  - `--server-url` HTTP-based approach is cleaner and more portable
  - Rejected in favor of HTTP-based remote benchmarking

### [Alternative 4: Static Architecture Documentation]

- **ALT-007 Description**: Hand-write architecture diagrams in markdown; maintain separately
- **ALT-008 Rejection Reason**:
  - Documentation diverges from implementation over time
  - Difficult to keep diagrams in sync with benchmark variants
  - Auto-generated diagrams ensure documentation stays current
  - Rejected in favor of programmatic diagram generation

## Implementation Notes

- **IMP-001**: Tag serialization format is designed for forward/backward compatibility
  - Existing plain labels deserialize as (label, empty_tag_set)
  - New tagged labels parse JSON safely with error recovery
  - Format versioned (`cosmian-kms-tags-v1`) for future evolution

- **IMP-002**: HsmKeyPairIds struct ensures both private and public key UIDs managed together
  - System tags `SYSTEM_TAG_PRIVATE_KEY` and `SYSTEM_TAG_PUBLIC_KEY` enable discovery
  - Prevents orphaned keys in case of partial creation failures

- **IMP-003**: Remote benchmarking auto-gates incompatible tasks
  - Local: `mise bench --sanity` runs all benchmarks (load, hsm, pkcs11)
  - Remote: `mise bench --server-url <url> --sanity` skips HSM-resident tasks
  - Prevents cryptic errors; honest failure messaging

- **IMP-004**: Architecture diagrams injected between Environment and Protocols sections
  - Diagram type selected by `is_hsm`, `is_hsm_kek`, `is_pkcs11` flags (same flags as Protocols/Methodology)
  - No manual edits needed; diagrams auto-generate on each benchmark run
  - Mermaid syntax renders on GitHub and mdBook

- **IMP-005**: Curve support matrix (`EcCurve` enum)
  - FIPS build: P224, P256, P384, P521 only
  - Non-FIPS build: + Secp256k1, Ed25519, Ed448, X25519
  - Feature-gating ensures FIPS compliance maintained

- **IMP-006**: CryptoOracle method signatures expanded carefully
  - `iv_counter_nonce`: Optional, defaults to empty if not provided
  - `input_is_digest`: Explicit flag for pre-hashed message optimization
  - Changes backward compatible (default behavior unchanged)

## References

- **REF-001**: ADR-2026-06-24 "Two-Role RBAC (Crypto Officer, Operator)" — related to key ownership and access control
- **REF-002**: KMIP 2.1 Specification (OASIS) — tag support in KMIP attributes
- **REF-003**: PKCS#11 v3.1 Specification — CKA_LABEL semantics and object discovery
- **REF-004**: Related codebase:
  - `crate/hsm/base_hsm/src/session/mod.rs` — tagging serialization
  - `crate/interfaces/src/hsm/interface.rs` — trait contracts
  - `crate/interfaces/src/hsm/hsm_store.rs` — HsmStore implementation
  - `crate/interfaces/src/crypto_oracle.rs` — CryptoOracle trait
  - `.mise/tasks/bench/` — benchmark tasks
  - `.mise/scripts/bench/plot_version_compare.py` — report generation
- **REF-005**: GitHub Issue #XXXX "Support HSM-delegated benchmarking" — original feature request
- **REF-006**: Cosmian KMS Benchmarks Guide — documentation/docs/benchmarks/

---

## Appendix: Usage Examples

### Benchmark HSM-Resident ECDSA-P256 Signatures

```bash
# Generate 256-bit ECDSA keypair on HSM, sign 10k messages
mise bench:load-hsm --delegated --variant non-fips --mode sign-ecdsa --concurrency 1,2,4,8

# Report at: documentation/docs/benchmarks/ckms_bench_delegated_crypto_operations/report.md
# Includes Architecture diagram showing: ckms → KMIP → CryptoOracle → PKCS#11 → HSM
```

### Remote Benchmark Against Production KMS

```bash
# Measure software baseline throughput on production server
mise bench:load --variant non-fips --server-url https://kms.prod.example.com:9090 --sanity

# Report at: documentation/docs/benchmarks/ckms_bench/report.md
# Includes Architecture diagram showing: ckms → KMIP → Crypto → Database
```

### Track and Clean Up Benchmark Keys

```rust
// Benchmark harness code:
let benchmark_tag = "bench-run-20260924";

// Create keys with tag
let key_uid = kms.create_key(tag: benchmark_tag, ...)?;

// At end of run, find all benchmark keys
let benchmark_uids = hsm_store.list_uids_for_tags(&[benchmark_tag])?;

// Clean up
for uid in benchmark_uids {
    kms.destroy(&uid)?;
}
```
