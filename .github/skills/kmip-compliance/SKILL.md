---
name: kmip-compliance
description: Validate a KMIP operation against the KMIP 2.1 spec, dispatch table, and type definitions. Use when adding or modifying a KMIP operation.
---

# KMIP Compliance Validator

Verify that a new or modified KMIP operation is fully compliant with the KMIP 2.1 specification and correctly wired through the codebase.

## When to Use

- Adding a new KMIP operation to `crate/server/src/core/operations/`
- Modifying request/response types in `crate/kmip/src/kmip_2_1/`
- Adding a new TTLV attribute or enum variant
- Reviewing a KMIP operation implementation for protocol correctness

## Step 1 — Identify the Operation

Determine the operation name (e.g. `Get`, `Create`, `Locate`, `Encrypt`, `ReKey`). Locate these files:

- **Spec**: `crate/kmip/src/kmip_2_1/` or `crate/kmip/src/kmip_1_4/` — HTML spec files
- **Types**: `crate/kmip/src/kmip_2_1/kmip_operations.rs`
- **Dispatch**: `crate/server/src/core/operations/dispatch.rs`
- **Implementation**: `crate/server/src/core/operations/<operation>.rs`
- **KMIP 2.1 spec HTML**: look for the operation's section in `crate/kmip/src/`

```bash
ls crate/kmip/src/
ls crate/server/src/core/operations/
```

## Step 2 — Spec Cross-Reference

Read the HTML spec file for the operation. Verify:

- [ ] **Request Payload fields** — every mandatory field from the spec is present in the Rust request struct
- [ ] **Response Payload fields** — every mandatory field from the spec is present in the response struct
- [ ] **Optional fields** — optional spec fields are modeled as `Option<T>` in Rust
- [ ] **TTLV tags** — tag values in the Rust type match the spec (check `#[kmip(tag = "0x...")]` attributes)
- [ ] **Enum variants** — all spec-defined enum values for this operation are covered
- [ ] **Batch support** — the operation correctly handles batch requests if spec mandates it

Do not rely on training-data recall for spec section numbers, field names, or TTLV tag values. **Always cross-reference against the actual HTML spec file.**

## Step 3 — Type Definition Audit

In `crate/kmip/src/kmip_2_1/kmip_operations.rs`:

- [ ] Request and response types are defined and added to the `Operation` enum
- [ ] All fields use correct Rust types mapped from KMIP types:

  | KMIP Type | Rust Type |
  |-----------|-----------|
  | TextString | `String` |
  | ByteString | `Vec<u8>` |
  | Integer | `i32` |
  | LongInteger | `i64` |
  | BigInteger | `Vec<u8>` |
  | Enumeration | Custom `enum` with `#[derive(KmipEnum)]` |
  | Boolean | `bool` |
  | DateTime | `i64` (epoch seconds) |
  | Structure | Nested struct |

- [ ] Structs derive `Debug`, `Clone`, `Serialize`, `Deserialize` (and `KmipSerialize`/`KmipDeserialize` via proc-macros)
- [ ] Optional fields consistently use `Option<T>`, not default-zero integers

## Step 4 — Dispatch Table Completeness

In `crate/server/src/core/operations/dispatch.rs`:

- [ ] A match arm exists routing the new operation's TTLV tag to the handler function
- [ ] The match arm is in the correct position (alphabetical or grouped by category)
- [ ] If the operation is non-FIPS-only, the dispatch arm is gated with `#[cfg(feature = "non-fips")]`
- [ ] No existing arm is accidentally shadowed by the new one

## Step 5 — Implementation Review

In `crate/server/src/core/operations/<operation>.rs`:

- [ ] **Access control**: Does the handler call the access check before returning key material or performing destructive operations?
    - Must verify: `db.is_allowed(uid, caller, operation_type)` (or equivalent)
    - Get, Export, Decrypt, Sign, MAC, Derive, Wrap, Unwrap → must check access
    - Destroy, Revoke → must check ownership or admin privilege
    - Create, Register, Import → must set the caller as owner
    - Locate → must filter results to caller's objects
- [ ] **Error handling**: Uses `?` propagation; no `.unwrap()` in production paths
- [ ] **Logging**: Operation start/end logged at `trace!`/`debug!` level; errors at `warn!` or `error!`
- [ ] **Function length**: Handler function ≤ 50 lines; sub-operations extracted to helpers
- [ ] Module registered in `crate/server/src/core/operations/mod.rs`

## Step 6 — Test Coverage

- [ ] A unit test exists in a `#[cfg(test)]` block within the operation file, or a test vector exists
- [ ] Test vector registered in `crate/test_kms_server/src/vector_runner.rs` (run `/kms-test-vector` if missing)
- [ ] Both success and error paths are tested

## Report Format

```markdown
## KMIP Compliance: [OperationName]

### Spec Cross-Reference
[Issues or ✅ clean]

### Type Definitions
[Issues or ✅ clean]

### Dispatch Table
[Issues or ✅ clean]

### Implementation
[Issues or ✅ clean]

### Access Control
[Issues or ✅ CRITICAL concern if missing]

### Test Coverage
[Missing vectors or ✅ covered]

### Required Actions
1. [Ordered list of fixes needed before the operation is compliant]
```
