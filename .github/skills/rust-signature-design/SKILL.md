---
name: rust-signature-design
description: 'Classify Rust function parameters and the structs behind them to catch omitted, swapped, or drifting arguments while designing a signature. Use when defining a new function signature, adding or removing a parameter, a parameter list grows past ~4 entries, `clippy::too_many_arguments` fires, or the same parameter group reappears in more than one function.'
---

# Rust Signature Design

Goal: make invalid or incomplete call states hard to represent — not merely shorten signatures.
Companion to the "Refactor" step of the lint-suppression tree in
[`rust.instructions.md`](../../instructions/rust.instructions.md): apply it before reaching for
`#[allow(clippy::too_many_arguments)]`.

## Step 1 — Classify every parameter

| Kind | Definition | KMS example | Typical home |
|---|---|---|---|
| Entity state | Durable property of a domain object | `UniqueIdentifier`, `Algorithm`, object `State` | Field on the entity/request struct |
| Operation state | Exists only for one call | `cascade`, `compromise_occurrence_date`, `ids_to_skip` in `recursively_revoke_key` (`crate/server/src/core/operations/revoke.rs:80-89`) | Operation input struct, built per call |
| Environmental dependency | Service/collaborator needed to act | `kms: &KMS`, `user: &UserId` — in nearly every `core/operations/*.rs` handler | Keep explicit unless ≥3 collaborators travel together into a *new* struct — see Step 3.5 |
| Derived value | Cheaply computable from another argument | `revoked_state`, computed from `revocation_reason` by `revocation_target_state()` (`revoke.rs:381`) | Compute inside the function; never accept both the source and its derivative |
| Control parameter | Changes behavior | `disable_unwrapped_cache: bool`, `clear_db_on_start: bool` (`crate/server_database/src/core/mod.rs:118-126`) | Named enum once ≥2 control bools form one configuration |

## Step 2 — Match against defect patterns

```bash
# Functions already fighting the lint — primary candidates
rg -n '#\[(allow|expect)\(clippy::too_many_arguments' --type rust <path>

# Same parameter pair/triple repeated verbatim across signatures
rg -n '^\s*kms: &KMS,$' -A1 --type rust <path> | rg -B1 'user: &UserId'

# Caller destructures a struct only to forward the fields individually
rg -n '\b(\w+)\.\w+,\s*&?\1\.\w+' --type rust <path>
```

| Pattern | Signal | Fix |
|---|---|---|
| Repeated parameter cluster | Same 2+ param names/types travel together across signatures | Group into an existing or new struct (Step 3) |
| Field extraction then forwarding | `callee(&req.a, &req.b, &req.c)` right after destructuring `req` | Pass `&req` or a narrow borrowed view |
| Argument omission | A multi-layer call chain drops a value an inner callee needs, forcing a re-derived or wrong default downstream | Thread the owning struct through every layer instead of re-adding a discrete parameter at each layer |
| Argument swapping | ≥2 adjacent same-typed params (`&str, &str, &str`) | Newtype each (`rust-patterns` Pattern 1) or a struct |
| Inconsistent reconstruction | Same `Struct { a: x.a.clone(), b: x.b, .. }` literal appears at ≥2 call sites | Move behind a constructor / `From` impl on the owning type |
| Signature drift | Sibling functions (`encrypt`/`decrypt`, `wrap`/`unwrap`) carry non-identical param sets for the same concept | Confirm intentional; otherwise align via a shared context struct |
| Semantically-required `Option<T>` | A field is `Option` only because some callers can't supply it, though the operation is unsound without it | Fallible constructor, or a distinct validated-state struct — not a permanent `Option` |
| Primitive-heavy signature | ≥2 `bool`/`u8` control params | Enum or policy struct |
| Struct exists but incomplete | A domain struct *and* fields that belong to it are passed separately beside it | Add the field only if its lifecycle/invariants match the struct |
| Overloaded context | A large `Context`/`Request` is threaded everywhere though each callee touches 1–2 fields | Narrow borrowed view or small dedicated struct, not a bigger bag |

## Step 3 — Pick the narrowest fix that applies

Try in order; stop at the first that fits:

1. **Reuse the existing request/entity struct** — pass `&Request` instead of its fields. KMIP request types live in
   `crate/kmip/src/kmip_2_1/kmip_operations.rs` and must match the KMIP 2.1 spec
   ([`rust-kmip.instructions.md`](../../instructions/rust-kmip.instructions.md)) — never add internal-only state to a wire type.
2. **Add a field to an existing struct** — only when the new field shares the struct's lifetime, invariants, and construction path.
3. **Narrow borrowed view** — `struct FooView<'a> { id: &'a KeyId, algorithm: Algorithm }`, built via a `.view()`/`.context()` method, when the full struct is too broad or ownership shouldn't transfer.
4. **Operation input struct** — group values that exist for one call only, e.g. `struct RevokeInput { cascade: bool, ids_to_skip: HashSet<String> }`, separate from durable entity state.
5. **Extend an existing collaborator** — the service layer is `KMS` (`crate/server/src/core/...`) plus the `ObjectsDb` / `PermissionsDb` / `Hsm` traits (`rust-patterns` Pattern 4). Add a method there; never wrap `KMS` in a second service type.
6. **Keep explicit parameters** — values are independent, used by one small function, or bundling would hide a dependency.
   Precedent (`crate/server_database/src/core/mod.rs:117`): `Database::instantiate` keeps 9 explicit params behind
   `#[allow(clippy::too_many_arguments)]` with an inline reason (cache config params are additive; a builder would
   over-engineer). Justify the same way — one line, inline.

## Before / after (illustrative)

```rust
// Before — req.tenant_id exists but the middle layer doesn't forward it.
fn outer(req: &Request) -> KResult<()> {
    inner(&req.key_id, &req.payload) // tenant_id silently dropped
}
fn inner(key_id: &KeyId, payload: &[u8]) -> KResult<()> { /* needs tenant_id too */ }

// After — the struct carries tenant_id through every layer; nothing to omit.
fn outer(req: &Request) -> KResult<()> {
    inner(req)
}
fn inner(req: &Request) -> KResult<()> { /* req.tenant_id always present */ }
```

## Do not

- Invent a generic `Params`/`Context`/`Data` struct with no domain meaning just to cut a parameter count.
- Add a field to a `crate/kmip` wire struct for internal bookkeeping — KMIP structs are spec-bound.
- Turn a required value into `Option<T>` to avoid updating a constructor.
- Mass-refactor the `kms`/`user` pair across `core/operations/*.rs` into a new wrapper struct — that spread is already deliberate (Step 3.5); only touch it where a concrete defect (Step 2) drives the change.
- Suppress `clippy::too_many_arguments` with a bare `#[allow]`/`#[expect]` and no inline reason on new code — forbidden per `rust.instructions.md`.
