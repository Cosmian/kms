# KMS design patterns (non-normative)

Background for [`../SKILL.md`](../SKILL.md). This page describes recurring shapes in the KMS codebase so reviews can recognize them. It is **not** a rulebook and contains no copyable API: the authoritative rules are the instruction files linked in each section, and the code is the source of truth. Check the symbol in `crate/` before relying on any name mentioned here.

## Newtype identifiers

Identifiers that are strings on the wire (object UIDs, user identities) are distinct Rust types so that two adjacent `String` parameters cannot be swapped silently. Examples in the tree: `UniqueIdentifier` in `crate/kmip/src/kmip_2_1/kmip_types.rs` and `UserId` in `crate/interfaces/src/user_id.rs`. Prefer an existing newtype or a parameter struct over adding a second `&str, &str` signature; see [`/rust-signature-design`](../../rust-signature-design/SKILL.md). Validation belongs in a fallible constructor, once.

## Typed operation dispatch

Each KMIP operation is a typed request/response value handled by a function under `crate/server/src/core/operations/`; `dispatch.rs` decodes the TTLV, enforces role-based access, then matches on the operation. Adding an operation touches the KMIP types, the dispatcher and the handler together: follow [`kmip-operations.instructions.md`](../../../instructions/kmip-operations.instructions.md) and [`rust-server.instructions.md`](../../../instructions/rust-server.instructions.md). Keep per-operation wiring in the match; extract shared boilerplate with a `macro_rules!` only when several arms are textually identical.

## Backend traits

Storage and HSM backends sit behind traits in `crate/interfaces/` (`ObjectsStore`, `PermissionsStore`, `HSM`); SQLite, PostgreSQL, MySQL and Redis-findex implement the stores. Operation handlers depend on the trait boundary, not on a concrete database. Backend conventions, SQL layout and the shared persistence tests are in [`rust-database.instructions.md`](../../../instructions/rust-database.instructions.md). `dyn` is the right choice here because the backend is selected at runtime.

## Key lifecycle

KMIP object states (`State` in `crate/kmip/src/kmip_0/kmip_types.rs`) are an enum, never a string. State transitions are enforced by the operation handlers (`Activate`, `Revoke`, `Destroy`, …) against the KMIP specification; review a transition change with [`/kmip-compliance`](../../kmip-compliance/SKILL.md). Do not duplicate the transition table in a second place.

## Error macros

Each crate has its own error enum and construction macros: `kms_error!` / `kms_bail!` (`crate/server/src/error.rs`), `db_error!` / `db_bail!` (`crate/server_database/src/error/mod.rs`), and equivalents in the other crates. Use the crate's macro and variant rather than building error strings by hand; error messages never carry secrets. Propagation guidance: [`/rust-error-propagation`](../../rust-error-propagation/SKILL.md).

## Extension traits

An extension trait adds crate-local helpers to a foreign type (typically `Result` or `Option` mapping to the crate error). Use one only when the same mapping is repeated at several call sites; otherwise a plain function or `map_err` is clearer.

## Dispatch macros

`macro_rules!` is used where many arms differ only by identifier (operation tags, enum conversions); proc macros are confined to `crate/kmip-derive/` (`kmip_enum`, which also generates `From<Enum> for u32`). Do not add a macro for something a function or generic can express.

## Related instruction files

[`rust-server`](../../../instructions/rust-server.instructions.md), [`rust-database`](../../../instructions/rust-database.instructions.md), [`rust-kmip`](../../../instructions/rust-kmip.instructions.md), [`kmip-operations`](../../../instructions/kmip-operations.instructions.md), [`rust-security`](../../../instructions/rust-security.instructions.md), [`rust-crypto`](../../../instructions/rust-crypto.instructions.md).
