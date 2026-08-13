---
title: "ADR-0006: PostgreSQL Audit Backend"
status: "Accepted"
date: "2026-08-10"
authors: "contributors, security operations engineers, compliance engineers"
tags: ["architecture", "decision", "audit", "postgresql", "compliance"]
supersedes: ""
superseded_by: ""
---

# ADR-0006: PostgreSQL Audit Backend

## Status

Accepted

## Context

ADR-0003 added a tamper-evident audit layer with exactly one storage backend: an
append-only JSONL file (`FileSink`). The file backend is deliberately the
"always available" option, but compliance deployments (PCI-DSS Req. 10, HIPAA
§164.312(b)) need the audit trail in a queryable, centrally-managed, separately-owned
datastore that the KMS process itself cannot rewrite.

This ADR adds `PostgreSQL` as a second audit backend, selected by configuration, with the
file backend remaining the default.

## Decision

### Trait boundary, not a `Box<dyn>` or enum

`cosmian_kms_interfaces::AuditSink` is a small async trait (`resume`, `write_event`,
`write_failure_is_fatal`, `final_sync`, `name`). The writer task (`crate::core::audit::writer`)
is generic over `S: AuditSink`, monomorphised once inside `AuditStore::start`. `KMS` and
`AuditMiddleware` keep holding one concrete `Option<AuditStore>` — the backend never leaks
into their types. A sink never assigns `id` or computes `row_hash`; the writer task owns the
chain and persists what it is handed, in order. This is what makes a third backend a new file,
not a refactor.

### Per-instance chains, single-writer enforced by the primary key

Each KMS instance owns an independent hash chain, restarting at `id = 0` with an
all-zeros `prev_hash`. The composite primary key `(instance_id, id)` makes a fork
**impossible**, not just detected: two writers sharing an `instance_id` collide on
`INSERT` with `SQLSTATE 23505`. A unique violation is disambiguated before being reported:
if the stored `row_hash` at that slot is byte-identical to the one we tried to write, it is
our own earlier attempt whose acknowledgement was lost to a network blip — treated as
success. Otherwise it is a genuinely different writer — fatal, naming the instance ID.

An earlier draft used a `pg_try_advisory_lock` instead. It was rejected: PostgreSQL advisory
locks are database-scoped (not cluster-wide, so no false collision across separate
databases on one server) but are released silently if the holding connection drops — an
instance believing itself exclusive could keep writing while a second instance took over,
exactly when the guarantee matters most. The primary key constraint is enforced by the
database on every insert, independent of connection liveness.

### Fail-fast, never a silent fallback

Backend selection is config-time only (`[audit.postgres].url` set → PostgreSQL; otherwise →
file). `PostgreSQL` unreachable at startup aborts the server. A runtime write failure that
survives the sink's own retry budget is escalated via `AuditSink::write_failure_is_fatal`
(`true` for `PostgreSQL`, `false` for the file backend, preserving ADR-0003's behaviour): the
writer stops consuming, `AuditStore::wait_fatal()` resolves, and `start_kms_server.rs` stops
the HTTP server. Serving requests that are silently not being audited is worse than being
unavailable, for a deployment that switched audit logging on.

### Defence in depth, honestly scoped

Three independent layers protect `kms_audit_events`:

| Layer | Stops | Does not stop |
|---|---|---|
| `REVOKE UPDATE, DELETE, TRUNCATE … FROM PUBLIC` | A role granted privileges by a permissive earlier migration | Almost everything on a fresh table (PostgreSQL grants nothing to `PUBLIC` by default) |
| `BEFORE UPDATE/DELETE/TRUNCATE` triggers | Every ordinary role, **including the table owner** | A superuser or the owner via `DISABLE TRIGGER`/`DROP TRIGGER` |
| SHA-256 hash chain | Uncoordinated modification | A coordinated writer with `UPDATE` access — the chain is unkeyed, so whoever can write can recompute every later `row_hash` |

The honest claim is **tamper-evident against uncoordinated modification**, not tamper-proof
against a privileged administrator. Production deployments should provision the audit
database with the KMS role holding only `INSERT`/`SELECT` on a table owned by a different
role — see `documentation/docs/configuration/audit-postgres-setup.sql`.

### Microsecond timestamp truncation

`cosmian_kms_access::audit::audit_now()` truncates to microsecond resolution at draft-creation
time. `PostgreSQL TIMESTAMPTZ` cannot store nanoseconds; truncating before the hash is computed
(rather than losing digits silently at the sink) keeps the canonical byte form, and therefore
`row_hash`, identical regardless of which backend later persists the event.

### Fail-fast over spool-and-replay

A local disk spool with idempotent replay-on-recovery would make transient `PostgreSQL`
failures survivable without operator intervention. It is deferred (`.agents/future_work.md`):
it needs a separate `ON CONFLICT DO NOTHING` replay query (the live path must keep treating a
conflict as a rogue writer, never silently deduplicate) and a rotation policy for the spool
file. Fail-fast is the simpler, safer default for this PR.

## Consequences

- A third audit backend is a new `AuditSink` implementation plus an `AuditBackendParams`
  variant — no changes to `AuditStore`, the writer task, or the middleware.
- Operators choosing the `PostgreSQL` backend take on running and backing up a second
  database, separate from the main object-storage database (enforced at config-resolution
  time, not just documented).
- `ckms` now links `cosmian_kms_server_database` (SQLite + MySQL + PostgreSQL backends) to
  read the audit chain for `export`/`verify`. Slimming this down via optional cargo features
  is deferred (`.agents/future_work.md`).

## Alternatives Considered

- **A single global chain across instances** — correct cross-instance ordering, but needs
  `pg_advisory_xact_lock` + a head re-read per event, adding a round trip and lock contention
  to every audited request. Deferred.
- **Configurable audit table name** — a dynamic identifier cannot be a bind parameter; the
  fixed `kms_audit_events` name is relocated via `search_path` instead. Deferred.
