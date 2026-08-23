---
title: "ADR-2026-06-24: RBAC Authorization Model with OPA Sidecar"
status: "Accepted"
date: "2026-06-24"
authors: "Cosmian Engineering"
tags: ["architecture", "decision", "security", "rbac", "opa", "authorization", "multi-tenant"]
supersedes: ""
superseded_by: ""
---

## Status

**Accepted** — merged on branch `rbac_rego`, [PR #998](https://github.com/Cosmian/kms/pull/998)

## Context

### Prior state

The Cosmian KMS has always enforced a per-object, per-user, per-operation grant
table stored in the KMS database (the *legacy permission layer*).  Every managed
object carries an owner, and other users may be granted specific KMIP operations
via explicit `AddAccess` / `RevokeAccess` calls.  The owner always has full
access to their own objects.

This model has two structural gaps for enterprise deployments:

1. **No role-based abstractions.** Access is granted object-by-object.
   There is no concept of a *role* that covers many objects at once.
2. **No central policy enforcement.** Policy lives only in the KMS database;
   auditors, SOC teams, and governance tooling cannot inspect or override it
   without calling KMS-specific APIs.

### Requirements driving this ADR

| Requirement | Detail |
|---|---|
| **Role-based decisions** | Support CryptoOfficer, Auditor, User, DomainAdmin, SuperAdmin roles out of the box, with role semantics expressible in a human-readable policy file. |
| **Dynamic roles** | Role names and the operations they permit must be changeable at runtime without restarting the KMS server.  Role vocabulary must **not** be hardcoded in the KMS binary or configuration file. |
| **Domain isolation** | Keys belong to a *domain* (a tenant identifier). Most roles are constrained to their own domain; only a SuperAdmin is cross-domain. |
| **Separation of duties** | Auditor and CryptoOfficer must be mutually constrainable — enforced in policy, not in code. |
| **Audit trail** | Every access decision must be attributable to a policy rule, visible in OPA's structured logs. |
| **Backward compatibility** | Operators who do not configure OPA must see no behavior change. |
| **Fail-closed** | Any failure in the authorization path (network, parse error, OPA timeout) must result in denial, not approval. |

### Constraints

- The KMS is Actix-web 4.x, async/multi-threaded Tokio runtime.
- Roles reach the KMS as JWT claims from an external Identity Provider (IdP)
  or Authentication Server; the KMS must not hard-code role names.
- The KMIP 2.1 specification does **not** define user authorization roles.
  The five roles adopted here are drawn from FIPS 140-3 §7.4, NIST SP 800-57
  Part 2 §4.3, and ANSI/INCITS 359-2004 (RBAC standard).

## Decision

### OPA as an authorization sidecar

[Open Policy Agent (OPA)](https://www.openpolicyagent.org/) is deployed as a
sidecar process alongside the KMS server.  The KMS calls OPA over its REST Data
API (`POST /v1/data/kms/allow`) for every access-control decision.

**Why a sidecar, not an embedded library?**

- Policy files (`.rego`) are human-readable and version-controlled independently
  of the Rust binary.
- Operators can reload policy without restarting the KMS.
- OPA's decision log (`--log-level=info`) produces a structured audit trail
  independent of KMS logs.
- A sidecar allows OPA to hold its own data documents (role assignments, domain
  maps) pushed via the OPA Data API — the KMS never needs to store role data.

### Three evaluation modes

Three modes are supported, selected via `--opa-url` (enables OPA) and
`--opa-mode`:

| Mode | `KMS_OPA_MODE` | Behavior |
|---|---|---|
| **Disabled** | *(absent `--opa-url`)* | OPA is not called; only legacy DB grants decide. |
| **Exclusive** | `exclusive` | OPA is the sole decision maker; the legacy DB grant table is not consulted.  Suitable for greenfield deployments that manage all access through policy. |
| **Enforcing** | `enforcing` *(default)* | OPA runs first.  If OPA denies → deny immediately.  If OPA allows → the legacy DB grant check also runs for operations on existing objects (belt-and-suspenders).  For object-creation operations (`Create`, `CreateKeyPair`, `Import`, `Register`) OPA's approval is sufficient because no DB grant exists yet. |

`Enforcing` is the recommended production mode: it layers OPA policy on top of
the existing fine-grained grant model without discarding it.

### Input document

The KMS sends the following JSON document to OPA with every evaluation request:

```json
{
  "input": {
    "user":          "alice@acme.com",
    "user_domain":   "acme",
    "roles":         ["CryptoOfficer"],
    "operation":     "create",
    "object_uid":    "*",
    "object_domain": "acme",
    "is_owner":      false
  }
}
```

| Field | Source | Notes |
|---|---|---|
| `user` | JWT `sub`, TLS CN, or API-token ID | Authenticated identity; never forged. |
| `user_domain` | JWT `as_domain` / `as_rid` private claim | Empty for non-JWT authentication. |
| `roles` | JWT `roles` claim (RFC 9068 array) | **Never set by KMS config.** Empty for non-JWT auth → fail-closed. |
| `operation` | `KmipOperation::to_string()` | Lowercase snake_case KMIP operation name (e.g. `"create"`, `"decrypt"`). |
| `object_uid` | Target object UID | `"*"` for object-less operations. |
| `object_domain` | Owner's domain stored with the object | Empty / equals `user_domain` for object-less operations. |
| `is_owner` | `user == object.owner()` | Owners always receive access regardless of role. |

**Key invariant**: The KMS is role-vocabulary-agnostic.  It forwards whatever
role strings the JWT carries and lets Rego interpret them.  Adding a new role
(e.g. `"DataEngineer"`) requires only a Rego change, not a KMS change or
restart.

### Default Rego policy (`test_data/opa/kms.rego`)

The repository ships a reference policy implementing five standard roles:

| Role | Scope | Permitted operations | Normative source |
|---|---|---|---|
| `SuperAdmin` | Global (cross-domain) | All operations | ANSI/INCITS 359-2004 §4.2 |
| `DomainAdmin` | Own domain | All operations | ANSI/INCITS 359-2004 §4.2 |
| `CryptoOfficer` | Own domain | Key lifecycle: `create`, `create_key_pair`, `import`, `get`, `export`, `locate`, `get_attributes`, `set_attribute`, `modify_attribute`, `delete_attribute`, `add_attribute`, `activate`, `revoke`, `archive`, `recover`, `destroy`, `rekey`, `rekey_key_pair` | FIPS 140-3 §7.4; NIST SP 800-57 Part 2 §4.3 |
| `Auditor` | Own domain | Read-only: `locate`, `get`, `get_attributes`, `list_access`, `query_access`, `mac_verify` | NIST SP 800-57 Part 2 §4.3; NIST SP 800-53 AU-9 |
| `User` | Own domain | Crypto-use only: `encrypt`, `decrypt`, `sign`, `verify`, `mac`, `mac_verify`, `derive_key`, `locate`, `get_attributes` | FIPS 140-3 §7.4; PKCS#11 v3.0 |

Owners always have full access to their objects, regardless of role.

Operators may supply their own Rego file; the default policy is a starting
point, not a requirement.

### Fail-closed design

Any error condition in the OPA call path results in *denial*:

- Network timeout (5 s hardcoded in `OpaClient`)
- HTTP non-2xx from OPA
- JSON parse failure
- OPA returns `{"result": null}` (undefined policy)

The decision is `Ok(false)` in all these cases.  The KMS never silently grants
access when authorization state is unknown.

### Task-local context propagation

The authenticated user's roles and domain are extracted by the auth middleware
and stored in a `tokio::task_local!` variable (`OPA_USER_CONTEXT`).  Every
async operation within the HTTP request's task scope reads this context when
building the OPA input document.

`thread_local!` was explicitly rejected because:

- Tokio's multi-threaded scheduler migrates tasks across OS threads at every
  `.await` point.
- A `thread_local!` value set before an `.await` may be invisible — or belong to
  a *different* request — when the task resumes on another thread.

`tokio::task_local!` (backed by Tokio's `task_local!` macro) is scoped to the
logical async task and survives `.await` migration safely.

## Consequences

### Positive

- **POS-001 Dynamic policy**: Operators can update role definitions and reload OPA
  (`SIGHUP` or bundle polling) without restarting the KMS.
- **POS-002 Role-vocabulary independence**: KMS config carries no role strings.
  Role names, operations, and domain constraints are entirely OPA's domain.
- **POS-003 Audit trail**: OPA's decision log (`/v1/data/kms/reason`) provides a
  per-request, policy-attributed audit record independently of KMS logs.
- **POS-004 Backward compatibility**: `Disabled` mode (no `--opa-url`) leaves
  existing deployments completely unchanged.
- **POS-005 Belt-and-suspenders in `Enforcing` mode**: Both OPA policy and the
  legacy per-object grant table must allow an operation, reducing the risk of
  policy misconfiguration silently widening access.
- **POS-006 Separation of duties**: The Auditor / CryptoOfficer SSD constraint is
  expressed in the Rego policy comment as a role-assignment-time requirement;
  enforcement is policy-level, not hard-coded.

### Negative

- **NEG-001 Extra network hop**: Every permission check incurs a local HTTP round-trip
  to the OPA sidecar.  The 5-second timeout and fail-closed semantics mitigate
  risk but do not eliminate latency.  OPA should be co-located on the same host
  or within the same pod/container group.
- **NEG-002 Role assignment is the authentication server's responsibility**: The KMS
  no longer stores or manages role assignments.  Roles are issued by the authentication
  server as a `roles` array in the JWT (RFC 9068 §2.2.3.1) and forwarded verbatim to OPA
  as `input.roles`.  OPA itself holds no role data; the Rego policy interprets the role
  strings it receives from the JWT.  Operators who want to use OPA's Data API
  (`PUT /v1/data/`) to store role assignments may do so, but the reference Rego policy
  does not require it.  This design adds an operational dependency on the authentication
  server's user and role management.
- **NEG-003 JWT-only roles**: Non-JWT authentication methods (TLS client certificates,
  API tokens) provide no JWT `roles` claim, so `input.roles` is empty.  The Rego
  policy can grant access to owners or on `is_owner`, but pure role-based rules
  will fail-closed for those auth methods unless the policy explicitly handles them.
- **NEG-004 `Enforcing` mode asymmetry**: Object-creation operations bypass the legacy
  DB grant check because no object exists yet; all other operations require both
  OPA and a DB grant.  This asymmetry must be kept in mind when debugging access
  denials.

## Alternatives Considered

### Embedded OPA Go library via FFI

- **ALT-001 Description**: Compile OPA as a Go shared library and call it from Rust via FFI.
- **ALT-002 Rejection Reason**: Significant build complexity; cross-language memory management;
  not idiomatic in Rust; breaks the FIPS build which does not allow arbitrary C/Go linkage.

### Role enum in `kms.toml`

- **ALT-003 Description**: Define allowed roles as an enum or list in the server configuration file.
- **ALT-004 Rejection Reason**: Hard-codes role vocabulary in KMS config; operators cannot rename
  roles without a KMS change and restart. Defeats the "dynamic roles" requirement.

### Static role mapping in database

- **ALT-005 Description**: Store role-to-permission mappings in the KMS database (e.g. a `roles` table).
- **ALT-006 Rejection Reason**: Same problem as enum-in-config; role changes require a database
  migration or admin API call; no independent audit log; no human-readable policy file.

### Casbin (Rust-native)

- **ALT-007 Description**: Use the Rust `casbin` crate for policy-based access control.
- **ALT-008 Rejection Reason**: Smaller ecosystem; less operator familiarity; no native audit-log
  integration comparable to OPA's; would still require a sidecar model for live policy reload.

### OPA bundled as in-process Wasm

- **ALT-009 Description**: Compile the Rego policy to Wasm and evaluate it in-process.
- **ALT-010 Rejection Reason**: Experimental OPA Wasm support does not cover the Data API;
  cannot be updated without redeployment; no audit log support.

## Implementation Notes

- **IMP-001**: The `OpaClient` uses a 5-second HTTP timeout with fail-closed semantics.
  OPA must be co-located (same host or pod) to avoid latency issues.
- **IMP-002**: Domain is stamped on every newly created object from the creator's JWT
  `as_domain` / `as_rid` claim via `OpaUserContext`.  Existing objects upgraded from
  pre-OPA KMS versions will have an empty domain string; the Rego policy must handle
  `object_domain == ""` gracefully (e.g., allow owner access regardless of domain).
- **IMP-003**: The `domain` column is added to all database backends (SQLite, PostgreSQL,
  MySQL, Redis-findex) via `ALTER TABLE ADD COLUMN domain TEXT NOT NULL DEFAULT ''`.
  This migration is applied automatically on server startup.
- **IMP-004**: `enforce_create_permission` explicitly preserves KMS-native CryptoOfficer
  access (`crypto_officer.users` list) for the `Create` right even when OPA is active,
  so split-key ceremony participants retain their ability to create key shares.
- **IMP-005 Success criteria**: All 15 OPA test vectors in `test_data/vectors/opa/` pass,
  covering all five roles × disabled/exclusive/enforcing modes × allow and deny paths.

## References

- **REF-001**: [`test_data/opa/kms.rego`](../../test_data/opa/kms.rego) — reference Rego policy
- **REF-002**: [`crate/server/src/core/opa/`](../../crate/server/src/core/opa/) — OPA client, input type, mode enum, task-local context
- **REF-003**: [`crate/server/src/middlewares/jwt/jwt_token_auth.rs`](../../crate/server/src/middlewares/jwt/jwt_token_auth.rs) — JWT domain/roles extraction into `AuthenticatedUser`
- **REF-004**: [`crate/server/src/middlewares/auth_verifier/token.rs`](../../crate/server/src/middlewares/auth_verifier/token.rs) — Auth Verifier JWT domain/roles extraction
- **REF-005**: [`crate/server/src/core/retrieve_object_utils.rs`](../../crate/server/src/core/retrieve_object_utils.rs) — `user_has_permission()` integration point
- **REF-006**: [`test_data/vectors/opa/`](../../test_data/vectors/opa/) — integration test vectors (15 total)
- **REF-007**: FIPS 140-3 §7.4 — CryptoOfficer and User mandatory module roles
- **REF-008**: NIST SP 800-57 Part 2 §4.3 — Key management role definitions
- **REF-009**: ANSI/INCITS 359-2004 §4.2 — Hierarchical + Constrained RBAC
- **REF-010**: NIST SP 800-53 Rev 5 AC-5, AC-6, AU-9 — Separation of duties, least privilege, audit
- **REF-011**: RFC 9068 §2.2.3.1 — `roles` claim in JWT access tokens
- **REF-012**: [PR #998](https://github.com/Cosmian/kms/pull/998) — implementation PR
