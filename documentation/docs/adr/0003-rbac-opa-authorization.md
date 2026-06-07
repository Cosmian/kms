# ADR-0003: RBAC Authorization Model with OPA Sidecar

| Field       | Value                                |
|-------------|--------------------------------------|
| **Status**  | Accepted                             |
| **Date**    | 2026-06-24                           |
| **Branch**  | `rbac_rego`                          |
| **PR**      | [#998](https://github.com/Cosmian/kms/pull/998) |
| **Authors** | Cosmian Engineering                  |

---

## 1. Context

### 1.1 Prior state

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

### 1.2 Requirements driving this ADR

| Requirement | Detail |
|---|---|
| **Role-based decisions** | Support CryptoOfficer, Auditor, User, DomainAdmin, SuperAdmin roles out of the box, with role semantics expressible in a human-readable policy file. |
| **Dynamic roles** | Role names and the operations they permit must be changeable at runtime without restarting the KMS server.  Role vocabulary must **not** be hardcoded in the KMS binary or configuration file. |
| **Domain isolation** | Keys belong to a *domain* (a tenant identifier). Most roles are constrained to their own domain; only a SuperAdmin is cross-domain. |
| **Separation of duties** | Auditor and CryptoOfficer must be mutually constrainable — enforced in policy, not in code. |
| **Audit trail** | Every access decision must be attributable to a policy rule, visible in OPA's structured logs. |
| **Backward compatibility** | Operators who do not configure OPA must see no behavior change. |
| **Fail-closed** | Any failure in the authorization path (network, parse error, OPA timeout) must result in denial, not approval. |

### 1.3 Constraints

- The KMS is Actix-web 4.x, async/multi-threaded Tokio runtime.
- Roles reach the KMS as JWT claims from an external Identity Provider (IdP)
  or Authentication Server; the KMS must not hard-code role names.
- The KMIP 2.1 specification does **not** define user authorization roles.
  The five roles adopted here are drawn from FIPS 140-3 §7.4, NIST SP 800-57
  Part 2 §4.3, and ANSI/INCITS 359-2004 (RBAC standard).

---

## 2. Decision

### 2.1 OPA as an authorization sidecar

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

### 2.2 Three evaluation modes

Three modes are supported, selected via `--opa-url` (enables OPA) and
`--opa-mode`:

| Mode | `KMS_OPA_MODE` | Behavior |
|---|---|---|
| **Disabled** | *(absent `--opa-url`)* | OPA is not called; only legacy DB grants decide. |
| **Exclusive** | `exclusive` | OPA is the sole decision maker; the legacy DB grant table is not consulted.  Suitable for greenfield deployments that manage all access through policy. |
| **Enforcing** | `enforcing` *(default)* | OPA runs first.  If OPA denies → deny immediately.  If OPA allows → the legacy DB grant check also runs for operations on existing objects (belt-and-suspenders).  For object-creation operations (`Create`, `CreateKeyPair`, `Import`, `Register`) OPA's approval is sufficient because no DB grant exists yet. |

`Enforcing` is the recommended production mode: it layeres OPA policy on top of
the existing fine-grained grant model without discarding it.

### 2.3 Input document

The KMS sends the following JSON document to OPA with every evaluation request:

```json
{
  "input": {
    "user":         "alice@acme.com",
    "user_domain":  "acme",
    "roles":        ["CryptoOfficer"],
    "operation":    "Create",
    "object_uid":   "*",
    "object_domain": "acme",
    "is_owner":     false
  }
}
```

| Field | Source | Notes |
|---|---|---|
| `user` | JWT `sub`, TLS CN, or API-token ID | Authenticated identity; never forged. |
| `user_domain` | JWT `as_domain` private claim | Empty for non-JWT authentication. |
| `roles` | JWT `roles` claim (RFC 9068 array) | **Never set by KMS config.** Empty for non-JWT auth → fail-closed. |
| `operation` | `KmipOperation::to_string()` | Lowercase snake_case KMIP operation name (e.g. `"create"`, `"decrypt"`). |
| `object_uid` | Target object UID | `"*"` for object-less operations. |
| `object_domain` | Owner's domain stored with the object | Empty / equals `user_domain` for object-less operations. |
| `is_owner` | `user == object.owner()` | Owners always receive access regardless of role. |

**Key invariant**: The KMS is role-vocabulary-agnostic.  It forwards whatever
role strings the JWT carries and lets Rego interpret them.  Adding a new role
(e.g. `"DataEngineer"`) requires only a Rego change, not a KMS change or
restart.

### 2.4 Default Rego policy (`test_data/opa/kms.rego`)

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

### 2.5 Fail-closed design

Any error condition in the OPA call path results in *denial*:

- Network timeout (5 s hardcoded in `OpaClient`)
- HTTP non-2xx from OPA
- JSON parse failure
- OPA returns `{"result": null}` (undefined policy)

The decision is `Ok(false)` in all these cases.  The KMS never silently grants
access when authorization state is unknown.

### 2.6 Task-local context propagation

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

---

## 3. Consequences

### 3.1 Positive

- **Dynamic policy**: Operators can update role definitions and reload OPA
  (`SIGHUP` or bundle polling) without restarting the KMS.
- **Role-vocabulary independence**: KMS config carries no role strings.
  Role names, operations, and domain constraints are entirely OPA's domain.
- **Audit trail**: OPA's decision log (`/v1/data/kms/reason`) provides a
  per-request, policy-attributed audit record independently of KMS logs.
- **Backward compatibility**: `Disabled` mode (no `--opa-url`) leaves
  existing deployments completely unchanged.
- **Belt-and-suspenders in `Enforcing` mode**: Both OPA policy and the
  legacy per-object grant table must allow an operation, reducing the risk of
  policy misconfiguration silently widening access.
- **Separation of duties**: The Auditor / CryptoOfficer SSD constraint is
  expressed in the Rego policy comment as a role-assignment-time requirement;
  enforcement is policy-level, not hard-coded.

### 3.2 Negative / Trade-offs

- **Extra network hop**: Every permission check incurs a local HTTP round-trip
  to the OPA sidecar.  The 5-second timeout and fail-closed semantics mitigate
  risk but do not eliminate latency.  OPA should be co-located on the same host
  or within the same pod/container group.
- **Role assignment is the authentication server's responsibility**: The KMS no longer stores or
  manages role assignments.  Roles are issued by the authentication server as a `roles` array
  in the JWT (RFC 9068 §2.2.3.1) and forwarded verbatim to OPA as `input.roles`.  OPA itself
  holds no role data; the Rego policy interprets the role strings it receives from the JWT.
  Operators who want to use OPA's Data API (`PUT /v1/data/`) to store role assignments may do
  so, but the reference Rego policy does not require it.  This design adds an operational
  dependency on the authentication server's user and role management.
- **JWT-only roles**: Non-JWT authentication methods (TLS client certificates,
  API tokens) provide no JWT `roles` claim, so `input.roles` is empty.  The Rego
  policy can grant access to owners or on `is_owner`, but pure role-based rules
  will fail-closed for those auth methods unless the policy explicitly handles
  them.
- **`Enforcing` mode complexity**: Object-creation operations bypass the legacy
  DB grant check because no object exists yet; all other operations require both
  OPA and a DB grant.  This asymmetry must be kept in mind when debugging access
  denials.

### 3.3 Alternatives rejected

| Alternative | Reason rejected |
|---|---|
| Embedded OPA Go library via FFI | Significant build complexity; not idiomatic in Rust. |
| Role enum in `kms.toml` | Hard-codes role vocabulary in KMS config; operators cannot rename roles without a KMS change and restart. |
| Static role mapping in DB | Same problem as above; defeats the "dynamic roles" requirement. |
| Casbin (Rust-native) | Smaller ecosystem; less operator familiarity; no native audit-log integration. |
| OPA bundled as in-process Wasm | Experimental OPA Wasm support does not cover the Data API; cannot be updated without redeployment. |

---

## 4. Implementation reference

| Artifact | Location |
|---|---|
| OPA input type | `crate/server/src/core/opa/input.rs` |
| OPA HTTP client | `crate/server/src/core/opa/client.rs` |
| OPA mode enum | `crate/server/src/core/opa/config.rs` |
| Task-local context | `crate/server/src/core/opa/context.rs` |
| Permission check integration | `crate/server/src/core/retrieve_object_utils.rs` — `user_has_permission()` |
| KMS struct field | `crate/server/src/core/kms/mod.rs` — `opa_client: Option<Arc<OpaClient>>` |
| CLI flags | `crate/server/src/config/command_line/opa_config.rs` |
| Reference Rego policy | `test_data/opa/kms.rego` |
| Docker Compose sidecar | `docker-compose.yml` — service `opa` |
