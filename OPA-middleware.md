# OPA RBAC Middleware — Context and Implementation Plan

> **Status:** this is the original design and implementation plan of the OPA integration. The feature is implemented and the plan has been corrected where the implementation differs from it: the domain claim is `as_rid` (the realm ID issued by the Authentication Verifier, which replaced the planned per-user `domain` and the `as_domain` claim; the KMS still accepts `as_domain` as a legacy alias), the caller is identified by the `email` claim and then by `sub`, `is_super_admin` is not part of the OPA input, and the operation names are lowercase `snake_case`. Phases 1 to 4 describe the Authentication Verifier work, minus the per-user `domain` that was planned there and dropped because the realm is the domain. The reference documentation is in [`documentation/docs/configuration/authorization/`](documentation/docs/configuration/authorization/index.md).

## Context

### What is being built

An OPA (Open Policy Agent) authorization layer for Cosmian KMS that evaluates RBAC rules
before (or alongside) the existing KMS permission system.

KMS runs the OPA server as a sidecar. On every KMIP operation, KMS calls
`POST /v1/data/kms/allow` with a JSON input document. OPA evaluates `kms.rego` and returns
`{"result": true|false}`.

Three modes:

| Mode | Name | Semantics |
|------|------|-----------|
| 1 | `Disabled` | OPA is not called; existing KMS permission system runs unchanged |
| 2 | `Exclusive` | Only OPA decides; KMS permission system is skipped |
| 3 | `Enforcing` | OPA is authoritative: a denial, error or timeout is final and an allow is sufficient. Exceptions: native Crypto Officers on non-HSM objects skip OPA and use the KMS permission system; HSM-backed objects must also pass the KMS permission system after OPA allows |

Fail-closed: if OPA is configured but unreachable, the request is denied.

---

### Role model

Five roles (defined in the authentication server's realm configuration, embedded in JWT):

| Role | Access |
|------|--------|
| `SuperAdmin` | Unrestricted, cross-domain |
| `DomainAdmin` | Full control within their own domain |
| `CryptoOfficer` | Key lifecycle operations within their domain (FIPS 140-3 §7.4) |
| `Auditor` | Read-only metadata within their domain (NIST SP 800-53 AU-9) |
| `User` | Crypto-use only within their domain (encrypt/decrypt/sign/verify) |

Roles are stored per-user per-realm in the authentication server's `userpass` table.
Multiple roles per user are allowed (RBAC union semantics in OPA — existential over the array).
An object owner always has full access regardless of role.

---

### Architecture: A3-i (JWT carries `roles` claim)

```text
User authenticates → Auth Server issues JWT
  JWT contains:
    "roles": ["CryptoOfficer"]           ← RFC 9068 §2.2.3.1, RFC 7643 §4.1.2
    "as_rid": "acme.com"                 ← private claim (RFC 7519 §4.3): the realm ID

KMS receives request with JWT
  KMS extracts:
    email (else sub) → input.user
    as_rid           → input.user_domain   (`as_domain` is accepted as a legacy alias)
    roles            → input.roles[]

KMS calls OPA:
  POST /v1/data/kms/allow
  {
    "input": {
      "user":          "alice@acme.com",
      "user_domain":   "acme.com",
      "roles":         ["CryptoOfficer"],
      "operation":     "create",
      "object_uid":    "*",
      "object_domain": "acme.com",
      "is_owner":      false
    }
  }

OPA evaluates kms.rego → {"result": true}

KMS applies mode logic:
  Exclusive:  allow = opa_result
  Enforcing:  native Crypto Officer, non-HSM object:  allow = kms_result  (OPA skipped)
              HSM-backed object:                      allow = opa_result AND kms_result
              any other request:                      allow = opa_result
```

Non-JWT auth (mTLS, API token): KMS sends `"roles": []` → all role-based rules are false → fail-closed.

---

### Domain model

`user_domain` comes from the `as_rid` JWT private claim (`as_domain` is accepted as a legacy alias; a claim named `domain` is not read), not from the `sub` string. This decouples username format from domain assignment entirely.

`object_domain` is stamped at object creation from the creator's `user_domain` and stored as a new `domain` column on the `objects` table. It is immutable after creation. Only the `Create` operation stamps it: the objects written by the other creation operations (for example `CreateKeyPair`, `Import`, `Certify`, `DeriveKey` and `ReKey`) keep `domain = ''`. The Redis-Findex and HSM stores do not persist the domain.

For object-less operations (e.g. `Create`): `object_domain = user_domain` at permission-check time.

An empty domain means "no domain" and never matches: the `same_domain` rule of `kms.rego` requires `user_domain` and `object_domain` to be both non-empty and equal. A user without a domain and an object with `domain = ''` (created before this feature, or by an operation that does not stamp the domain) therefore match no role rule: only the object owner (owner rule) and the `SuperAdmin` role are allowed.

---

### Key files

**Authentication server (`Cosmian/authentication`, branch `develop`):**

| File | Change |
|------|--------|
| `client/src/models/client_claims.rs` | New `AuthorizationClaims` struct (`roles`); the realm ID is issued as `as_rid` in `AuthPrivateClaims` (planned as a separate `as_domain`) |
| `client/src/models/base.rs` | `roles: Vec<String>` on `UserPass` (a per-user `domain` was planned and dropped: the realm is the domain) |
| `server/src/session/jwt.rs` | `issue_token()` gains a `roles` parameter |
| `server/src/server/endpoints/client_endpoints.rs` | Login fetches userpass; passes its roles to the token |
| `server/src/database/impls/{sqlite,postgres,mysql}.rs` | Schema + CRUD for new columns |
| `server/documentation/openapi.yaml` | `UserPass` schema update |

**KMS (`Cosmian/kms`, branch `rbac_rego`):**

| File | Change |
|------|--------|
| `test_data/opa/kms.rego` | `input.roles[_]` existential; `count(input.roles) == 0` for no-role |
| `crate/interfaces/src/stores/object_with_metadata.rs` | Add `domain: String` field |
| `crate/server_database/src/stores/sql/query.sql` | `domain` column on `objects` |
| `crate/server_database/src/stores/sql/query_mysql.sql` | Same for MySQL |
| `crate/server_database/src/stores/sql/pgsql.rs` | Migration block for `domain` |
| `crate/server_database/src/stores/sql/{sqlite,mysql}.rs` | CRUD update |
| `crate/server/src/core/retrieve_object_utils.rs` | OPA call in `user_has_permission()` |
| `crate/server/src/core/kms/mod.rs` | `opa_client: Option<Arc<OpaClient>>` |
| `crate/server/src/config/params/server_params.rs` | `opa_params: Option<OpaParams>` |
| `crate/server/src/config/command_line/clap_config.rs` | `--opa-url`, `--opa-mode` |

---

### OPA input document

```json
{
  "input": {
    "user":            "<JWT email, else sub>",
    "user_domain":     "<as_rid claim, or '' for non-JWT>",
    "roles":           ["<role1>", ...],
    "operation":       "<KMIP operation name, lowercase snake_case>",
    "object_uid":      "<KMIP object UID, or '*' for object-less ops>",
    "object_domain":   "<objects.domain column, or user_domain for object-less ops>",
    "is_owner":        true
  }
}
```

| Field | Source | Default |
|-------|--------|---------|
| `user` | JWT `email` claim (else `sub`) / TLS CN / API-token id | — |
| `user_domain` | JWT `as_rid` private claim (`as_domain` legacy alias) | `""` |
| `roles` | JWT `roles` public claim (RFC 9068) | `[]` |
| `operation` | KMIP operation name, e.g. `create`, `get_attributes` | — |
| `object_uid` | Target object UID | `"*"` for object-less ops |
| `object_domain` | `objects.domain` column | `user_domain` for object-less ops |
| `is_owner` | `user == owm.owner()` | `false` |

---

### Normative references

| Standard | Used for |
|----------|----------|
| RFC 7519 | JWT registered claims (`sub`, `exp`, etc.) |
| RFC 9068 §2.2.3.1 | `roles` as a standard JWT authorization claim |
| RFC 7643 §4.1.2 | SCIM User schema — `roles` attribute definition |
| FIPS 140-3 §7.4 | CryptoOfficer and User as mandatory module roles |
| NIST SP 800-57 Part 2 §4.3 | Key management role definitions |
| ANSI/INCITS 359-2004 §4.2 | RBAC hierarchy and separation of duties |
| NIST SP 800-53 Rev 5 AC-5, AC-6, AU-9 | Least privilege, SoD, audit protection |

### KMIP role taxonomy (verified against local spec files)

> **Verified against `kmip/v2.1/kmip-spec-v2.1-os.html` and `kmip/v3.0/kmip-spec-v3.0-csd01.html`.**

KMIP defines **two** concepts named "role" — neither of which is a user authorization role:

#### 1. Endpoint Role (KMIP 2.1 §11.19, Table 451–452)

Used exclusively by the `Set Endpoint Role` operation (§6.1.54 / §6.2.5), which
swaps client/server roles on a bidirectional communication channel.

| Value | Description |
|-------|-------------|
| `Client` | The endpoint that sends requests and receives responses |
| `Server` | The endpoint that receives requests and sends responses |

**Not a user authorization concept.** Only relevant for KMIP bidirectional channel setup.

#### 2. Key Role Type (KMIP 2.1 §11.26, Table 462)

A cryptographic key classification attribute — describes the *purpose* of a key,
not who may use it. Values (KMIP 2.1):

| Name | Value | Meaning |
|------|-------|---------|
| BDK | 0x00000001 | Base Derivation Key |
| CVK | 0x00000002 | Card Verification Key |
| DEK | 0x00000003 | Data Encryption Key |
| MKAC | 0x00000004 | Master Key — AC |
| MKSMC | 0x00000005 | Master Key — SMC |
| MKSMI | 0x00000006 | Master Key — SMI |
| MKDAC | 0x00000007 | Master Key — DAC |
| MKDN | 0x00000008 | Master Key — DN |
| MKCP | 0x00000009 | Master Key — CP |
| MKOTH | 0x0000000A | Master Key — Other |
| KEK | 0x0000000B | Key Encryption Key |
| MAC16609 | … | MAC key (ISO 16609) |

**Not a user authorization concept.** This is a key metadata attribute, not an
identity/permission claim.

#### Conclusion: KMIP does NOT define user authorization roles

Neither KMIP 2.1 nor KMIP 3.0 defines concepts such as Administrator, Auditor,
or CryptoOfficer as user authorization roles. The terms "CryptoOfficer" and
"Auditor" do not appear anywhere in either specification outside of OASIS
administrative boilerplate.

The role model in this project (`SuperAdmin`, `DomainAdmin`, `CryptoOfficer`,
`Auditor`, `User`) is **implementation-defined**, sourced from:

- **FIPS 140-3 §7.4** — mandates a "Crypto Officer" role and a "User" role for
  cryptographic module access control. Names and semantics are normative.
- **NIST SP 800-57 Part 2 §4.3** — defines "Key Management Officer", "Audit and
  Compliance Officer", and "Key User" as organizational roles in a key management
  infrastructure.
- **ANSI/INCITS 359-2004 §4.2** — RBAC model for hierarchical and constrained
  role structures (basis for DomainAdmin hierarchy).

These are the correct normative citations for the role names used in `kms.rego`.

---

## Design decisions

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| S1 | Role storage in auth DB | JSON TEXT column on `userpass` | Minimal schema change; roles are only read at login, never filtered in SQL |
| R1 | JWT `roles` wire shape | `Vec<String>` — plain string array | RFC 9068 provides no vocabulary; string array is the common implementation |
| M3 | Multi-role | Allowed; OPA uses `input.roles[_] == "X"` | Flexibility without ambiguity; union semantics via Rego existential |
| DB1 | DB storage | JSON column (not join table) | No SQL filtering by role; join table complexity unwarranted |
| P1 | Claims struct placement | New `AuthorizationClaims` struct (RFC 9068 §4.2) | `roles` is a public IANA-registered claim, not a private `as_` claim |
| N1 | Non-JWT auth → roles | `input.roles = []` | Fail-closed; Rego existential over empty set is false |
| E3 | `user_domain` source | The `as_rid` JWT private claim (the realm ID; `as_domain` was the original proposal and is accepted as a legacy alias) | Decouples username format from domain; `sub` may be email, CN, or UUID; a realm is already an isolated namespace, so no second claim is needed |
| OD1 | Object domain assignment | Stamped at creation from `user_domain`, immutable | Auditable, consistent; mirrors how `owner` is assigned |
| OB1 | Object domain storage | New `domain` column on `objects` table | First-class operational field; consistent with `owner` and `state` |
| D-B | Domain claim placement | `AuthPrivateClaims` with `rename = "as_rid"` | Private deployment claim (RFC 7519 §4.3); not an IANA-registered public claim |
| SA3 | Ceremony super-admin | Independent of OPA: it is not part of the OPA input and works through the native KMS gate | Two systems are independent; OPA handles JWT roles, native KMS handles the ceremony |

---

## Ceremony super-admin and OPA — separation of concerns

The KMS key ceremony (an XOR $n$-of-$n$ split key shared between the Crypto Officers) and OPA RBAC are **independent**:

- `is_super_admin` is **not** part of the OPA input document, and OPA has no visibility into the ceremony state.
- In Mode 1 (Disabled): the ceremony works as before, inside the native KMS check.
- In Mode 2 (Exclusive): OPA decides the operations that query it and the ceremony has no effect on them. The native KMS check still applies on the paths that never query OPA (for example `Locate` and `Destroy`), where an activated Crypto Officer reaches every non-HSM object.
- In Mode 3 (Enforcing): native Crypto Officers (including the ceremony candidates listed in `crypto_officer_users`) skip OPA on non-HSM objects and are evaluated by the native KMS check only.

The JWT `SuperAdmin` role (assigned by the Authentication Verifier administrator) and the ceremony activation of a Crypto Officer are distinct concepts with different trust anchors and different enforcement paths. An activated Crypto Officer is outside the policy, so keep `crypto_officer.users` small and trusted.

---

## Implementation plan

### Phase 1 — Auth server: data model

**Step 1** — `client/src/models/client_claims.rs`

Add `AuthorizationClaims` (RFC 9068 §2.2.3.1 public claims, RFC 7643 §4.1.2):

```rust
/// RFC 9068 §2.2.3.1 — Authorization claims (IANA-registered via RFC 7643 §4.1.2).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizationClaims {
    /// `roles` — roles assigned to the subject.
    /// RFC 7643 §4.1.2; registered in IANA JWT Claims registry by RFC 9068 §7.2.1.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}
```

The realm ID is already issued in `AuthPrivateClaims` as the private claim `as_rid` (RFC 7519 §4.3), and a realm is an isolated authentication namespace, so it is used as the domain. No separate `domain` claim is added: `as_domain`, which this plan first proposed, is dropped on the Authentication Verifier side (see the Authentication Verifier ADR `2026-06-24-role-jwt-opa-integration.md`, Decision 3). The KMS reads `as_rid` and still accepts `as_domain` as a legacy alias.

Add to `ClientClaims`:

```rust
/// RFC 9068 §2.2.3.1 — authorization attributes (roles, groups, entitlements).
#[serde(flatten)]
pub authorization: AuthorizationClaims,
```

**Step 2** — `client/src/models/base.rs`

Add to `UserPass`:

```rust
/// Roles assigned to this user in this realm.
/// Serialised as JSON array in the DB column `roles`.
pub roles: Vec<String>,
```

The user's domain is the realm the user belongs to (`UserPass::realm`); there is no per-user `domain` field.

---

### Phase 2 — Auth server: database layer (all 3 backends)

**Step 3** — Schema change in each backend:

```sql
-- Add to CREATE TABLE userpass:
roles  TEXT NOT NULL DEFAULT '[]'
```

Migration query (run at startup, check-then-ALTER pattern; the exact statements differ per backend, for example MySQL adds the column, back-fills `'[]'`, then makes it `NOT NULL`):

```sql
-- add-column-roles
ALTER TABLE userpass ADD COLUMN roles TEXT NOT NULL DEFAULT '[]';
```

**Step 4** — CRUD update in all 3 backends:

- `create_userpass`: INSERT includes `roles` (JSON-serialised)
- `get_userpass`: SELECT reads `roles` (deserialise → `Vec<String>`)
- `update_userpass`: UPDATE includes `roles`
- `list_*`: SELECT includes `roles`

Serialisation:

- write: `serde_json::to_string(&userpass.roles)?`
- read: `serde_json::from_str::<Vec<String>>(&row_roles).unwrap_or_default()`

---

### Phase 3 — Auth server: token issuance

**Step 5** — `server/src/session/jwt.rs`

New signature:

```rust
pub fn issue_token(
    subject: &str,
    auth_scheme: AuthScheme,
    realm_id: &str,
    roles: Vec<String>,          // NEW — from UserPass.roles
    extra_claims: HashMap<String, serde_json::Value>,
    jwt_config: &JwtTokenConfig,
    expiration_seconds: i64,
) -> Result<String, AuthError>
```

Inside: `claims.authorization.roles = Some(roles)` when the list is not empty; the realm ID is emitted as `as_rid`.

**Step 6** — `server/src/server/endpoints/client_endpoints.rs`

In `login()`, after TOTP check, before `issue_token()`: the roles are read from the userpass record only when the client authenticated with a username and password. Any other scheme (JWT, mTLS) gets an empty list, so a same-named identity never borrows the roles of a userpass row (fail-closed, N1):

```rust
let roles = if authenticated_client.auth_scheme == AuthScheme::UsernamePassword {
    database
        .get_userpass(&realm.id, &authenticated_client.username)
        .await?
        .map(|up| up.roles)
        .unwrap_or_default()
} else {
    Vec::new()
};
```

---

### Phase 4 — Auth server: API surface

**Step 7** — `server/src/server/endpoints/realms_endpoints.rs`

No handler logic change needed — `roles` is carried by the `UserPass` struct
which is already deserialized from the request body and passed to `database.create_userpass()`.

**Step 8** — `server/documentation/openapi.yaml`

Add to `UserPass` schema:

```yaml
roles:
  type: array
  items:
    type: string
  description: "Roles assigned to this user (RFC 9068 §2.2.3.1)"
  example: ["CryptoOfficer"]
```

---

### Phase 5 — KMS: Rego policy update

**Step 9** — `test_data/opa/kms.rego`

- `input.role` → removed entirely
- All role checks: `input.role == "X"` → `input.roles[_] == "X"` (Rego existential)
- `reason := "no_role"`: check `count(input.roles) == 0; not input.is_owner`
- Header: document `input.roles` as array from JWT, `input.user_domain` from the `as_rid` claim (`as_domain` legacy alias)

---

### Phase 6 — KMS: object domain

**Step 10** — `crate/interfaces/src/stores/object_with_metadata.rs`

```rust
pub struct ObjectWithMetadata {
    id: String,
    object: Object,
    owner: String,
    state: State,
    attributes: Attributes,
    domain: String,   // NEW — stamped at creation, empty string for legacy objects
}
```

Add `domain()` getter; update `new()` to require `domain: String`; update `Display`.

**Step 11** — SQL schema (`query.sql`, `query_mysql.sql`)

```sql
-- In CREATE TABLE objects:
domain VARCHAR(255) NOT NULL DEFAULT '',
```

Migration:

```sql
-- add-column-domain
ALTER TABLE objects ADD COLUMN domain VARCHAR(255) NOT NULL DEFAULT '';
```

**Step 12** — DB backend CRUD (sqlite.rs, pgsql.rs, mysql.rs)

- `ObjectsStore::create()` trait: add `domain: &str` parameter
- INSERT: include `domain`
- SELECT: include `domain`, populate `ObjectWithMetadata::domain`

---

### Phase 7 — KMS: OPA input construction

**Step 13** — `OpaInput` struct (new module, e.g. `crate/server/src/core/opa/input.rs`):

```rust
#[derive(Serialize)]
pub struct OpaInput {
    pub user: String,           // JWT `email` (else `sub`), TLS CN, or API-token id
    pub user_domain: String,    // from the `as_rid` claim (`as_domain` alias), or ""
    pub roles: Vec<String>,     // from claims.authorization.roles, or []
    pub operation: String,      // lowercase snake_case KMIP operation name
    pub object_uid: String,
    pub object_domain: String,  // from ObjectWithMetadata.domain
    pub is_owner: bool,
}
```

The per-request roles and domain travel from the route handler to the permission layer in a `tokio::task_local!` (`OPA_USER_CONTEXT`), not in a `thread_local!`, because a task migrates between OS threads at every `.await`.

**Step 14** — `build_opa_input()` in the permission layer (`retrieve_object_utils.rs`):

- JWT present: extract `claims.authorization.roles` → `Vec<String>` and the `as_rid` claim → `String`
- JWT absent (mTLS/API-token): `roles = vec![]`, `user_domain = ""`
- Object-less ops (Create, Locate, etc.): `object_domain = user_domain`
- Object-bearing ops: `object_domain = owm.domain()`
- `is_super_admin` is not part of the input (SA3): the JWT `SuperAdmin` role is the only super-admin the policy knows

**Step 15** — Object creation path:

When `Create` is dispatched, `user_domain` is available from the task-local OPA user context.
`create.rs` stamps it on the new object. The other creation operations (for example `CreateKeyPair`, `Import`, `Certify`, `DeriveKey` and `ReKey`) do not stamp it yet and store `domain = ''`.

---

### Phase 8 — KMS: OPA client + configuration

**Step 16** — New types:

```rust
pub enum OpaMode { Disabled, Exclusive, Enforcing }

pub struct OpaParams {
    pub url: String,    // e.g. "http://localhost:8181"
    pub mode: OpaMode,
}
```

**Step 17** — `OpaClient` (reqwest, fail-closed):

```rust
impl OpaClient {
    /// Returns Ok(true) if OPA allows, Ok(false) if denied, Err if unreachable.
    /// Callers treat Err as deny (fail-closed).
    pub async fn query(&self, input: &OpaInput) -> Result<bool, OpaError>;
}
```

**Step 18** — Extend `ServerParams` and KMS struct:

- `server_params.rs`: `pub opa_params: Option<OpaParams>`
- `kms/mod.rs`: `pub(crate) opa_client: Option<Arc<OpaClient>>`

**Step 19** — `clap_config.rs`:

```text
--opa-url   <URL>   OPA sidecar base URL (enables OPA integration)
--opa-mode  <MODE>  "exclusive" or "enforcing" [default: "disabled"]
```

**Step 20** — `crate/server/src/core/retrieve_object_utils.rs`

In `user_has_permission()`, condensed (the real function also logs every denial on the `audit` target through `opa_decision()`):

```rust
// Disabled — only the native KMS permission logic below runs.

// Exclusive — OPA alone decides; the native logic is skipped:
//     return Ok(opa_decision(opa_client, mode, user, owm, *operation_type).await);

// Enforcing — OPA decides, except for native Crypto Officers acting on non-HSM objects
// (activated, or listed in `crypto_officer.users`), which skip OPA:
let is_native_co = !ObjectHandle::from(object_id).is_hsm()
    && (kms.is_crypto_officer(user).await?
        || kms.params.crypto_officer.users.iter().any(|u| u == user.as_str()));
if !is_native_co {
    // fail-closed: an error or a timeout counts as a denial
    if !opa_decision(opa_client, mode, user, owm, *operation_type).await {
        return Ok(false);
    }
    // An OPA allow is final for non-HSM objects: no ownership / DB grant check
    if !is_hsm { return Ok(true); }
    // HSM-backed objects fall through to the HSM admin + DB grant checks
}

// Native KMS permission logic: owner, then the Crypto Officer bypass (non-HSM objects only,
// logged as CRYPTO_OFFICER_ACCESS), then HSM admin, then the per-operation grants in the database.
```

---

## Verification

Run the commands from the root of the corresponding repository. The Rego policy tests and the OPA integration run with `mise run test:interop:opa-rbac --variant non-fips`.

```bash
# 1. Auth server tests (in the Authentication Verifier repository, `authentication/` submodule here)
cargo test --workspace

# 2. KMS tests
cargo test-non-fips

# 3. OPA smoke test — should return {"result":true}
docker compose up -d opa
curl -s -X POST http://localhost:8181/v1/data/kms/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "user": "alice@acme.com",
      "user_domain": "acme.com",
      "roles": ["CryptoOfficer"],
      "operation": "create",
      "object_uid": "*",
      "object_domain": "acme.com",
      "is_owner": false
    }
  }'

# 4. Same with empty roles — should return {"result":false}
curl -s -X POST http://localhost:8181/v1/data/kms/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "user": "anon",
      "user_domain": "",
      "roles": [],
      "operation": "create",
      "object_uid": "*",
      "object_domain": "",
      "is_owner": false
    }
  }'

# 5. SuperAdmin role (cross-domain) — should return {"result":true}
curl -s -X POST http://localhost:8181/v1/data/kms/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "user": "root@globex.com",
      "user_domain": "globex.com",
      "roles": ["SuperAdmin"],
      "operation": "destroy",
      "object_uid": "key-123",
      "object_domain": "acme.com",
      "is_owner": false
    }
  }'

# 6. Lint
cargo clippy-all   # KMS
cargo clippy --workspace --all-targets -- -D warnings   # auth server
```

---

## Scope exclusions

- **Admin realm**: the `_` admin realm does not participate in KMS RBAC. Admins manage realms/users; they are not KMS crypto operators.
- **Redis-findex backend and HSM store**: the domain is not persisted (every object reads back with `domain = ''`), so under an active OPA mode only the owner and the `SuperAdmin` role match; the server logs a warning at startup when Redis-Findex is combined with an OPA mode.
- **Wizard / TOML templates**: OPA is configured with the `--opa-url` / `--opa-mode` flags, the `KMS_OPA_URL` / `KMS_OPA_MODE` environment variables, or the `[opa]` table of `kms.toml` (see `crate/server/kms_template.toml`); the configuration wizard does not prompt for it and `resources/kms.toml` has no OPA key.
- **WASM bindings**: client-side only, no OPA involvement.
- **`privileged_users`**: this deprecated, hidden option is not consulted by the OPA code path. When `[roles] crypto_officer_users` is unset, the listed users are promoted to Crypto Officers at startup (with a warning), and native Crypto Officers keep the `Create` right without OPA and skip OPA on non-HSM objects in `enforcing` mode (see [`documentation/docs/configuration/authorization/index.md`](documentation/docs/configuration/authorization/index.md)).
