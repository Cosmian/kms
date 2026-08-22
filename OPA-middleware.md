# OPA RBAC Middleware — Context and Implementation Plan

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
| 3 | `Enforcing` | OPA runs first; if true, KMS permission system also runs; both must allow |

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
    "as_domain": "acme.com"              ← private claim (RFC 7519 §4.3)

KMS receives request with JWT
  KMS extracts:
    sub       → input.user
    as_domain → input.user_domain
    roles     → input.roles[]

KMS calls OPA:
  POST /v1/data/kms/allow
  {
    "input": {
      "user":          "alice@acme.com",
      "user_domain":   "acme.com",
      "roles":         ["CryptoOfficer"],
      "operation":     "Create",
      "object_uid":    "*",
      "object_domain": "acme.com",
      "is_owner":      false
    }
  }

OPA evaluates kms.rego → {"result": true}

KMS applies mode logic:
  Exclusive:  allow = opa_result
  Enforcing:  allow = opa_result AND kms_result
```

Non-JWT auth (mTLS, API token): KMS sends `"roles": []` → all role-based rules are false → fail-closed.

---

### Domain model

`user_domain` comes from the `as_domain` JWT private claim — not inferred from the `sub` string.
This decouples username format from domain assignment entirely.

`object_domain` is stamped at object creation time from the creator's `user_domain` and stored
as a new `domain` column on the `objects` table. It is immutable after creation.

For object-less operations (e.g. `Create`): `object_domain = user_domain` at permission-check time.

Existing objects (before this feature) get `domain = ''`, which only `SuperAdmin` can access
via domain-scoped roles (the `same_domain` rule fails; owner rule still works).

---

### Key files

**Authentication server (`Cosmian/authentication`, branch `develop`):**

| File | Change |
|------|--------|
| `client/src/models/client_claims.rs` | New `AuthorizationClaims` struct (`roles`); `as_domain` in `AuthPrivateClaims` |
| `client/src/models/base.rs` | `roles: Vec<String>` and `domain: Option<String>` on `UserPass` |
| `server/src/session/jwt.rs` | `issue_token()` gains `roles` and `domain` params |
| `server/src/server/endpoints/client_endpoints.rs` | Login fetches userpass; passes roles+domain to token |
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
    "user":            "<JWT sub>",
    "user_domain":     "<as_domain claim, or '' for non-JWT>",
    "roles":           ["<role1>", ...],
    "is_super_admin":  false,
    "operation":       "<KMIP operation name>",
    "object_uid":      "<KMIP object UID, or '*' for object-less ops>",
    "object_domain":   "<objects.domain column, or user_domain for object-less ops>",
    "is_owner":        true
  }
}

| Field | Source | Default |
|-------|--------|---------|
| `user` | JWT `sub` / TLS CN / API-token id | — |
| `user_domain` | JWT `as_domain` private claim | `""` |
| `roles` | JWT `roles` public claim (RFC 9068) | `[]` |
| `is_super_admin` | `kms.is_super_admin(user).await?` (SA3) | `false` |
| `operation` | KMIP operation tag | — |
| `object_uid` | Target object UID | `"*"` for object-less ops |
| `object_domain` | `objects.domain` column | `user_domain` for object-less ops |
| `is_owner` | `user == owm.owner()` | `false` |
```

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
| E3 | `user_domain` source | Dedicated `as_domain` JWT private claim | Decouples username format from domain; `sub` may be email, CN, or UUID |
| OD1 | Object domain assignment | Stamped at creation from `user_domain`, immutable | Auditable, consistent; mirrors how `owner` is assigned |
| OB1 | Object domain storage | New `domain` column on `objects` table | First-class operational field; consistent with `owner` and `state` |
| D-B | `as_domain` claim placement | `AuthPrivateClaims` with `rename = "as_domain"` | Private deployment claim (RFC 7519 §4.3); not an IANA-registered public claim |
| SA3 | Ceremony super-admin | Fully decoupled from OPA; operates only inside native KMS gate | Two systems are independent; OPA handles JWT roles, native KMS handles ceremony SA |

---

## Ceremony super-admin and OPA — separation of concerns

The KMS ceremony super-admin (Shamir split-key) and OPA RBAC are **fully independent**:

- `is_super_admin` is **not** included in the OPA input document.
- OPA has no visibility into the ceremony state.
- In Mode 1 (Disabled): ceremony super-admin operates as before (early return in native KMS check).
- In Mode 2 (Exclusive): ceremony has no effect — OPA is the sole decision maker.
- In Mode 3 (Enforcing): ceremony super-admin takes effect inside Gate 2 (native KMS), only after OPA has already allowed.

The JWT `SuperAdmin` role (assigned by auth admin) and the ceremony super-admin (Shamir activation) are distinct concepts with different trust anchors and different enforcement paths.

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

Add `domain` to `AuthPrivateClaims`:

```rust
/// Domain the subject belongs to, used for domain-scoped RBAC.
/// Private claim (RFC 7519 §4.3) — not an IANA-registered name.
#[serde(rename = "as_domain", skip_serializing_if = "Option::is_none")]
pub domain: Option<String>,
```

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

/// Domain the user belongs to (e.g. "acme.com").
/// Emitted as the `as_domain` JWT private claim.
pub domain: Option<String>,
```

---

### Phase 2 — Auth server: database layer (all 3 backends)

**Step 3** — Schema change in each backend:

```sql
-- Add to CREATE TABLE userpass:
roles  TEXT NOT NULL DEFAULT '[]',
domain TEXT
```

Migration queries (run at startup, check-then-ALTER pattern):

```sql
-- add-column-roles
ALTER TABLE userpass ADD COLUMN roles TEXT NOT NULL DEFAULT '[]';
-- add-column-domain
ALTER TABLE userpass ADD COLUMN domain TEXT;
```

**Step 4** — CRUD update in all 3 backends:

- `create_userpass`: INSERT includes `roles` (JSON-serialised), `domain`
- `get_userpass`: SELECT reads `roles` (deserialise → `Vec<String>`), `domain`
- `update_userpass`: UPDATE includes both
- `list_*`: SELECT includes both

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
    public_key_pem: Option<String>,
    roles: Vec<String>,          // NEW — from UserPass.roles
    domain: Option<String>,      // NEW — from UserPass.domain
    algorithm: Algorithm,
    encoding_key: EncodingKey,
    expiration_seconds: i64,
) -> Result<String, AuthError>
```

Inside: `claims.authorization.roles = Some(roles)` and `claims.private.domain = domain`.

**Step 6** — `server/src/server/endpoints/client_endpoints.rs`

In `login()`, after TOTP check, before `issue_token()`:

```rust
let userpass = database
    .get_userpass(&realm.id, &authenticated_client.username)
    .await?;
let (roles, domain) = userpass
    .map(|u| (u.roles, u.domain))
    .unwrap_or_default();
// Non-userpass schemes (mTLS) return None → roles=[], domain=None → N1 satisfied
```

---

### Phase 4 — Auth server: API surface

**Step 7** — `server/src/server/endpoints/realms_endpoints.rs`

No handler logic change needed — `roles` and `domain` are carried by the `UserPass` struct
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
domain:
  type: string
  nullable: true
  description: "Domain the user belongs to, emitted as as_domain JWT claim"
  example: "acme.com"
```

---

### Phase 5 — KMS: Rego policy update

**Step 9** — `test_data/opa/kms.rego`

- `input.role` → removed entirely
- All role checks: `input.role == "X"` → `input.roles[_] == "X"` (Rego existential)
- `reason := "no_role"`: check `count(input.roles) == 0; not input.is_owner`
- Header: document `input.roles` as array from JWT, `input.user_domain` from `as_domain`

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
    pub user: String,
    pub user_domain: String,    // from claims.private.domain (as_domain), or ""
    pub roles: Vec<String>,     // from claims.authorization.roles, or []
    pub is_super_admin: bool,   // SA3: from kms.is_super_admin(user)
    pub operation: String,
    pub object_uid: String,
    pub object_domain: String,  // from ObjectWithMetadata.domain
    pub is_owner: bool,
}
```

**Step 14** — `build_input()` in the permission layer:

- JWT present: extract `claims.authorization.roles` → `Vec<String>`, `claims.private.domain` → `String`
- JWT absent (mTLS/API-token): `roles = vec![]`, `user_domain = ""`
- Object-less ops (Create, Locate, etc.): `object_domain = user_domain`
- Object-bearing ops: `object_domain = owm.domain()`
- SA3: call `kms.is_super_admin(user).await?` → `is_super_admin: bool`

**Step 15** — Object creation path:

When `Create` is dispatched, `user_domain` is available from the request context.
Pass it into `database.create(uid, owner, object, attributes, tags, user_domain)`.

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
--opa-mode  <MODE>  "exclusive" or "enforcing" [default: "enforcing"]
```

**Step 20** — `crate/server/src/core/retrieve_object_utils.rs`

In `user_has_permission()` — SA3 integration:

```rust
// Mode 0 (Disabled) — existing flow unchanged:
//   line 225: if kms.is_super_admin(user).await? { return Ok(true); }
//   ... normal HSM + DB checks ...

// Mode 2/3 (Exclusive/Enforcing) — OPA is the sole gate:
if kms.opa_client.is_some() {
    // Skip the is_super_admin() early return — SA3 feeds it into OPA input instead
    let input = build_input(kms, user, owm, operation_type).await?;
    //   ↑ build_input calls kms.is_super_admin(user) → sets input.is_super_admin
    let opa_ok = kms.opa_client.as_ref().unwrap()
        .query(&input).await.unwrap_or(false); // fail-closed
    match kms.params.opa_mode {
        OpaMode::Exclusive => return Ok(opa_ok),
        OpaMode::Enforcing => {
            if !opa_ok { return Ok(false) }
            // fall through to HSM admin + DB grant checks
        }
        OpaMode::Disabled => unreachable!(),
    }
} else {
    // Mode 0 — existing super-admin bypass + normal logic
    if kms.is_super_admin(user).await? {
        warn!("SUPER_ADMIN_ACCESS: ...");
        return Ok(true);
    }
}
// ... HSM admin check, DB permission check ...
```

---

## Verification

```bash
# 1. Auth server tests
cd /Users/manu/Cosmian/github/authentication
cargo test --workspace

# 2. KMS tests
cd /Users/manu/Cosmian/core/cli_alt3/kms
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
      "is_super_admin": false,
      "operation": "Create",
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
      "is_super_admin": false,
      "operation": "Create",
      "object_uid": "*",
      "object_domain": "",
      "is_owner": false
    }
  }'

# 5. SA3 — ceremony super-admin with no JWT roles — should return {"result":true}
curl -s -X POST http://localhost:8181/v1/data/kms/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "user": "custodian@acme.com",
      "user_domain": "",
      "roles": [],
      "is_super_admin": true,
      "operation": "Destroy",
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
- **Redis-findex backend**: domain column follows the same OB1 pattern but is tracked as a separate task (Redis store has a different object representation).
- **Wizard / TOML templates**: `--opa-url` / `--opa-mode` are CLI flags only in this phase; wizard integration is deferred.
- **WASM bindings**: client-side only, no OPA involvement.
- **`privileged_users`**: this config field is not consulted in OPA modes 2 or 3. SuperAdmin role in OPA is the equivalent.
