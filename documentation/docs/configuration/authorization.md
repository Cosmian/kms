The authorization system in the Cosmian Key Management Service (KMS) operates based on two fundamental principles:

1. **Ownership:** Every cryptographic object has an assigned owner. The ownership is established when an object is
   created using any of the following KMIP operations: `Create`, `CreateKeyPair`, or `Import`. As an owner, a user holds
   the privilege to carry out all supported KMIP operations on their objects.

2. **Access rights delegation:** owners can grant access rights, allowing one or more users to perform certain KMIP
   operations on an object. When granted such rights, a user can invoke the corresponding KMIP operation on the KMS for
   that particular object. The owner retains the authority to withdraw these access rights at any given time.

## Delegable KMIP operations

Owners can delegate the following KMIP operations to other users via the `grant` and `revoke` endpoints (or the CLI commands `ckms access-rights grant` / `ckms access-rights revoke`):

| Operation          | Description                                                     |
| ------------------ | --------------------------------------------------------------- |
| `create`           | Create new cryptographic objects (symmetric keys, key pairs, …) |
| `certify`          | Issue or renew X.509 certificates                               |
| `decrypt`          | Decrypt ciphertext using a managed key                          |
| `derive_key`       | Derive a new key from an existing key                           |
| `destroy`          | Permanently destroy an object                                   |
| `encrypt`          | Encrypt plaintext using a managed key                           |
| `export`           | Export an object (key material + metadata) from the KMS         |
| `get`              | Retrieve an object — **this is a super-privilege** (see below)  |
| `get_attributes`   | Read the KMIP attributes of an object                           |
| `hash`             | Compute a cryptographic hash                                    |
| `import`           | Import an external object into the KMS                          |
| `locate`           | Search for objects matching given attributes                    |
| `mac`              | Compute a Message Authentication Code                           |
| `revoke`           | Revoke (deactivate) an object                                   |
| `rekey`            | Re-key an existing symmetric key                                |
| `sign`             | Generate a digital signature                                    |
| `signature_verify` | Verify a digital signature                                      |
| `validate`         | Validate a certificate chain                                    |

Multiple operations can be granted or revoked in a single call. For example, using the CLI:

```bash
# Grant encrypt and decrypt to user "alice"
ckms access-rights grant alice -i <object-uid> encrypt decrypt

# Revoke the get privilege from user "bob"
ckms access-rights revoke bob -i <object-uid> get
```

## The `Get` super-privilege

The `Get` operation has a special role in the permission model: **it acts as a super-privilege that implies every other
object-level operation**.

When checking whether a user is authorized to perform a given operation on an object, the KMS evaluates the following
rules in order:

1. **Owner check** — if the requesting user is the owner of the object, access is always granted.
2. **Explicit permission** — if the user has been explicitly granted the requested operation (e.g. `encrypt`), access is
   granted.
3. **`Get` fallback** — if the user holds the `Get` permission on the object, access is granted **regardless of the
   specific operation requested**.

In other words, granting `Get` to a user on an object is equivalent to granting that user `encrypt`, `decrypt`,
`export`, `sign`, `derive_key`, and every other object-level operation — except lifecycle operations (`revoke`,
`destroy`) which still require their own explicit grant.

This design allows owners to share full read/use access to an object with a single permission, without individually
enumerating every operation.

!!! warning Security implication
    Because `Get` implies all other operation-level permissions, it should be granted with care.
    If you only need a user to encrypt data with a key, grant `encrypt` — not `get`.

### Practical example

| Granted permissions  | Can the user `encrypt`? | Can the user `export`? | Can the user `destroy`? |
| -------------------- | :---------------------: | :--------------------: | :---------------------: |
| `encrypt`            |           Yes           |           No           |           No            |
| `get`                |           Yes           |          Yes           |           No            |
| `encrypt`, `destroy` |           Yes           |           No           |           Yes           |
| `get`, `destroy`     |           Yes           |          Yes           |           Yes           |

!!! note
    The `destroy` and `revoke` operations are **never** implied by `get`. They must always be granted explicitly
    because they are irreversible lifecycle transitions.

## Special handling of the `Create` permission

The `Create` operation is not bound to a specific object — it controls whether a user is allowed to create *new* objects
in the KMS. Internally it is stored against the wildcard object identifier `*`.

- When granting or revoking `create`, no object UID is required.
- `Create` can be combined with object-level operations in the same request; the server will separate and process them
  accordingly.

## Privileged users

By default, all users are allowed to create or import objects in the KMS.

However, when the KMS server is configured with a list of privileged users, object creation rights are restricted as follows:

- Privileged users can create or import objects and are authorized to grant or revoke object creation permissions for other users.
- Regular users cannot create or import objects unless they have explicitly been granted permission by a privileged user.
- Regular users cannot grant or revoke creation permissions for others.
- Privileged users cannot revoke object creation permissions from other privileged users.

## The wildcard user `*`

!!! important "The Wildcard User: *"
    In addition to regular users, a special user called `*` (the wildcard user) can be used to grant access rights on
    objects to **all** users. When a permission is granted to `*`, every authenticated user benefits from that permission
    on the targeted object. Individual per-user grants are merged with the wildcard grants when evaluating access.

## HSM keys and authorization

Keys stored in an HSM are physically located in the HSM hardware, not in the KMS database.
However, their **authorization model is identical to that of regular KMS keys**: ownership and
access rights are still tracked by the KMS, and all the rules described on this page apply.

| Aspect                        | KMS keys                 | HSM keys                          |
| ----------------------------- | ------------------------ | --------------------------------- |
| Key material stored in        | KMS database (encrypted) | HSM hardware                      |
| Authorizations managed by     | KMS                      | KMS (same ownership + ACL model)  |
| Owner                         | Creating user            | HSM admin at creation time        |
| `grant` / `revoke` supported  | Yes                      | Yes — same REST API               |
| `Get` super-privilege applies | Yes                      | Yes                               |

The one HSM-specific restriction is **creation and destruction**: only users listed in the server's
`hsm_admin` configuration (or granted the `Create` / `Destroy` operation by an HSM admin) may create
or destroy objects directly in the HSM. All other operations (`Encrypt`, `Decrypt`, `Get`, etc.) follow
the standard KMS access rights model and can be delegated to any authenticated user via `grant`.

See the [HSM operations](../hsm_support/hsm_operations.md) page for details on HSM admin configuration.

## Authentication vs. authorization

It is important to distinguish authentication from authorization:

- **Authentication** determines *who* the user is. The KMS supports TLS client certificates, JWT tokens, and API tokens.
  See the [Authentication](authentication.md) page for details on how to configure these methods and how user identities
  are established.
- **Authorization** determines *what* an authenticated user is allowed to do with a given cryptographic object. This is
  the permission model described on this page.

!!! tip
    An **API token** (used for authentication) is not the same thing as a **symmetric key** stored in the KMS.
    The API token proves the user's identity; the symmetric key is a cryptographic object the user may or may not
    have permission to use.

## Typical workflow: per-user keys with limited permissions

!!! info "Permissions are managed at runtime, not in `kms.toml`"
    The `kms.toml` configuration file controls **server-level** settings only (authentication methods, database backend,
    TLS, privileged users, etc.). It does **not** contain any user-to-key permission mapping.
    Per-object access rights are managed dynamically at runtime through the REST API (`/access/grant`, `/access/revoke`)
    or the CLI (`ckms access-rights grant` / `ckms access-rights revoke`).
    The only authorization-related setting in `kms.toml` is `privileged_users`, which restricts who can create or import
    new objects (see [Privileged users](#privileged-users) above).

A common deployment pattern is to have an administrator create one symmetric key per user and grant only the
operations each user needs (e.g. `encrypt` and `decrypt`).

### Step 1 — Create the key (as admin/owner)

```bash
# The admin creates a 256-bit AES key and tags it for easy lookup
ckms sym keys create --algorithm aes --number-of-bits 256 --tag user-alice-key
```

The command returns the key's unique identifier, for example `a]b2c3d4-...`.

### Step 2 — Grant limited permissions

```bash
# Grant only encrypt and decrypt to alice (identified by her authenticated username)
ckms access-rights grant alice@example.com -i a]b2c3d4-... encrypt decrypt
```

Alice can now encrypt and decrypt using this key, but she **cannot** export it, destroy it, or perform any other
operation on it.

### Step 3 — Alice uses the key

Alice authenticates to the KMS (via her client certificate, JWT token, or API token) and calls the encrypt/decrypt
endpoints referencing the key UID. The server verifies she holds the `encrypt` / `decrypt` permission before
proceeding.

### Step 4 — Revoke access (if needed)

```bash
ckms access-rights revoke alice@example.com -i a]b2c3d4-... encrypt decrypt
```

!!! note
    Do **not** grant `get` if you only want to allow encrypt/decrypt — `get` is a super-privilege that implies all
    object-level operations (see above).

## Access management endpoints

The KMS exposes the following REST endpoints to manage access rights:

| Method | Endpoint                   | Description                                               |
| ------ | -------------------------- | --------------------------------------------------------- |
| POST   | `/access/grant`            | Grant operations on an object to a user                   |
| POST   | `/access/revoke`           | Revoke operations on an object from a user                |
| GET    | `/access/list/{object_id}` | List all access rights granted on an object (owner only)  |
| GET    | `/access/owned`            | List all objects owned by the authenticated user          |
| GET    | `/access/obtained`         | List all access rights obtained by the authenticated user |
| GET    | `/access/create`           | Check whether the authenticated user can create objects   |
| GET    | `/access/privileged`       | Check whether the authenticated user is privileged        |

## Authorization rules summary

| Scenario                                                | Access granted? |
| ------------------------------------------------------- | :-------------: |
| User is the object owner                                |     Always      |
| User has the exact requested operation granted          |       Yes       |
| User has `Get` granted (any operation except lifecycle) |       Yes       |
| User holds a role that grants the operation             |       Yes       |
| User has no matching permission                         |     Denied      |
| User tries to grant/revoke their own permissions        |     Denied      |
| Non-owner tries to grant permissions                    |     Denied      |

## Role-Based Access Control (RBAC)

In addition to per-user, per-object direct grants, the KMS supports **NIST Core RBAC** (INCITS 359-2012). RBAC allows
administrators to define **roles** — named bundles of permissions — and assign them to users. Permissions granted through
roles are **merged** with direct grants: a user's effective permission set is the union of their direct grants and all
role-based grants.

!!! note "Backward compatible"
    RBAC is fully additive and opt-in. Existing deployments that do not use roles continue to work exactly as before.
    When RBAC tables are empty, the permission model is identical to the pre-RBAC behavior.

### Concepts

| Concept            | Description                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------- |
| **Role**           | A named bundle of permissions (e.g. "operator", "crypto-user"). Identified by a unique slug ID.      |
| **Permission**     | A (role, object_id, operations) triple. `object_id` can be `*` (wildcard) to apply to all objects.   |
| **User assignment**| A (user, role) mapping — the user inherits all permissions of the role.                              |
| **Built-in role**  | A role seeded automatically at server startup. Cannot be deleted, but its permissions can be modified.|

### Built-in roles

The KMS ships with five built-in roles that are automatically created on first startup:

| Role ID         | Name          | Default permissions (on wildcard `*`)                                               |
| --------------- | ------------- | ----------------------------------------------------------------------------------- |
| `admin`         | Administrator | All KMIP operations                                                                 |
| `operator`      | Operator      | `create`, `import`, `certify`, `rekey`, `destroy`, `revoke`, `locate`, `get_attributes` |
| `crypto-user`   | Crypto User   | `encrypt`, `decrypt`, `sign`, `signature_verify`, `mac`, `hash`, `derive_key`, `locate`, `get_attributes` |
| `auditor`       | Auditor       | `get`, `get_attributes`, `locate`                                                   |
| `key-custodian` | Key Custodian | `export`, `import`, `get`, `get_attributes`, `locate`                               |

Built-in roles cannot be deleted, but administrators can modify their permissions using the
`add-permission` and `remove-permission` commands.

### Effective permission resolution

When a user requests an operation on an object, the KMS evaluates permissions in the following order:

1. **Owner check** — if the user owns the object, access is always granted.
2. **Direct grants** — if the user has been explicitly granted the operation (via `/access/grant`), access is granted.
3. **`Get` fallback (direct)** — if the user holds a direct `Get` grant, access is granted for any non-lifecycle operation.
4. **Role-based grants** — the KMS collects all operations granted to the user via their assigned roles (both object-specific and wildcard). If the requested operation is in this set, access is granted.
5. **`Get` fallback (role)** — if any role grants `Get`, access is granted for any non-lifecycle operation.

The result is a **union** of all permission sources — RBAC never restricts access that would otherwise be available through direct grants.

### Managing roles via CLI

```bash
# ── Role management ──────────────────────────────────────────────────────
ckms roles create my-role --name "My Custom Role" --description "A custom role"
ckms roles list
ckms roles get my-role
ckms roles delete my-role

# ── Permission management ────────────────────────────────────────────────
# Grant encrypt and decrypt on all objects
ckms roles add-permission my-role --operations encrypt decrypt --object-id '*'

# Grant sign on a specific key
ckms roles add-permission my-role --operations sign --object-id a1b2c3d4-...

# Remove encrypt from the role
ckms roles remove-permission my-role --operations encrypt --object-id '*'

# List all permissions of a role
ckms roles list-permissions my-role

# ── User assignment ──────────────────────────────────────────────────────
ckms roles assign my-role --users alice@example.com bob@example.com
ckms roles revoke my-role --user alice@example.com
ckms roles members my-role
```

### Managing roles via REST API

| Method | Endpoint                                          | Description                                      |
| ------ | ------------------------------------------------- | ------------------------------------------------ |
| POST   | `/roles`                                          | Create a new role                                |
| GET    | `/roles`                                          | List all roles                                   |
| GET    | `/roles/{role_id}`                                | Get a role by ID                                 |
| PUT    | `/roles/{role_id}`                                | Update a role's name and description             |
| DELETE | `/roles/{role_id}`                                | Delete a role (cascades permissions and users)   |
| POST   | `/roles/{role_id}/permissions`                    | Add permissions to a role                        |
| DELETE | `/roles/{role_id}/permissions`                    | Remove permissions from a role                   |
| GET    | `/roles/{role_id}/permissions`                    | List permissions of a role                       |
| POST   | `/roles/{role_id}/users`                          | Assign a role to users                           |
| DELETE | `/roles/{role_id}/users/{user_id}`                | Revoke a role from a user                        |
| GET    | `/roles/{role_id}/users`                          | List users assigned to a role                    |
| GET    | `/users/{user_id}/roles`                          | List roles assigned to a user                    |
| GET    | `/users/{user_id}/effective-permissions/{obj_id}` | Get effective permissions for a user on an object|

### Typical RBAC workflow

#### Step 1 — Create a custom role (or use a built-in role)

```bash
ckms roles create data-processor --name "Data Processor" --description "Can encrypt and decrypt data"
```

#### Step 2 — Add permissions

```bash
ckms roles add-permission data-processor --operations encrypt decrypt --object-id '*'
```

#### Step 3 — Assign users

```bash
ckms roles assign data-processor --users alice@example.com bob@example.com
```

Now Alice and Bob can encrypt and decrypt using **any** key in the KMS, without the key owner needing to grant
individual access to each user.

#### Step 4 — Inspect effective permissions

```bash
# Check what Alice can do on a specific key
curl -s http://localhost:9998/users/alice@example.com/effective-permissions/a1b2c3d4-...
```

### Role Hierarchy (Hierarchical RBAC)

The KMS supports **NIST Hierarchical RBAC** (General Hierarchy) — senior roles automatically inherit all permissions of
their junior roles. This eliminates the need to duplicate permissions across related roles. The hierarchy forms a
directed acyclic graph (DAG): a role can have multiple seniors and multiple juniors, but cycles are forbidden.

#### Default hierarchy

The following hierarchy is seeded automatically on server startup:

```
admin
  ├── operator
  │     └── crypto-user
  └── key-custodian

auditor (standalone — no inheritance)
```

This means:

- **operator** inherits all `crypto-user` permissions (encrypt, decrypt, sign, etc.) in addition to its own management operations.
- **admin** inherits all `operator` and `key-custodian` permissions, giving it full coverage.
- **auditor** is standalone — it does not inherit from any role, and no role inherits from it.

Administrators can modify the default hierarchy (add or remove edges) at any time.

#### Permission inheritance

```
effective_role_permissions(role) =
    direct_permissions(role)
  ∪ ∪{ effective_role_permissions(junior) | junior ∈ juniors(role) }
```

Inheritance is **transitive**: if A → B → C, then A inherits permissions from both B and C.

#### Managing hierarchy via CLI

```bash
# Add a junior role (operator inherits crypto-user)
ckms roles add-junior operator --junior crypto-user

# Remove a hierarchy edge
ckms roles remove-junior operator --junior crypto-user

# List direct juniors of a role
ckms roles juniors admin

# View the full hierarchy tree (from a specific root or all roots)
ckms roles hierarchy admin
```

#### Managing hierarchy via REST API

| Method | Endpoint                                  | Description                                            |
| ------ | ----------------------------------------- | ------------------------------------------------------ |
| POST   | `/roles/{senior_id}/juniors/{junior_id}`  | Add hierarchy edge (senior inherits junior)            |
| DELETE | `/roles/{senior_id}/juniors/{junior_id}`  | Remove hierarchy edge                                  |
| GET    | `/roles/{role_id}/juniors`                | List direct junior roles                               |
| GET    | `/roles/{role_id}/seniors`                | List direct senior roles                               |
| GET    | `/roles/{role_id}/hierarchy`              | Get full hierarchy tree from this role downward         |
| GET    | `/roles-hierarchy`                        | List all hierarchy edges in the system                 |

#### Cycle detection

The KMS prevents cycles in the hierarchy. When adding an edge (senior → junior), a BFS traversal checks whether
the proposed senior can be reached from itself by following existing edges upward. If so, the insertion is rejected
with an error. Self-loops (a role as its own junior) are also rejected.

#### Web UI

The Web UI provides a **View Hierarchy** page that shows the full role hierarchy as an interactive tree, with the
ability to remove edges directly. The **Add Junior Role** page provides a form to create new hierarchy edges.

### RBAC Enforcement Configuration

The RBAC enforcement behavior can be fine-tuned via the `[rbac]` section in `kms.toml`. All settings default to
backward-compatible values — existing deployments are not affected unless these options are explicitly enabled.

```toml
[rbac]
enabled = true
bootstrap_admins = ["alice@corp.com"]

# When true, Get only grants Get — it does not imply encrypt/decrypt/sign/etc.
strict_get_privilege = false   # default: false (backward compatible)

# Controls how RBAC permissions interact with direct grants.
# "additive" (default): effective = owner ∪ direct_grants ∪ role_grants
# "restrictive": effective = (direct ∪ role) ∩ role_ceiling (roles define max permissions)
enforcement_mode = "additive"

# When true, only admin/operator roles (or object owners) can call grant/revoke.
restrict_grant_to_roles = false
```

#### Strict `Get` privilege

By default, the `Get` permission acts as a **super-privilege** that implies all non-lifecycle operations (see
[The `Get` super-privilege](#the-get-super-privilege)). When `strict_get_privilege = true`, the `Get` operation
grants only the `Get` operation itself. Users must be explicitly granted each operation they need.

This aligns with the FIPS 140-3 principle of least privilege and is recommended for regulated deployments.

| `strict_get_privilege` | `Get` grants...                                                |
| :--------------------: | -------------------------------------------------------------- |
|       `false`          | All non-lifecycle operations (backward compatible behavior)    |
|       `true`           | Only the `Get` operation itself                                |

#### Enforcement mode

The enforcement mode controls how RBAC permissions interact with direct per-user grants:

- **Additive** (default): `effective = owner ∪ direct_grants ∪ role_grants`. RBAC never restricts access that
  would otherwise be available through direct grants. This is fully backward compatible.

- **Restrictive**: `effective = (direct_grants ∪ role_grants) ∩ role_ceiling`. Roles define the **maximum** permission
  set for a user. Direct grants that exceed what the user's roles allow are ignored. Owners always have full access
  regardless of mode. If a user has no roles assigned, the system falls back to direct grants only (backward compat).

| Mode          | Direct grant for `Destroy` + role only grants `Encrypt` | Result           |
| ------------- | -------------------------------------------------------- | ---------------- |
| `additive`    | User can `Destroy` **and** `Encrypt`                    | Union            |
| `restrictive` | User can only `Encrypt`                                 | Capped at role   |

#### Role-based grant/revoke restrictions

When `restrict_grant_to_roles = true`, only users with the **admin** or **operator** built-in role (or the object
owner) can call `grant_access()` / `revoke_access()`. This prevents non-admin users who happen to have direct
grants from further delegating permissions.

When `restrict_grant_to_roles = false` (default), only object ownership is required to grant/revoke access
(the existing behavior).
