The authorization system in the Cosmian Key Management Service (KMS) operates based on two fundamental principles:

1. **Ownership:** Every cryptographic object has an assigned owner. The ownership is established when an object is
   created using any of the following KMIP operations: `Create`, `CreateKeyPair`, or `Import`. As an owner, a user holds
   the privilege to carry out all supported KMIP operations on their objects.

2. **Access rights delegation:** owners can grant access rights, allowing one or more users to perform certain KMIP
   operations on an object. When granted such rights, a user can invoke the corresponding KMIP operation on the KMS for
   that particular object. The owner retains the authority to withdraw these access rights at any given time.

## Delegable KMIP operations

Owners can delegate the following KMIP operations to other users via the `grant` and `revoke` endpoints (or the CLI commands `cosmian kms access-rights grant` / `cosmian kms access-rights revoke`):

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
cosmian kms access-rights grant alice -i <object-uid> encrypt decrypt

# Revoke the get privilege from user "bob"
cosmian kms access-rights revoke bob -i <object-uid> get
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

!!! warning "Security implication"
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
    or the CLI (`cosmian kms access-rights grant` / `cosmian kms access-rights revoke`).
    The only authorization-related setting in `kms.toml` is `privileged_users`, which restricts who can create or import
    new objects (see [Privileged users](#privileged-users) above).

A common deployment pattern is to have an administrator create one symmetric key per user and grant only the
operations each user needs (e.g. `encrypt` and `decrypt`).

### Step 1 — Create the key (as admin/owner)

```bash
# The admin creates a 256-bit AES key and tags it for easy lookup
cosmian kms sym keys create --algorithm aes --number-of-bits 256 --tag user-alice-key
```

The command returns the key's unique identifier, for example `a]b2c3d4-...`.

### Step 2 — Grant limited permissions

```bash
# Grant only encrypt and decrypt to alice (identified by her authenticated username)
cosmian kms access-rights grant alice@example.com -i a]b2c3d4-... encrypt decrypt
```

Alice can now encrypt and decrypt using this key, but she **cannot** export it, destroy it, or perform any other
operation on it.

### Step 3 — Alice uses the key

Alice authenticates to the KMS (via her client certificate, JWT token, or API token) and calls the encrypt/decrypt
endpoints referencing the key UID. The server verifies she holds the `encrypt` / `decrypt` permission before
proceeding.

### Step 4 — Revoke access (if needed)

```bash
cosmian kms access-rights revoke alice@example.com -i a]b2c3d4-... encrypt decrypt
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
| User has no matching permission                         |     Denied      |
| User tries to grant/revoke their own permissions        |     Denied      |
| Non-owner tries to grant permissions                    |     Denied      |
