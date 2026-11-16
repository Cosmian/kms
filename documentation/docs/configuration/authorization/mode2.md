# Mode 2 — Exclusive OPA (RBAC)

When the OPA server is configured with `opa_mode = "exclusive"`, OPA is the **sole
authorization decision maker** for the requests it is asked about. The native KMS permission system
(ownership, grants) is bypassed for them. Several operations are never sent to OPA and keep using the
native KMS permission system (see the note below the table).

```toml
# kms.toml — Mode 2
[opa]
opa_url  = "http://localhost:8181"
opa_mode = "exclusive"
```

| Environment variable | Example |
| -------------------- | ------- |
| `KMS_OPA_URL`        | `http://localhost:8181` |
| `KMS_OPA_MODE`       | `exclusive` |

!!! note "Operations that never reach OPA"
    In the current server, several operations are authorized from the native KMS ownership and grants only, and OPA is not queried for them. They include Locate, Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify, Revoke, Destroy and Rekey. A caller that the policy would allow but that has no native grant is refused (Encrypt and Revoke return `Item_Not_Found`), and a native grant is honored even where the policy would deny. Locate does not refuse anything: it returns only the objects the caller owns or holds a native grant on, whatever the policy says. An activated [Crypto Officer](key_ceremony.md) passes the native check on every non-HSM object, across domains, and `Locate` returns every matching object to it. Create, Get, GetAttributes, Activate and the other operations that the server routes through OPA (for example attribute changes, Check, Validate and DeriveKey) are decided by OPA. [Try RBAC with Keycloak and OPA](rbac-keycloak-opa-demo.md) shows Encrypt and Revoke; the other operations are listed from the server code and the demo does not exercise them.

---

## Prerequisites

- **JWT authentication required** — all users must authenticate via JWT issued by the
  Eviden Authentication Server. The JWT must contain the `roles` and `as_rid` claims
  (the legacy name `as_domain` is accepted as an alias; a bare `domain` claim is not read).
  A token without a domain claim carries no domain and is denied by every role-based rule.
- **Non-JWT auth is fail-closed** — mTLS and API token users receive `roles: []` in the
  OPA input, causing all role-based rules to evaluate to `false`.
- **Native KMS grants are ignored** — even if a user has explicit grants in the KMS
  database, they are not consulted for the operations OPA decides. The exception is the
  operations listed in the note above, which are authorized from the native grants only.

---

## Sequence diagram

```mermaid
sequenceDiagram
    actor Client
    participant AuthSrv as Authentication Server
    participant KMS as KMS Server
    participant OPA as OPA Server
    participant DB as KMS Database

    Client->>AuthSrv: POST /login (username + password + TOTP)
    AuthSrv-->>Client: JWT (email, roles, as_rid)

    Client->>KMS: KMIP request + Bearer JWT
    KMS->>KMS: Verify JWT signature via JWKS
    KMS->>KMS: Extract email (or sub), roles, as_rid

    KMS->>DB: retrieve_objects(uid_or_tags)
    DB-->>KMS: ObjectWithMetadata (owner, domain)

    KMS->>OPA: POST /v1/data/kms/allow
    Note right of KMS: {input: user, roles,<br/>user_domain, operation,<br/>object_uid, object_domain,<br/>is_owner}
    OPA->>OPA: Evaluate kms.rego
    OPA-->>KMS: {result: true/false}

    alt OPA allows
        KMS->>DB: Execute KMIP operation
        KMS-->>Client: KMIP response (success)
    else OPA denies or unreachable
        KMS-->>Client: Error: Access Denied
    end
```

---

## OPA decision flowchart

The Rego policy evaluates rules top-to-bottom. The first matching rule grants access:

```mermaid
flowchart TD
    Start([OPA receives input]) --> Owner{is_owner?}
    Owner -->|Yes| Allow([Allow])
    Owner -->|No| SA{SuperAdmin role?}
    SA -->|Yes| Allow
    SA -->|No| DA{DomainAdmin role?}
    DA -->|Yes, same domain| Allow
    DA -->|No| CO{CryptoOfficer role?}
    CO -->|Yes, same domain + valid op| Allow
    CO -->|No| AU{Auditor role?}
    AU -->|Yes, same domain + audit op| Allow
    AU -->|No| US{User role?}
    US -->|Yes, same domain + user op| Allow
    US -->|No| Deny([Deny])
```

---

## Fail-closed behaviour

```mermaid
flowchart LR
    KMS([KMS sends query]) --> OPA{OPA reachable?}
    OPA -->|Yes, result=true| Allow([Allow])
    OPA -->|Yes, result=false| Deny([Deny])
    OPA -->|Timeout / error / non-2xx| Deny
    OPA -->|Response parse failure| Deny
```

If OPA is configured but unreachable, **all requests are denied**. This is
intentional: a crashed sidecar does not degrade the KMS to open access.

---

## What is NOT evaluated in Mode 2

| Native KMS concept | Evaluated? | Reason |
| ------------------ | :--------: | ------ |
| Object ownership grants | No | OPA handles `is_owner` directly |
| Per-user operation grants | No | Replaced by role-based rules |
| `Get` super-privilege | No | OPA does not implement this shortcut |
| Privileged users (creation rights) | Yes, for `Create` | The default username and the `crypto_officer_users` keep the `Create` right without OPA being queried; OPA decides for everyone else |
| HSM admin bypass | No | OPA handles all HSM key decisions |
| Ceremony super-admin | No, for the operations OPA decides | The native KMS gate is not consulted for them. It still applies to `Locate` and to the operations of the note at the top of this page, where an activated Crypto Officer reaches every non-HSM object |

Apart from the `Create` shortcut of privileged users, the table describes the operations that OPA decides. For the operations in the note at the top of this page, ownership and per-user grants are the only check (for the cryptographic operations on non-HSM keys, a `Get` grant is also enough), plus the activated Crypto Officer bypass.

---

## Deploying the OPA sidecar

OPA has no authentication or TLS in its default configuration, and the KMS has no OPA-specific authentication to offer (no bearer token, no client certificate): anyone who can reach the OPA port can read the policy and query decisions, and anyone who can replace the policy or impersonate the endpoint decides who is authorized. Run OPA as a sidecar of the KMS, bound to the loopback interface, and use the same `http://127.0.0.1:8181` address in the KMS `opa_url`.

Minimal start:

```bash
opa run --server --addr 127.0.0.1:8181 kms.rego
```

Production (hot-reloadable via bundles):

```bash
opa run --server --addr 127.0.0.1:8181 \
  --set bundles.kms.service=policy-service \
  --set bundles.kms.resource=kms/bundle.tar.gz \
  --set services.policy-service.url=https://policy.example.com
```

The policy can be updated at runtime without restarting KMS or OPA.

!!! warning "Harden a production OPA"
    - Keep the OPA port off public and shared networks. If OPA runs on another host, put a TLS-terminating reverse proxy that authenticates the KMS in front of it and use an `https://` `opa_url`.
    - Pin the OPA image by digest rather than by a mutable tag such as `latest` or `edge`.
    - Serve the policy as a signed bundle and restrict who can publish it: the bundle is the authorization policy of the whole KMS.
    - Do not expose the `/v1/data/kms/reasons` debug endpoint or console decision logs to untrusted readers: they contain user identities and object identifiers.

---

## Debugging denied requests

Query the debug endpoint to see which rules matched:

```bash
curl -s -X POST http://localhost:8181/v1/data/kms/reasons \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": "alice@acme.com",
      "user_domain": "acme.com",
      "roles": ["CryptoOfficer"],
      "operation": "destroy",
      "object_uid": "key-123",
      "object_domain": "acme.com",
      "is_owner": false
    }
  }'
```

Response: `{"result": ["crypto_officer"]}` — the `CryptoOfficer` role allows `destroy`.

If the response contains `"denied"`, no rule matched.

---

## See also

- [Authorization overview](index.md) — role model, JWT claims, OPA input document
- [Mode 3 — Enforcing](mode3.md) — OPA stays authoritative; native Crypto Officers and HSM-backed objects also use the native KMS check
- [Try RBAC with Keycloak and OPA](rbac-keycloak-opa-demo.md) — run the roles end to end with a Keycloak, OPA and KMS Docker Compose stack
- Rego policy source: `test_data/opa/kms.rego`
