---
title: "ADR-2026-07-26: SPIRE/SPIFFE Integration via Vault-Compatible API"
status: "Accepted"
date: "2026-07-26"
authors: "Architecture Team"
tags: ["architecture", "spiffe", "spire", "vault", "kms", "auth-verifier", "mercedes-benz-rfi"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-07-26: SPIRE/SPIFFE Integration via Vault-Compatible API

## Status

Accepted

## Context

The Mercedes-Benz SPEYER initiative (Zero Trust M2M RFI, June 2026) requires SPIRE to use an
enterprise KMS as both UpstreamAuthority (PKI engine: sign intermediate CA certificates) and
KeyManager (Transit engine: key-as-a-service, signing only — private keys never leave the backend).

SPIRE's two relevant plugins call the HashiCorp Vault HTTP API:

- `upstreamauthority "vault"`: POST `/<pki_mount>/root/sign-intermediate` with a PKCS#10 CSR
- `keymanager "hashicorp_vault"`: POST `/<transit>/keys/<name>`, GET, LIST, POST sign, DELETE

Both plugins first authenticate with one of four Vault auth methods (Token, Cert, AppRole,
Kubernetes), obtain an opaque `client_token`, then carry `X-Vault-Token: <token>` on all
subsequent requests.

The Cosmian stack has two servers:

- **auth-verifier**: Actix-web HTTPS, handles authentication, sessions, realm management
- **KMS**: Actix-web HTTPS, FIPS 140-3, KMIP 2.1, HSM/PKCS#11, existing signing and CA
  certificate issuance primitives

The decision covers where to implement Vault auth endpoints and Vault crypto endpoints.

## Decision

**Auth layer** → auth-verifier, new `/v1/auth/` Actix scope.
Implements: AppRole login + admin CRUD, Kubernetes service-account JWT login,
token lookup-self / renew-self / revoke-self.

**Crypto layer** → KMS, new `/v1/transit/` and `/v1/<pki_mount>/` Actix scopes.
Implements: transit key CRUD + sign, PKI sign-intermediate.

**Token validation**: on each transit/PKI request the KMS middleware calls
`GET /v1/auth/token/lookup-self` on auth-verifier with a 30-second in-memory cache.

**CLI**: `ckms vault approle` subcommands (create-role, get-role-id, generate-secret-id,
destroy-secret-id) in the KMS CLI for AppRole credential provisioning.

## Consequences

### Positive

- **POS-001** Clean separation of concerns — authentication in auth-verifier, cryptography
  in KMS. Each server evolves independently.
- **POS-002** Auth-verifier reuses its existing `JwksManager` for K8s JWT validation,
  `AdminAuth` middleware for AppRole provisioning, and multi-backend DB layer.
- **POS-003** KMS retains FIPS 140-3 compliance. All crypto operations (sign, certify) go
  through the existing KMIP core and HSM oracle stack.
- **POS-004** HSM/PKCS#11 backing satisfies RFI FR-2.6 ("private keys must never be
  persisted to disk") without additional work.
- **POS-005** PQC readiness (FR-2.14, NFR-11) — ML-DSA-65 mapped as a transit key type
  in non-FIPS mode; algorithm policy changes take effect at next SPIRE key rotation.
- **POS-006** Multiple SPIRE servers sharing one backend are handled by SPIRE's own
  `{SERVER-ID}-{UUID}-{SPIRE-KEY-ID}` transit key naming convention; no KMS changes needed.
- **POS-007** Drop-in replacement: SPIRE operator changes only `vault_addr` in SPIRE config;
  the auth method and plugin config are otherwise identical to a real Vault deployment.

### Negative

- **NEG-001** Cross-service dependency — KMS requires auth-verifier reachability for token
  validation. Mitigated by 30-second cache; cache miss on auth-verifier outage will fail
  new transit requests until auth-verifier recovers.
- **NEG-002** Two services must be co-deployed and co-configured. Operators must manage
  two TLS endpoints and two database schemas.
- **NEG-003** 30-second cache staleness window — a revoked token remains valid at the KMS
  for up to 30 seconds. Acceptable for the beta; production hardening may reduce this or
  add a revocation push notification.

## Alternatives Considered

### Alternative A — All auth and crypto in the KMS

- Implement both `/v1/auth/` and `/v1/transit/` + `/v1/pki/` in the KMS.
- **Rejected**: Mixes token issuance into the cryptographic server. KMS access model is
  KMIP-centric; a parallel Vault token model creates two competing auth subsystems. Auth
  logic is better co-located in auth-verifier, which already owns realm management, JWKS
  validation, and session lifecycle.

### Alternative B — All in auth-verifier (transit as HTTP proxy to KMS)

- auth-verifier serves transit/PKI endpoints and proxies crypto calls to KMS.
- **Rejected**: Every transit call would traverse two network hops. auth-verifier has no
  KMIP client today, adding significant new scope. The proxy adds latency that conflicts
  with NFR-2 (certificate issuance < 500ms, DPoP validation < 5ms).

### Alternative C — Dedicated Vault adapter shim microservice

- A third service translates Vault HTTP API to Cosmian KMIP API.
- **Rejected**: Adds a third deployment unit with no reuse of existing infrastructure.
  Over-engineered for beta timeline; increases operational surface area.

## Implementation Notes

### New DB tables (auth-verifier)

```sql
-- Vault tokens
vault_tokens(token_hash BLOB PK, entity TEXT, policies TEXT,
             expiry TIMESTAMP, renewable BOOL, lease_duration_secs INT, created_at TIMESTAMP)

-- AppRole
vault_approle_roles(name TEXT PK, role_id TEXT UNIQUE, secret_id_ttl_secs INT,
                    token_ttl_secs INT, bind_secret_id BOOL, token_policies TEXT)
vault_secret_ids(accessor TEXT PK, secret_id_hash BLOB, role_name TEXT FK,
                 expiry TIMESTAMP, num_uses_remaining INT)

-- Kubernetes
vault_k8s_roles(name TEXT PK, jwks_url TEXT, bound_sa_names TEXT,
                bound_sa_namespaces TEXT, token_ttl_secs INT)
```

### Token format

`hvs.<base64url(32 random bytes)>`, stored as `SHA-256(token)` in the database.

### KMS config for vault API (beta)

```toml
vault_api_enabled = true
vault_auth_verifier_url = "https://auth.example.com"
vault_transit_mount = "transit"
vault_pki_mount = "pki"
vault_pki_ca_key_label = "spire-intermediate-ca"
vault_token_cache_ttl_secs = 30
```

Multi-mount segmentation (FR-2.18, PKI-5) is deferred post-beta; the single-mount config
is forward-compatible — upgrading to a HashMap requires only a config-file change.

### Transit key type mapping

| Vault type | KMS algorithm | Feature gate |
|------------|---------------|--------------|
| `ecdsa-p256` | EC P-256 | FIPS + non-FIPS (default) |
| `ecdsa-p384` | EC P-384 | FIPS + non-FIPS |
| `rsa-2048` | RSA-2048 | FIPS + non-FIPS |
| `rsa-4096` | RSA-4096 | FIPS + non-FIPS |
| `ed25519` | EdDSA | `non-fips` only |
| `ml-dsa-65` | ML-DSA 65 | `non-fips` only |

### Signature output format

All transit sign responses: `vault:v1:<base64(raw_sig)>`. SPIRE strips this prefix.
ECDSA returns ASN.1 DER. The `exportable: false` invariant is enforced server-side
unconditionally, satisfying FR-2.15 regardless of client request body.

### PKI sign-intermediate validation

Requests with empty `uri_sans` are rejected with HTTP 400 — at least one SPIFFE URI SAN
is required per SPIRE plugin contract. Response de-duplication follows Vault ≥1.11: root
cert stripped from `ca_chain`; signed certificate stripped from `ca_chain` (already
present in `certificate`).
