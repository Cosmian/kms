---
title: "ADR-2026-07-26: SPIRE/SPIFFE Integration via Vault-Compatible API (KMS Crypto Layer)"
status: "Accepted"
date: "2026-07-26"
authors: "Architecture Team"
tags: ["architecture", "spiffe", "spire", "vault", "kms", "mercedes-benz-rfi"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-07-26: SPIRE/SPIFFE Integration via Vault-Compatible API (KMS Crypto Layer)

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
Kubernetes) against a Vault-compatible auth endpoint, obtain an opaque `client_token`, then
carry `X-Vault-Token: <token>` on all subsequent requests to the crypto engines above.

The Cosmian stack splits this across two servers:

- **auth-verifier**: Actix-web HTTPS, handles authentication, sessions, realm management —
  owns the `/v1/auth/` scope (AppRole/Kubernetes login, token lookup/renew/revoke). See the
  auth-verifier repository's own ADR for that implementation:
  `authentication/server/documentation/adr/2026-07-26-vault-compatible-auth-api-for-spire.md`.
- **KMS**: Actix-web HTTPS, FIPS 140-3, KMIP 2.1, HSM/PKCS#11, existing signing and CA
  certificate issuance primitives — owns the crypto-facing `/v1/transit/` and
  `/v1/<pki_mount>/` scopes described by this ADR.

This ADR covers only the KMS side of that split: why the crypto engines live in the KMS
rather than in auth-verifier or a third component, and how they are implemented.

## Decision

**Crypto layer** → KMS, new `/v1/transit/` and `/v1/<pki_mount>/` Actix scopes.
Implements: transit key CRUD + sign, PKI sign-intermediate.

**Token validation**: on each transit/PKI request the KMS middleware calls
`GET /v1/auth/token/lookup-self` on auth-verifier (see the auth-verifier ADR referenced
above for the auth-verifier side of this contract) with a 30-second in-memory cache.

**CLI**: `ckms vault approle` subcommands (create-role, get-role-id, generate-secret-id,
destroy-secret-id) in the KMS CLI for AppRole credential provisioning against auth-verifier.

## Consequences

### Positive

- **POS-001** Clean separation of concerns — authentication in auth-verifier, cryptography
  in KMS. Each server evolves independently.
- **POS-002** KMS retains FIPS 140-3 compliance. All crypto operations (sign, certify) go
  through the existing KMIP core and HSM oracle stack.
- **POS-003** HSM/PKCS#11 backing satisfies RFI FR-2.6 ("private keys must never be
  persisted to disk") without additional work.
- **POS-004** PQC readiness (FR-2.14, NFR-11) — ML-DSA-65 mapped as a transit key type
  in non-FIPS mode; algorithm policy changes take effect at next SPIRE key rotation.
- **POS-005** Multiple SPIRE servers sharing one backend are handled by SPIRE's own
  `{SERVER-ID}-{UUID}-{SPIRE-KEY-ID}` transit key naming convention; no KMS changes needed.
- **POS-006** Drop-in replacement: SPIRE operator changes only `vault_addr` in SPIRE config;
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

### auth-verifier side

The `/v1/auth/` scope, its database schema (`vault_tokens`, `vault_approle_roles`,
`vault_secret_ids`, `vault_k8s_roles`), and the `hvs.<base64url(...)>` token format are
implemented and documented entirely in the auth-verifier repository — see
`authentication/server/documentation/adr/2026-07-26-vault-compatible-auth-api-for-spire.md`.
This ADR only depends on that contract through the `X-Vault-Token` header and the
`GET /v1/auth/token/lookup-self` validation call described below.

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
