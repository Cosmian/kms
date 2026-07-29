---
title: "ADR-2026-07-26: SPIRE/SPIFFE Integration via Vault-Compatible API (KMS Crypto Layer)"
status: "Amended"
date: "2026-07-26"
amended: "2026-07-28"
authors: "Architecture Team"
tags: ["architecture", "spiffe", "spire", "vault", "kms"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-07-26: SPIRE/SPIFFE Integration via Vault-Compatible API (KMS Crypto Layer)

## Status

Accepted — amended 2026-07-28 (see Amendment below)

## Context

Production SPIRE deployments require an enterprise KMS as both UpstreamAuthority (PKI engine: sign intermediate CA certificates) and
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
  `authentication/server/documentation/adr/2026-07-26-app-auth-api-for-spire.md`.
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
- **POS-003** HSM/PKCS#11 backing ensures private keys are never persisted to disk,
  without additional work.
- **POS-004** PQC readiness — ML-DSA-65 mapped as a transit key type
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
  two TLS endpoints and two database schemas. *(An nginx vault-proxy was previously also
  required as a third operational component; this was eliminated by the 2026-07-28
  amendment — see below.)*
- **NEG-003** 30-second cache staleness window — a revoked token remains valid at the KMS
  for up to 30 seconds. Acceptable for the beta; production hardening may reduce this or
  add a revocation push notification.

### Known Limitations (beta)

These are accepted limitations of the beta implementation, surfaced in code review and
recorded here so they are tracked before longer-lived production rollouts.

- **LIM-001** Single-tier CA chain — the PKI `sign-intermediate` response builds `ca_chain`
  as a single element (`[issuing_ca]`) by following `CA private key → PublicKeyLink →
  CertificateLink` exactly one hop. This is correct for a single-tier CA but returns an
  incomplete chain for a root→intermediate→leaf hierarchy, where SPIRE expects the *last*
  `ca_chain` element to be the true root. Multi-tier CA traversal is deferred; production
  multi-tier rollouts must account for this until full chain-walking is implemented.
- **LIM-002** Whole-second `creation_time` precision — transit key `creation_time` is
  formatted from KMIP's `InitialDate`, a POSIX-seconds timestamp with no sub-second
  component, so the RFC 3339 string never carries a fractional part (unlike real Vault,
  which returns nanosecond timestamps). If two keys for the same logical SPIRE key id are
  created within the same wall-clock second (e.g. a fast rotation-retry loop), SPIRE's
  string-based newest-key tiebreak is non-deterministic. Acceptable for the beta given
  SPIRE key ids are effectively unique per rotation; sub-second precision would require
  threading a higher-resolution creation timestamp through the KMIP object metadata.
- **LIM-003** FIPS transit/PKI paths untested in CI — the `spire` CI job runs only with the
  `non-fips` feature set, because the transit key-creation path exercises algorithms and
  Vault-API compatibility behaviour that are non-FIPS-only. The FIPS-mode SPIRE code paths
  (the `#[cfg(not(feature = "non-fips"))]` stubs and the FIPS-approved transit/PKI subset)
  therefore compile in CI but are not exercised end-to-end. This is a deliberate scoping
  decision for the beta: a FIPS CI cell for SPIRE is deferred until the FIPS-approved
  algorithm subset for transit is finalised.

## Alternatives Considered

### Alternative A — All auth and crypto in the KMS

- Implement both `/v1/auth/` and `/v1/transit/` + `/v1/pki/` in the KMS.
- **Rejected**: Mixes token issuance into the cryptographic server. KMS access model is
  KMIP-centric; a parallel Vault token model creates two competing auth subsystems. Auth
  logic is better co-located in auth-verifier, which already owns realm management, JWKS
  validation, and session lifecycle.
- **Note**: The 2026-07-28 amendment adds a *transparent proxy* (not token issuance) for
  `/v1/auth/*` in the KMS, which resolves the `vault_addr` routing problem without
  duplicating the auth subsystem — see Amendment below.

### Alternative B — All in auth-verifier (transit as HTTP proxy to KMS)

- auth-verifier serves transit/PKI endpoints and proxies crypto calls to KMS.
- **Rejected**: Every transit call would traverse two network hops. auth-verifier has no
  KMIP client today, adding significant new scope. The proxy adds latency incompatible
  with low-latency targets (certificate issuance < 500ms, DPoP validation < 5ms).

### Alternative C — Dedicated Vault adapter shim microservice

- A third service translates Vault HTTP API to Cosmian KMIP API.
- **Rejected**: Adds a third deployment unit with no reuse of existing infrastructure.
  Over-engineered for beta timeline; increases operational surface area.

## Implementation Notes

### auth-verifier side

The `/v1/auth/` scope, its database schema (`vault_tokens`, `vault_approle_roles`,
`vault_secret_ids`, `vault_k8s_roles`), and the `hvs.<base64url(...)>` token format are
implemented and documented entirely in the auth-verifier repository — see
`authentication/server/documentation/adr/2026-07-26-app-auth-api-for-spire.md`.
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

Multi-mount segmentation is deferred post-beta; the single-mount config
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
unconditionally regardless of client request body.

### PKI sign-intermediate validation

Requests with empty `uri_sans` are rejected with HTTP 400 — at least one SPIFFE URI SAN
is required per SPIRE plugin contract. Response de-duplication follows Vault ≥1.11: root
cert stripped from `ca_chain`; signed certificate stripped from `ca_chain` (already
present in `certificate`).

---

## Amendment — 2026-07-28: Remove nginx vault-proxy; KMS proxies `/v1/auth/*`

### Problem

SPIRE's `vault_addr` must be a **single URL** covering both the auth API
(`/v1/auth/*`) and the crypto engines (`/v1/transit/*`, `/v1/pki/*`). The original
design resolved this by fronting both services with an nginx reverse proxy. This added a
third operational component with its own TLS certificates, Docker image, and health check.

### Decision

**KMS adds a transparent reverse proxy** for the `/v1/auth/*` scope: every request
arriving at `KMS:9998/v1/auth/*` is forwarded byte-for-byte to the auth-verifier
instance already configured via `vault_auth_verifier_url`. The TLS client used for
token validation is reused, so no new configuration keys are needed.

SPIRE's `vault_addr` now points directly at the KMS. The nginx vault-proxy service is
removed from the reference deployment.

### Why this is not a rejection of Alternative A

Alternative A was "implement token issuance in KMS". This amendment does **not** do that:

- Token generation (`hvs.` tokens), AppRole role storage, and secret-id lifecycle remain
  entirely in auth-verifier.
- The KMS proxy is stateless and transparent — it does not inspect, modify, or cache the
  auth payload. It is equivalent to nginx's `proxy_pass /v1/auth/*` directive, but
  implemented inside the KMS process.
- The "two competing auth subsystems" concern that rejected Alternative A still does not
  apply: auth-verifier remains the sole authority for authentication.

### Consequences

| | Before | After |
|---|---|---|
| Services to deploy | KMS + auth-verifier + nginx vault-proxy | KMS + auth-verifier |
| TLS certificates | 3 (kms, auth, vault-proxy) | 2 (kms, auth) |
| SPIRE `vault_addr` | `https://vault-proxy:8200` | `https://kms:9998` |
| Auth path routing | nginx path-prefix | KMS built-in proxy scope |
| Auth token issuance | auth-verifier | auth-verifier (unchanged) |
| `/v1/auth/*` extra hop | none (nginx → auth-verifier direct) | one (KMS → auth-verifier) |

The extra network hop introduced by the KMS proxy only affects authentication calls
(AppRole login, token renewal), which are infrequent (once per token TTL, typically 1 h).
Transit and PKI requests are handled by KMS natively — their latency is unchanged.

The 30-second token validation cache in the KMS middleware is also unchanged: cache-hit
transit/PKI calls never call auth-verifier at all, whether nginx was present or not.

### Implementation

- `crate/server/src/routes/spire/auth_proxy.rs` — `proxy_auth_request` handler
- `crate/server/src/start_kms_server.rs` — `/v1/auth` scope registered alongside
  transit and PKI scopes inside the `vault_api_enabled` guard
- `test_data/spire/` — nginx configuration removed; `spire-server.conf` updated to
  `vault_addr = "https://host.docker.internal:9998"`
- `docker-compose.yml` — `vault-proxy` service removed from the `spire` profile

### auth-verifier side (co-shipped)

The amendment also ships the AppRole and token endpoints in auth-verifier that the KMS
now proxies to (`/v1/auth/approle/*`, `/v1/auth/token/*`). See
`authentication/server/documentation/adr/2026-07-26-app-auth-api-for-spire.md`.
