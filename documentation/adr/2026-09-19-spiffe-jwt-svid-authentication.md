---
title: "ADR-2026-09-19: SPIFFE JWT-SVID Authentication via JWT `sub`-Claim Fallback"
status: "Accepted"
date: "2026-09-19"
authors: "Architecture Team"
tags: ["architecture", "spiffe", "spire", "jwt", "mtls", "authentication"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-09-19: SPIFFE JWT-SVID Authentication via JWT `sub`-Claim Fallback

## Status

Accepted

## Context

Operators deploying the KMS inside a Kubernetes cluster that uses SPIFFE/SPIRE for
workload identity terminate service-to-service traffic in mTLS, with each workload
authenticating via a JWT-SVID (a JWT issued by the SPIRE OIDC Discovery Provider) rather
than a classic OIDC identity token.

Two options were initially considered by the operator to reach this deployment shape:

1. Enable KMS mTLS **and** force `force_default_username = admin` in the server config so
   that every authenticated client (whatever its actual workload identity) is mapped to a
   single administrative account. This defeats per-workload authorization/audit and is a
   security regression.
2. Enable TLS only, with no authentication at all, which removes any application-level
   identity and authorization — unacceptable for a KMS.

Investigation of the existing KMS auth stack showed two real gaps preventing a proper
third option (mTLS as transport only + JWT-SVID as the actual identity):

- `crate/server/src/middlewares/jwt/jwt_token_auth.rs` required an `email` claim to
  authenticate a JWT. A JWT-SVID carries no `email` claim — only `sub =
  spiffe://<trust-domain>/<workload-path>` (already required and validated by
  `validate_authentication_token`, which enforces `required_spec_claims = ["sub", "exp"]`).
- The existing mTLS middleware (`tls_auth.rs`) only reads the certificate CN, not the
  SPIFFE SAN URI — but this ADR does not extend it (see Alternatives).

The KMS already supports configuring an arbitrary OIDC-style JWT issuer via
`--jwt-auth-provider`, and a SPIRE OIDC Discovery Provider exposes a standard
`/.well-known/openid-configuration` + JWKS endpoint, so no new provider integration is
needed — only the claim-to-identity mapping logic needed to change, and only when the
operator explicitly opts in.

## Decision

Introduce an explicit, per-deployment opt-in flag, `--jwt-svid-auth` /
`KMS_JWT_SVID_AUTH` (`IdpAuthConfig.jwt_svid_auth`), applied globally to all
`--jwt-auth-provider` entries. When enabled, the JWT authentication middleware accepts a
validated token that has **no** `email` claim, provided its `sub` claim starts with
`spiffe://` (a SPIFFE ID). The full SPIFFE URI is used, unmodified, as the KMS `UserId`
(no truncation), which becomes the acting principal for every subsequent authorization
check.

**Audience is mandatory.** The SPIFFE JWT-SVID specification requires a validator to
reject any SVID whose `aud` does not include the validator's own identifier; otherwise a
token minted for service A can be replayed against service B. `jsonwebtoken` only checks
`aud` when the claim is present, so the SPIFFE `sub` path (Bearer and `POST /ui/login_svid`)
additionally requires a present, non-empty `aud` claim, and the server **refuses to start**
when `--jwt-svid-auth` is set and any `--jwt-auth-provider` entry has no audience (third
field `issuer,jwks_uri,audience`). Because the flag is global, this applies to every
configured provider. Google CSE issuers never accept SPIFFE subjects.

**mTLS precedence.** `tls_auth.rs` is left unmodified and does not read the SPIFFE SAN, but
mTLS is *not* purely transport-level when combined with JWT-SVID. Actix runs `wrap`ped
middleware last-in-first-out, and `start_kms_server.rs` wraps the client-certificate
middleware after the JWT middleware, so it runs **first**. If the presented client
certificate has a CN, the request is authenticated as that CN (`AuthMethod::Mtls`); the JWT
middleware then sees an already-authenticated user and ignores any JWT-SVID, as does the
session cookie. A certificate without a usable CN (missing, empty or `*`) does not
authenticate, and the request falls through to the JWT-SVID. Operators wanting the SPIFFE ID
to be the identity must therefore issue CN-less client certificates (SPIRE-issued X.509-SVIDs
typically carry no CN; verify for your SPIRE version), use separate listeners/paths, or knowingly accept CN precedence.

Priority order in the JWT middleware is: `email` (existing OIDC/IdP behavior, unchanged)
first; `sub` (SPIFFE-only fallback, opt-in) second; otherwise reject with the pre-existing
"no email in JWT" error. This preserves 100% backward compatibility for every existing
JWT/OIDC and Google CSE configuration, none of which set the new flag.

The Web UI and `ckms` CLI are fully integrated with SPIFFE JWT-SVID authentication:

- **`ckms` CLI**: Implements native Workload API gRPC integration via `ckms login spire --audience <aud>` (`crate/clients/clap/src/actions/login.rs`), which connects directly to the local SPIRE Agent's Unix Domain Socket (discovered via `SPIFFE_ENDPOINT_SOCKET` or `--socket-path`), attests the process via kernel peer credentials (`SO_PEERCRED`), fetches a JWT-SVID, and persists it into `http_config.access_token` in `ckms.toml`.
- **Web UI (Gateway/BFF session)**: Browsers cannot reach the Workload API, and the Web UI has **no** paste-your-SVID login form. When `--jwt-svid-auth` is set the server advertises `"SPIFFE"` in the `auth_methods` of `GET /ui/auth_method` (priority JWT > SPIFFE > AUTH_VERIFIER > CERT). A trusted gateway/BFF posts a JWT-SVID to `POST /ui/login_svid` (`{"jwt_svid":"<token>"}`), which establishes an encrypted, cookie-backed `auth_session`; the UI resolves the identity via `GET /ui/whoami`. A browser with no session only sees an informational notice. The gateway MUST authenticate the end user first (see NEG-004).
- **Is `jwt_svid_auth` still mandatory?**: **Yes, `jwt_svid_auth` remains mandatory on the KMS server.** It acts as an indispensable explicit security gate. Without this flag, a standard OIDC provider could allow tokens with missing or forged `email` claims to fall back to arbitrary `sub` identities, violating standard OIDC trust invariants. Furthermore, both `validate_jwt_svid` (used only by `POST /ui/login_svid`) and the bearer path (`jwt_auth_middleware` → `handle_jwt` → `resolve_authenticated_user`) enforce `accept_spiffe_subject == true` before permitting `sub: spiffe://...` resolution.

## Consequences

### Positive

- **POS-001**: Operators can run the KMS as a proper SPIFFE-aware workload — mTLS for
  transport-level trust, JWT-SVID for per-workload identity and authorization — without
  collapsing all traffic onto a single shared `admin` account.
- **POS-002**: Zero behavioral change for existing OIDC/IdP and Google CSE deployments: the
  fallback is strictly opt-in per flag and additionally scoped to `sub` values that are
  syntactically SPIFFE IDs.
- **POS-003**: No new provider/protocol integration was required — the SPIRE OIDC
  Discovery Provider is consumed through the existing generic `--jwt-auth-provider`
  mechanism.
- **POS-004**: `ckms` CLI natively supports acquiring and using SPIFFE JWT-SVIDs via `ckms login spire`, operating over standard Unix domain sockets without shelling out to external binaries or requiring long-lived credentials.
- **POS-005**: The Web UI can be fronted by a gateway/BFF that establishes a cookie-backed session through `POST /ui/login_svid`, so raw JWT-SVIDs never reach the browser. No credential is ever typed or pasted into the UI.

### Negative

- **NEG-001**: The full SPIFFE URI becomes the KMS username; operators relying on
  human-readable usernames for audit/reporting will see SPIFFE URIs instead (mitigated by
  documenting this mapping clearly; no truncation/aliasing is performed, by design, to
  avoid silently colliding two distinct workload identities).
- **NEG-002**: Direct in-browser attestation against the SPIRE Workload API remains architecturally impossible due to browser sandbox constraints; Web UI sessions require a gateway (or sidecar) with access to the Workload API socket to bridge into `POST /ui/login_svid`.
- **NEG-004**: A session obtained with the *gateway's own* JWT-SVID is a session as one shared SPIFFE identity: every browser that receives it shares one user, with no per-user authorization or audit, which is the anti-pattern rejected in ALT-003/ALT-004. The gateway must authenticate the end user (e.g. OIDC at the gateway) before relaying a session, and the session identity should be scoped accordingly.
- **NEG-005**: When mTLS (`clients_ca_cert_file`) and `--jwt-svid-auth` are both enabled, a client certificate with a CN takes precedence over any JWT-SVID or session cookie (see Decision).
- **NEG-006**: Operators must configure an audience on every `--jwt-auth-provider` entry when enabling `--jwt-svid-auth`; the server refuses to start otherwise.
- **NEG-003**: The JWT middleware now carries an additional branch (SPIFFE `sub` fallback),
  slightly increasing its cyclomatic complexity; mitigated by extracting the decision logic
  into a small, independently unit-tested pure function
  (`resolve_authenticated_user`).

## Alternatives Considered

### Extend `tls_auth.rs` to read the SPIFFE SAN URI from the client certificate

- **ALT-001 Description**: Have the mTLS middleware itself extract the SPIFFE ID from the
  certificate's SAN URI and use it as the KMS identity, instead of relying on the JWT.
- **ALT-002 Rejection Reason**: The operator's deployment explicitly separates transport
  trust (mTLS) from application identity (JWT-SVID), matching how the SPIRE Workload API
  and the cluster's existing token-minting flow are actually used. Using the certificate as
  the identity source would create two divergent identity paths (cert-based vs
  JWT-based) depending on which auth method wins, complicating the audit trail. Kept as a
  documented non-goal.

### Force `force_default_username = admin` when mTLS is enabled

- **ALT-003 Description**: Map every mTLS-authenticated client to a single shared `admin`
  account, as the operator was initially forced to do.
- **ALT-004 Rejection Reason**: Eliminates per-workload authorization and audit trail —
  unacceptable from a least-privilege and traceability standpoint; the entire motivation
  for this ADR was to avoid this workaround.

### TLS only, no authentication

- **ALT-005 Description**: Terminate TLS without any authentication middleware.
- **ALT-006 Rejection Reason**: Removes all application-level identity; not viable for a
  KMS handling key material and cryptographic operations.

## Implementation Notes

- **IMP-001**: New `AuthMethod::JwtSvid` variant distinguishes SPIFFE JWT-SVID
  authentication from standard OIDC JWT (`AuthMethod::OidcJwt`) in audit logs.
- **IMP-002**: `JwtConfig.accept_spiffe_subject: bool` is set from the single global
  `--jwt-svid-auth` flag on every `--jwt-auth-provider`-derived entry (there is no
  per-provider switch); Google CSE's internally constructed `JwtConfig` entries always set
  it to `false`. Startup fails if any such entry lacks an audience, and the SPIFFE `sub`
  path requires a non-empty `aud` claim (SPIFFE JWT-SVID spec: validators must reject SVIDs
  whose `aud` does not include their own identifier, preventing cross-service replay).
- **IMP-003**: `resolve_authenticated_user` (pure function, no HTTP/actix dependency) holds
  the identity-resolution decision and is covered by unit tests in
  `jwt_token_auth.rs` (email priority, SPIFFE acceptance/rejection, non-SPIFFE
  `sub` rejection, reserved-identity defense-in-depth).
- **IMP-004**: Integration test harnesses (`.mise/tasks/test/spire-jwt-svid` in this repository, as well as the reference Kubernetes deployment smoke test) validate the end-to-end flow:
  1. Native `ckms login spire --audience <aud>` connects to the SPIRE Agent Workload API socket and persists the JWT-SVID.
  2. A gateway/BFF calls `POST /ui/login_svid` to obtain a cookie-backed session.
  3. Authenticated requests create KMS cryptographic keys owned by the full SPIFFE URI.
- **IMP-005**: The Web UI backend exposes `POST /ui/login_svid` (`crate/server/src/routes/ui_auth.rs`), which requires `--jwt-svid-auth` (HTTP 500 otherwise), accepts only tokens whose `sub` starts with `spiffe://` (a token with an `email` claim but a non-SPIFFE `sub` is rejected), and validates the JWT-SVID against the cached JWKS, refreshing the JWKS once and retrying on failure (SPIRE key rotation). Success returns 200 `{"next_step":"Authenticated"}` and sets the `auth_session` cookie; an invalid SVID returns 401. `GET /ui/auth_method` advertises `SPIFFE` when the flag is set.
- **IMP-006**: Wizard (`auth_wizard.rs`) prompts operators configuring a JWT/OIDC provider whether it issues SPIFFE JWT-SVIDs, populating `jwt_svid_auth` accordingly.

## References

- **REF-001**: `documentation/docs/adr/2026-07-26-spire-spiffe-via-vault-api.md` — related
  but distinct SPIRE/SPIFFE integration (KMS as Vault-compatible backend *for* SPIRE
  itself, not KMS-as-a-SPIFFE-workload authentication).
- **REF-002**: `documentation/docs/integrations/spire_webui.md` — Web UI SPIFFE Authentication & Ingress Gateway Architecture.
- **REF-003**: `documentation/docs/integrations/spire_ckms.md` — CLI (`ckms`) SPIFFE Authentication Architecture.
- **REF-004**: `crate/server/src/middlewares/jwt/jwt_token_auth.rs`,
  `crate/server/src/middlewares/jwt/jwt_config.rs`,
  `crate/server/src/routes/ui_auth.rs`,
  `crate/clients/clap/src/actions/login.rs`,
  `crate/server/src/config/command_line/idp_auth_config.rs`,
  `crate/server/src/config/params/server_params.rs`,
  `crate/server/src/start_kms_server.rs`,
  `crate/server/src/config/wizard/auth_wizard.rs`.
- **REF-005**: SPIFFE JWT-SVID specification —
  <https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>
