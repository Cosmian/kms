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

mTLS, when enabled, remains strictly a **transport-level** control: the peer certificate is
verified against the SPIFFE trust bundle via the existing `client_ca_cert_pem` mechanism,
but its content (CN or SAN) is **not** used to derive application identity.
`tls_auth.rs` is intentionally left unmodified. All application identity for this flow
comes from the JWT-SVID's `sub` claim, keeping a single source of truth for "who is
calling" regardless of whether mTLS or plain TLS is used at the transport level.

Priority order in the JWT middleware is: `email` (existing OIDC/IdP behavior, unchanged)
first; `sub` (SPIFFE-only fallback, opt-in) second; otherwise reject with the pre-existing
"no email in JWT" error. This preserves 100% backward compatibility for every existing
JWT/OIDC and Google CSE configuration, none of which set the new flag.

The Web UI and `ckms` CLI are unaffected: `ckms` already supports configuring a
pre-obtained bearer token (`access_token` in `ckms.toml`), which is exactly how an operator
supplies a JWT-SVID minted via `spire-server jwt mint`. No CLI or UI code changes are
required; self-service SPIFFE login from the browser UI remains a known, documented
limitation, out of scope for this decision.

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
- **POS-004**: `ckms` CLI and existing `access_token` configuration work unchanged, keeping
  the CLI/UI parity rule (`cli-ui-sync.instructions.md`) satisfied without additional
  development.

### Negative

- **NEG-001**: The full SPIFFE URI becomes the KMS username; operators relying on
  human-readable usernames for audit/reporting will see SPIFFE URIs instead (mitigated by
  documenting this mapping clearly; no truncation/aliasing is performed, by design, to
  avoid silently colliding two distinct workload identities).
- **NEG-002**: There is still no self-service SPIFFE login path for the Web UI; UI users
  must continue to authenticate via the existing supported methods. This is a known,
  documented limitation, not a defect of this decision.
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
- **IMP-002**: `JwtConfig.accept_spiffe_subject: bool` is carried per JWT provider
  configuration (not globally), so only providers derived from
  `--jwt-auth-provider` + `--jwt-svid-auth` are affected; Google CSE's internally
  constructed `JwtConfig` entries always set it to `false`.
- **IMP-003**: `resolve_authenticated_user` (pure function, no HTTP/actix dependency) holds
  the identity-resolution decision and is covered by unit tests in
  `jwt_token_auth.rs` (email priority, SPIFFE acceptance/rejection, non-SPIFFE
  `sub` rejection, reserved-identity defense-in-depth).
- **IMP-004**: A local, non-Kubernetes integration test
  (`.mise/tasks/test/spire-jwt-svid`, reusing the existing `test_data/spire/` /
  `.mise/tasks/test/spire*` harness of local SPIRE server/agent processes) validates the
  end-to-end flow: mint a JWT-SVID via `spire-server jwt mint`, configure it as
  `access_token` in `ckms.toml`, and verify the resulting KMS object owner is the full
  SPIFFE URI.
- **IMP-005**: Wizard (`auth_wizard.rs`) prompts operators configuring a JWT/OIDC provider
  whether it issues SPIFFE JWT-SVIDs, populating `jwt_svid_auth` accordingly.

## References

- **REF-001**: `documentation/docs/adr/2026-07-26-spire-spiffe-via-vault-api.md` — related
  but distinct SPIRE/SPIFFE integration (KMS as Vault-compatible backend *for* SPIRE
  itself, not KMS-as-a-SPIFFE-workload authentication).
- **REF-002**: `crate/server/src/middlewares/jwt/jwt_token_auth.rs`,
  `crate/server/src/middlewares/jwt/jwt_config.rs`,
  `crate/server/src/config/command_line/idp_auth_config.rs`,
  `crate/server/src/config/params/server_params.rs`,
  `crate/server/src/start_kms_server.rs`,
  `crate/server/src/config/wizard/auth_wizard.rs`.
- **REF-003**: SPIFFE JWT-SVID specification —
  <https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>
