## Features

### SPIFFE JWT-SVID Workload Authentication (`--jwt-svid-auth`)

Cosmian KMS now natively supports authenticating Kubernetes and microservice
workloads using standard **SPIFFE JWT-SVIDs** issued by SPIRE.

#### Motivation & Architecture

In Kubernetes environments using SPIRE, workloads establish mTLS at the transport
level (validating peer certificates against the SPIFFE trust bundle via `client_ca_cert_pem`)
and authenticate application requests via short-lived JWT-SVIDs presented in the
`Authorization: Bearer <token>` header.

Because a SPIFFE JWT-SVID does not carry an `email` claim (identifying the workload
solely via `sub = spiffe://<trust-domain>/<workload-path>`), standard OIDC JWT
validation previously rejected these tokens.

#### Changes

1. **Opt-in server flag**: `--jwt-svid-auth` / `KMS_JWT_SVID_AUTH` (`IdpAuthConfig.jwt_svid_auth`),
   defaulting to `false`. When enabled on the server, JWT authentication allows tokens without an
   `email` claim provided `sub` starts with `spiffe://`.
2. **Subject Mapping**: The full SPIFFE URI (e.g. `spiffe://cosmian-test-a.local/my-workload`)
   is used directly as the KMS `UserId` / object owner.
3. **Audit Trail**: Authentications via SPIFFE JWT-SVID are tracked as `AuthMethod::JwtSvid`
   (distinct from `AuthMethod::OidcJwt`).
4. **Interactive Setup**: `kms setup` auth wizard now prompts whether configured JWT/OIDC
   providers issue SPIFFE JWT-SVIDs.
5. **E2E Integration Test**: Added `.mise/tasks/test/spire-jwt-svid` validating the full
   mint → `ckms` configuration → object creation and ownership verification flow against a
   live SPIRE server.
