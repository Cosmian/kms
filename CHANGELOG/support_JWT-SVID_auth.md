## Features

### Server / Config

- Add opt-in SPIFFE JWT-SVID workload authentication: `--jwt-svid-auth` / `KMS_JWT_SVID_AUTH` / `[idp_auth] jwt_svid_auth = true` (default `false`, global to all `--jwt-auth-provider` entries). A validated JWT without an `email` claim is accepted when `sub` starts with `spiffe://`; the full SPIFFE ID becomes the KMS user and object owner (audit method `JwtSvid`).
- **Audience required**: with `--jwt-svid-auth`, the server refuses to start if any `--jwt-auth-provider` entry has no audience (`issuer,jwks_uri,audience`), and SPIFFE subjects are rejected when the token has no non-empty `aud` claim. Google CSE issuers never accept SPIFFE subjects.
- When client-certificate authentication (`clients_ca_cert_file`) and `--jwt-svid-auth` are both enabled, a client certificate with a CN is authenticated first and takes precedence over any JWT-SVID or session cookie.
- `kms setup` auth wizard now asks whether the configured JWT/OIDC providers issue SPIFFE JWT-SVIDs.

### CLI

- Add `ckms login spire --audience <aud> [--spiffe-id <id>] [--socket-path <path|uri>]`: fetches a JWT-SVID from the local SPIRE Agent Workload API and stores it as `http_config.access_token`. `--socket-path` accepts a bare absolute path or a `unix://` / `tcp://` URI; when omitted, `SPIFFE_ENDPOINT_SOCKET` is used.

### API

- Add `POST /ui/login_svid` (body `{"jwt_svid":"<token>"}`): a gateway/BFF establishes a cookie-backed Web UI session from a JWT-SVID. Returns 200 `{"next_step":"Authenticated"}`, 401 for an invalid SVID (only `spiffe://` subjects are accepted; the JWKS is refreshed once and validation retried on failure), and 500 when `--jwt-svid-auth` is not enabled or the session cannot be stored.

### UI

- `GET /ui/auth_method` advertises `SPIFFE` in `auth_methods` when `--jwt-svid-auth` is set (priority JWT > SPIFFE > AUTH_VERIFIER > CERT). Browsers without a session see an informational notice; sessions are established by a gateway, not by a login form.

## Testing

- Add the `.mise/tasks/test/spire-jwt-svid` end-to-end suite: mint a JWT-SVID against a live SPIRE server, configure `ckms`, create an object and verify it is owned by the SPIFFE ID.

## Documentation

- Add ADR-2026-09-19 (SPIFFE JWT-SVID authentication) and the SPIFFE guides for the CLI, the Web UI gateway/BFF flow and workload authentication, including the mTLS precedence and audience requirements.
