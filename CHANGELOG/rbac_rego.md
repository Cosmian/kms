## Features

- Add OPA (Open Policy Agent) RBAC middleware integration with three modes: disabled, exclusive, enforcing
- Add `--opa-url` and `--opa-mode` CLI flags (env vars `KMS_OPA_URL`, `KMS_OPA_MODE`) to configure the OPA sidecar
- Add startup validation of the OPA settings: `--opa-mode exclusive` or `--opa-mode enforcing` without `--opa-url`, and `--opa-url` together with `--opa-mode disabled` (OPA would never be consulted), are startup errors; `--opa-url` must be an `http://` or `https://` URL (it is not echoed in errors, as it may embed credentials), and a cleartext `http://` URL to a non-loopback host logs a `SECURITY` warning
- Add KMIP-GO compliance tests for `CreateSplitKey` (§4.38) and `JoinSplitKey` (§4.39): share metadata assertions, full split-then-join roundtrip, threshold enforcement, and Query operation advertisement (`split_key_test.go`)
- Add a `domain` column to the objects table of the SQL backends (SQLite, PostgreSQL, MySQL/MariaDB) for domain-scoped access control; the Redis-Findex store does not persist it (objects read back without a domain, so a domain-scoped role never matches and only the owner and `SuperAdmin` rules can), and the server logs a startup warning when an OPA mode is combined with Redis-Findex
- Add `OpaClient` HTTP client with fail-closed design: any transport, parse or non-2xx error is a denial, HTTP redirects are not followed (a redirect is a denial, so the decision input is never replayed to another host), and the body of a non-2xx response is only logged at `debug` level
- Add support for CSR-based Certify TTL: the `requested_validity_days` vendor attribute is now honoured on CSR-based `Certify` requests (the `build_and_sign_certificate` path already read it; this release adds regression tests and a matching `ttlDays int` parameter to `github.com/Cosmian/kmip-go`'s `Certify()` function, closing the SPIRE / kmip-go limitation documented at <https://github.com/spiffe/spire/pull/7235#discussion_r3829548963>)
- Wire OPA authorization into `user_has_permission()` with mode-dependent behavior:
    - Exclusive: OPA is the sole decision maker
    - Enforcing: OPA is authoritative (a denial, error or timeout is final and an allow is sufficient); native Crypto Officers skip OPA on non-HSM objects and use the legacy KMS permission logic, and HSM-backed objects must also pass it after OPA allows
- Add `build_opa_input()` helper that constructs the OPA input document from request context
- Add `kms.rego` Rego policy supporting role-based domain-scoped access control: the object owner and `SuperAdmin` are always allowed, while `DomainAdmin`, `CryptoOfficer`, `Auditor` and `User` are limited to the operations of their role on objects of their own domain; an empty domain never matches (a user without a domain, or an object without a domain, is reachable by its owner and `SuperAdmin` only), and an `Auditor` cannot `Get` key material
- Extract the JWT `roles` and `as_rid` claims (the Authentication Server realm ID, which is the user's domain) into `AuthenticatedUser` for the OPA context; the legacy claim name `as_domain` is accepted as an alias and a bare `domain` claim is ignored, so an identity provider attribute of that name cannot scope a user to a tenant
- Add a per-request `OpaUserContext` task-local (`tokio::task_local!`) to propagate roles/domain without threading them through all function signatures
- Log every OPA denial at `WARN` on the `audit` log target as `OPA_DENIED` (user, roles, domains, operation, object and mode); the line is only emitted when `RUST_LOG` enables that target, for example `RUST_LOG="cosmian_kms_server=info,audit=warn"`
- Add the `deploy/rbac_rego` Docker Compose stack that runs the KMS in exclusive OPA mode behind Keycloak, to try the RBAC roles end to end:
    - Keycloak realm `kms` with the five role groups (`SuperAdmin`, `DomainAdmin`, `CryptoOfficer`, `Auditor`, `User`), eight sample users in two domains, token mappers for the `roles`, `as_rid` and audience claims, and a `domain` attribute that is mandatory when an administrator creates a user
    - OPA with live policy reload (`--watch`) and a console decision log, loading `test_data/opa/kms.rego`
    - `verify.sh`: 53 checks that send KMIP requests with the token of each sample user and compare the outcome with the expected role matrix and with OPA
    - Dependabot (`docker-compose` ecosystem) keeps the digest-pinned Keycloak and OPA images up to date
    - Complete KMS fixture `test_data/configs/server/rbac/keycloak_opa.toml` and `test_data/certificates/client_server/generate_idp_server_cert.sh`, which issues the `keycloak.localhost` certificate with the existing test CA
    - Hardened demo realm and ports: access tokens live 5 minutes, brute-force detection locks an account after 5 failures, passwords need at least 12 characters, and the `email` attribute (the identity the KMS authorizes) can only be edited by an administrator, not by the user it belongs to; the published ports are bound to the loopback interface and the Keycloak and OPA images are pinned by digest
- Add the `opa` and `auth-verifier` services to the root `docker-compose.yml` for the OPA test suite: both images are pinned by digest and their ports are published on the loopback interface only (the OPA REST API is unauthenticated and accepts policy updates), and the `auth-verifier` health check probes the TLS port with a TCP connect because the image ships no `curl`

## Documentation

- Restructure `documentation/docs/configuration/authorization/` into 4 pages:
    - `index.md`: overview, mode table, architecture diagram, role model, domain model, JWT claims, OPA input document, ceremony note, config reference
    - `mode1.md`: native KMS permissions (ownership, grants, HSM, privileged users) with sequence and flowchart diagrams
    - `mode2.md`: exclusive OPA mode with sequence diagram, Rego evaluation flowchart, fail-closed diagram, debug endpoint
    - `mode3.md`: enforcing mode (OPA-authoritative, with the native KMS check for native Crypto Officers and HSM-backed objects) with sequence diagram, decision flowchart, interaction scenarios table
- Remove `is_super_admin` from OPA input document — ceremony super-admin is fully decoupled from OPA (native KMS gate only)
- Remove `is_super_admin` allow rule and `super_admin_ceremony` reason from `kms.rego`
- Update `OPA-middleware.md` SA3 section to reflect full decoupling
- Update `documentation/mkdocs.yml` navigation
- Add the how-to page `Try RBAC with Keycloak and OPA` (`configuration/authorization/rbac-keycloak-opa-demo.md`) and `deploy/rbac_rego/README.md`
- Document in `mode2.md`, `mode3.md`, the Keycloak how-to page and `deploy/rbac_rego/README.md` that Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify, Revoke, Destroy and Rekey on a key owned by someone else are authorized from the native KMS ownership and grants only, even in exclusive and enforcing OPA modes
- Document in the Keycloak how-to page and in `deploy/rbac_rego/README.md` that a token without a domain claim leaves its user without a domain: only the owner and `SuperAdmin` rules can then apply to it, and the objects it creates carry no domain
- Document that only the `Create` operation stamps the creator's domain on the new object: the objects of the other creation operations carry no domain, so with OPA enabled a non-owner can only reach them as `SuperAdmin`
- Rewrite the `opa-authverifier-setup.md` how-to for the Cosmian Authentication Server 0.5.0: users are created with a plaintext `password_input` (the server hashes it) and the realm ID is the user's domain, the JWKS is served at `/.well-known/jwks.json`, and the KMS trusts the verifier through the TOML-only `[auth_verifier]` table because its tokens carry no `iss`, `aud`, `email` or `kid` claim (`jwt_auth_provider` is for third-party OIDC providers such as Keycloak and rejects them)
- Fix the documentation of the Web UI Authentication Verifier login (`configuration/ui.md` and the `/ui/login_as` description of the OpenAPI specification): the settings are `auth_verifier_url`, `auth_verifier_realm` and `auth_verifier_accept_invalid_certs` of the TOML-only `[auth_verifier]` table; the `[cosmian_auth]` table and the `--cosmian-auth-*` flags it described do not exist
- Document the `OPA_DENIED` audit log and the `RUST_LOG` filter it needs, and correct the OPA RBAC ADRs and the `OPA-middleware.md` design plan where they differed from the implementation (claim names, Auditor operations, domain stamping, `ceremony_key_id` status, redirects)
- Fix the debug query of `mode2.md`: the Rego rule that lists the matching rules is `/v1/data/kms/reasons`, not `/v1/data/kms/reason`

## Refactor

- Add `domain: String` field to `ObjectWithMetadata` struct
- Extend `ObjectsStore::create()` trait with `domain: &str` parameter
- Add schema migration for existing databases: `ALTER TABLE objects ADD COLUMN domain` on SQLite, PostgreSQL (`IF NOT EXISTS`) and MySQL/MariaDB (after checking that the column is missing)
- Add `roles: Vec<String>` and `domain: Option<String>` fields to `AuthenticatedUser`
- `UserClaim` (JWT deserialization) now includes `roles` and a `domain` read from the `as_rid` claim (alias `as_domain`)

## Testing

- Add 5 OPA integration test vectors under `test_data/vectors/opa/` covering mode 1 (disabled), mode 2 (exclusive), and mode 3 (enforcing), with both allowed and denied paths
- Provision the Cosmian Authentication Server for the OPA vectors with `test_data/configs/auth_verifier/provision_opa_users.sh`: it creates the realms `kms-opa-test` and `kms-opa-other` (the realm ID is the domain, carried by the `as_rid` claim) and eight users (one per `SuperAdmin`, `CryptoOfficer`, `User`, `Auditor` and `DomainAdmin` role, plus users without a role and with an unknown role) through the 0.5.0 API, where users are created with a plaintext `password_input` that the server hashes; the script is idempotent, fails on any unexpected HTTP status and prints one `export KMS_TEST_OPA_*_JWT=…` line per user for the vectors to read
- Add `get_or_init_opa_allowed_server()` and `get_or_init_opa_denied_server()` OnceCell helpers that start KMS servers patched with OPA config; tests skip gracefully when `KMS_OPA_URL` or `KMS_AUTH_SERVER_URL` env vars are absent
- Add `json` and `cookies` features to the `reqwest` dev-dependency for auth server REST calls
- Add 2 new OPA negative test vectors under `test_data/vectors/opa/`:
    - `mode_exclusive_user_role_denied`: `User`-role JWT (non-owner) attempts `Get` on an officer's key → denied because `Get ∉ user_ops` in `kms.rego`
    - `mode_exclusive_wrong_domain`: `CryptoOfficer` JWT in domain `kms-opa-other` attempts `Get` on a key created in domain `kms-opa-test` → denied because `same_domain` helper fails
- Extend `IdentityConfig` with `access_token_env: Option<String>` to support JWT-based multi-identity test vectors (in addition to existing mTLS `client_cert`/`client_key`)
- Extend `build_identity_clients` to build JWT identity clients via `access_token_env` (reads named env var for the Bearer token; clears mTLS settings)
- Add 3 more OPA test vectors (`mode_exclusive_auditor_destroy_denied`, `mode_exclusive_auditor_get_attributes_allowed`, `mode_exclusive_domain_admin_wrong_domain`) with JWT-based Auditor and DomainAdmin identities
- Add 4 multi-tenant isolation test vectors completing the cross-domain isolation matrix for all five RBAC roles:
    - `mode_exclusive_auditor_wrong_domain`: Auditor (kms-opa-test) denied `GetAttributes` on a key owned by kms-opa-other — same_domain fails even for read-only metadata ops
    - `mode_exclusive_user_wrong_domain`: User (kms-opa-test) denied `GetAttributes` on a key owned by kms-opa-other — domain boundary blocks even the least-privileged role
    - `mode_enforcing_wrong_domain`: CryptoOfficer (kms-opa-other) denied `Get` on a kms-opa-test key in enforcing mode — domain isolation is not exclusive-mode-only
    - `mode_exclusive_super_admin_cross_domain`: SuperAdmin allowed `Get` across domain boundaries — proves only the designated top role bypasses `same_domain`; the key is then destroyed by its owner, because `Destroy` is authorized from the native KMS permissions and never consults OPA
- Add 5 `test_vec_opa_*_auth_verifier_*` tests that run the officer, super-admin, user-role and auditor vectors through the dedicated Authentication Verifier middleware (`[auth_verifier]`), so the `roles` and `as_rid` claims of real Authentication Server tokens reach OPA; with the 21 vectors of `test_data/vectors/opa/` this makes 26 `test_vec_opa_*` tests, which skip themselves when the environment variables they need (`KMS_OPA_URL`, `KMS_AUTH_SERVER_URL`, `KMS_TEST_OPA_*_JWT`) are unset
- Harden the `opa-rbac` interop script `.mise/scripts/test/test_opa_rbac.sh`: no `set -x` (it traced every command, including those handling the provisioned JWTs), free ports picked at run time instead of the fixed 9991, 8182 and 8444, the OPA image pinned by digest and published on the loopback interface only, TLS verification kept on when probing the Authentication Server, a `mktemp` directory for its ephemeral database, strict parsing of the JWT lines printed by the provisioning script instead of `eval`, and a single `EXIT` handler that also stops the Authentication Server and no longer turns a passing run into a failure when Phase 3 is skipped
- Add policy checks to `test_opa_rbac.sh` that pin the `kms.rego` rules: an `Auditor` cannot `get` key material but can `locate`, a `User` can `signature_verify`, and a caller or an object without a domain is reachable by the owner and `SuperAdmin` only
- OPA JWT test servers: point `jwt_auth_provider` at the Authentication Server JWKS endpoint `/.well-known/jwks.json` (there is no `/public/jwks`)

## Bug Fixes

- Automatic CRL regeneration (after `Revoke` and the refresh cron) signs as the issuer certificate's owner and bypasses the Crypto Officer gate of `GenerateCRL`, so published CRLs keep refreshing when `crypto_officer.users` is configured; the caller-driven `GenerateCRL` keeps the gate
- Web UI SPIFFE JWT-SVID session login (`POST /ui/login_svid`) now keeps the SVID's `roles` and `domain` claims in the session, like the Auth Verifier login, so OPA evaluates the same context as for bearer tokens
- `UserClaim` JWT deserialization: add `#[serde(default)]` to the `aud` field so a JWT without an `aud` claim no longer fails with "missing field `aud`"; the audience is still enforced when the provider declares one (third field of `--jwt-auth-provider`), in which case a token without `aud` is rejected
- JWT middleware: fall back to `sub` claim when `email` is absent, for identity providers that identify their users by `sub` only; the fallback is reserved to issuers that did not opt into SPIFFE (`--jwt-svid-auth`), and a `spiffe://` `sub` is rejected unless the issuer opted in
- JWT middleware (`handle_jwt`): remove panicking `actix_identity::Identity::extract` call; the JWT bearer-token middleware reads directly from the `Authorization: Bearer` header — session cookie auth is handled by the dedicated `SessionAuth` middleware and must not be mixed into the OIDC JWT path
- OPA denied test servers: merge `exclusive_denied` and `enforcing_denied` into a single shared `ONCE_VECTOR_OPA_DENIED` singleton to avoid concurrent macOS Keychain PKCS#12 loading failures (`OSStatus -26276`) when both servers start in parallel
- OPA denied test servers: disable the socket server and use opa-mode-specific `sqlite_path` and `root_data_path` to prevent port/file conflicts between concurrent cert-auth test servers
- OPA denied test servers: stop overriding `http.port` in the config patch; the test server helper binds a free port before applying the patch, so the override pointed the client at a port nobody listens on and every vector of the shared denied server failed
- Fix `create.rs` to stamp the created object with the creator's domain (from OPA user context) instead of hardcoded `""`, enabling non-owner domain-scoped role checks (Auditor, DomainAdmin) to work correctly; only `Create` stamps the domain, the objects produced by the other creation operations carry no domain and are therefore reachable through OPA by their owner and `SuperAdmin` only
- Fix `kms.rego` operation names: all role-based op sets (`crypto_officer_ops`, `auditor_ops`, `user_ops`) now use lowercase snake_case names matching `KmipOperation::Display` output (e.g. `"get_attributes"` not `"GetAttributes"`)
- Fix `mode_exclusive_auditor_destroy_denied` manifest: wrong `assert_error_reason` was `Object_Not_Found`; Destroy uses a count guard returning `Item_Not_Found` when no object passes permission check
- Fix `enforce_create_permission`: honor `crypto_officer.users` and `default_username` for the `Create` right even when OPA is active, so KMS-native CryptoOfficers (e.g. split-key ceremony participants) can still create keys; OPA remains the authoritative gatekeeper for all other users
- Add 5 unit tests for `handle_auth_verifier` (full pipeline: HTTP `Authorization` header → `AuthenticatedUser.domain` + `.roles`) and 5 unit tests for `handle_jwt` (full pipeline: Authorization header → `AuthenticatedUser.domain` + `.roles` + username resolution) in `crate/server/src/middlewares/`; these are the definitive proof that `domain` and `roles` survive the middleware pipeline without being dropped

### Hardening

- JWT validation (`--jwt-auth-provider`): the `iss` claim (unless the issuer opted into SPIFFE), the `aud` claim when the provider declares an audience, and the `sub` claim when the subject is validated are now required; `jsonwebtoken` only compares them when the token carries them, so a token signed by a trusted key that omitted a claim used to skip that check. Tokens from an identity provider that omits these claims are now rejected with HTTP 401, so configure the provider to emit them; Cosmian Authentication Server tokens carry no `iss` or `aud` and are accepted through the TOML `[auth_verifier]` table, not through `--jwt-auth-provider`
- JWT identity: a blank `email` claim is treated as absent (the `sub` fallback applies) instead of being accepted as an empty username, a token with neither a usable `email` nor a usable `sub` is rejected, and identity claims are written to the logs escaped so that control characters in a claim cannot forge log lines
- Web UI login: the OIDC callback and the Authentication Verifier login (`POST /ui/login_as`) now start a fresh session (previous state discarded and session ID renewed), as the SPIFFE login already did, so that neither a session ID planted before authentication nor the `roles` and `domain` of an earlier login on the same cookie can be inherited by the new identity
