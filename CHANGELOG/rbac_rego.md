# Features

- Add OPA (Open Policy Agent) RBAC middleware integration with three modes: disabled, exclusive, enforcing
- Add `--opa-url` and `--opa-mode` CLI flags (env vars `KMS_OPA_URL`, `KMS_OPA_MODE`) to configure the OPA sidecar
- Add startup validation: `--opa-mode exclusive` or `--opa-mode enforcing` now fails with a clear error when `--opa-url` is not set (the server previously silently ignored the mode setting)
- Add KMIP-GO compliance tests for `CreateSplitKey` (§4.38) and `JoinSplitKey` (§4.39): share metadata assertions, full split-then-join roundtrip, threshold enforcement, and Query operation advertisement (`split_key_test.go`)
- Add `domain` column to the objects table across all database backends (SQLite, PostgreSQL, MySQL, Redis-findex) for domain-scoped access control
- Add `OpaClient` HTTP client with fail-closed design (deny on any transport/parse error)
- Wire OPA authorization into `user_has_permission()` with mode-dependent behavior:
    - Exclusive: OPA is the sole decision maker
    - Enforcing: both OPA and legacy KMS permission logic must allow
- Add `build_opa_input()` helper that constructs the OPA input document from request context
- Add `kms.rego` Rego policy supporting role-based domain-scoped access control
- Extract JWT `roles` and `as_domain` claims into `AuthenticatedUser` for OPA context
- Add per-request `OpaUserContext` thread-local to propagate roles/domain without threading through all function signatures

## Documentation

- Restructure `documentation/docs/configuration/authorization/` into 4 pages:
    - `index.md`: overview, mode table, architecture diagram, role model, domain model, JWT claims, OPA input document, ceremony note, config reference
    - `mode1.md`: native KMS permissions (ownership, grants, HSM, privileged users) with sequence and flowchart diagrams
    - `mode2.md`: exclusive OPA mode with sequence diagram, Rego evaluation flowchart, fail-closed diagram, debug endpoint
    - `mode3.md`: enforcing dual-gate mode with sequence diagram, compound decision flowchart, interaction scenarios table
- Remove `is_super_admin` from OPA input document — ceremony super-admin is fully decoupled from OPA (native KMS gate only)
- Remove `is_super_admin` allow rule and `super_admin_ceremony` reason from `kms.rego`
- Update `OPA-middleware.md` SA3 section to reflect full decoupling
- Update `documentation/mkdocs.yml` navigation

## Refactor

- Add `domain: String` field to `ObjectWithMetadata` struct
- Extend `ObjectsStore::create()` trait with `domain: &str` parameter
- Add schema migration for existing databases (ALTER TABLE ADD COLUMN domain)
- Add `roles: Vec<String>` and `domain: Option<String>` fields to `AuthenticatedUser`
- `UserClaim` (JWT deserialization) now includes `roles` and `domain` (alias `as_domain`) fields

## Testing

- Add 5 OPA integration test vectors under `test_data/vectors/opa/` covering mode 1 (disabled), mode 2 (exclusive), and mode 3 (enforcing), with both allowed and denied paths
- Add `setup_auth_server_for_opa()` helper that provisions the auth server (KMS_AUTH_SERVER_URL) with a `kms-opa-test` realm and `kms-opa-officer` user (CryptoOfficer role) via reqwest REST calls
- Add `get_or_init_opa_allowed_server()` and `get_or_init_opa_denied_server()` OnceCell helpers that start KMS servers patched with OPA config; tests skip gracefully when `KMS_OPA_URL` or `KMS_AUTH_SERVER_URL` env vars are absent
- Add `argon2` and `sha2` dev-dependencies to `test_kms_server` for computing Argon2id password hashes matching the auth server's formula
- Add `json` and `cookies` features to the `reqwest` dev-dependency for auth server REST calls
- Add 2 new OPA negative test vectors under `test_data/vectors/opa/`:
    - `mode_exclusive_user_role_denied`: `User`-role JWT (non-owner) attempts `Get` on an officer's key → denied because `Get ∉ user_ops` in `kms.rego`
    - `mode_exclusive_wrong_domain`: `CryptoOfficer` JWT in domain `kms-opa-other` attempts `Get` on a key created in domain `kms-opa-test` → denied because `same_domain` helper fails
- Extend `IdentityConfig` with `access_token_env: Option<String>` to support JWT-based multi-identity test vectors (in addition to existing mTLS `client_cert`/`client_key`)
- Extend `build_identity_clients` to build JWT identity clients via `access_token_env` (reads named env var for the Bearer token; clears mTLS settings)
- Extend `setup_auth_server_for_opa` to provision 3 users: `kms-opa-officer` (CryptoOfficer, kms-opa-test), `kms-opa-user` (User, kms-opa-test), `kms-opa-other-officer` (CryptoOfficer, kms-opa-other); store extra JWTs in `KMS_TEST_OPA_USER_ROLE_JWT` / `KMS_TEST_OPA_OTHER_DOMAIN_JWT`
- Restructure `setup_auth_server_for_opa` to use separate admin (`cookie_store=true`) and login (cookieless) clients, preventing admin session cookie from being overwritten by user logins
- Add 3 more OPA test vectors (`mode_exclusive_auditor_destroy_denied`, `mode_exclusive_auditor_get_attributes_allowed`, `mode_exclusive_domain_admin_wrong_domain`) with JWT-based Auditor and DomainAdmin identities; now 11 OPA vectors total, all passing
- Add 4 multi-tenant isolation test vectors completing the cross-domain isolation matrix for all five RBAC roles:
    - `mode_exclusive_auditor_wrong_domain`: Auditor (kms-opa-test) denied `GetAttributes` on a key owned by kms-opa-other — same_domain fails even for read-only metadata ops
    - `mode_exclusive_user_wrong_domain`: User (kms-opa-test) denied `GetAttributes` on a key owned by kms-opa-other — domain boundary blocks even the least-privileged role
    - `mode_enforcing_wrong_domain`: CryptoOfficer (kms-opa-other) denied `Get` on a kms-opa-test key in enforcing mode — domain isolation is not exclusive-mode-only
    - `mode_exclusive_super_admin_cross_domain`: SuperAdmin allowed `Get` and `Destroy` across domain boundaries — proves only the designated top role bypasses `same_domain`; now 15 OPA vectors total
- Extend `setup_auth_server_for_opa` to provision 5 users with per-user `domain` field: `kms-opa-officer` (CryptoOfficer, kms-opa-test), `kms-opa-user` (User, kms-opa-test), `kms-opa-auditor` (Auditor, kms-opa-test), `kms-opa-domain-admin-other` (DomainAdmin, kms-opa-other), `kms-opa-other-officer` (CryptoOfficer, kms-opa-other); store JWTs in `KMS_TEST_OPA_AUDITOR_JWT`, `KMS_TEST_OPA_DOMAIN_ADMIN_OTHER_JWT`

## Bug Fixes

- `UserClaim` JWT deserialization: add `#[serde(default)]` to `aud` field so JWTs without an `aud` claim (e.g. from Cosmian auth server) are accepted instead of failing with "missing field `aud`"
- JWT middleware: fall back to `sub` claim when `email` is absent, enabling compatibility with Cosmian auth server JWTs that use `sub` for the username
- JWT middleware (`handle_jwt`): remove panicking `actix_identity::Identity::extract` call; the JWT bearer-token middleware reads directly from the `Authorization: Bearer` header — session cookie auth is handled by the dedicated `SessionAuth` middleware and must not be mixed into the OIDC JWT path
- OPA denied test servers: merge `exclusive_denied` and `enforcing_denied` into a single shared `ONCE_VECTOR_OPA_DENIED` singleton to avoid concurrent macOS Keychain PKCS#12 loading failures (`OSStatus -26276`) when both servers start in parallel
- OPA denied test servers: set opa-mode-specific `sqlite_path`, `root_data_path`, and `socket_server_start = false` to prevent port/file conflicts between concurrent cert-auth test servers
- Auth server provisioning: use `drop()` instead of `let _ =` on HTTP responses to avoid `let_underscore_drop` Clippy lint
- Auth server provisioning: treat all HTTP errors on idempotent steps (realm/admin/userpass creation) as non-fatal, since re-running against a live in-memory auth server returns `500 UNIQUE constraint` instead of `409`
- Fix `create.rs` to stamp the created object with the creator's domain (from OPA user context) instead of hardcoded `""`, enabling non-owner domain-scoped role checks (Auditor, DomainAdmin) to work correctly
- Fix `kms.rego` operation names: all role-based op sets (`crypto_officer_ops`, `auditor_ops`, `user_ops`) now use lowercase snake_case names matching `KmipOperation::Display` output (e.g. `"get_attributes"` not `"GetAttributes"`)
- Fix `mode_exclusive_auditor_destroy_denied` manifest: wrong `assert_error_reason` was `Object_Not_Found`; Destroy uses a count guard returning `Item_Not_Found` when no object passes permission check
- Fix auth server provisioning: set `domain` field on each userpass record to the realm ID so the JWT `as_domain` claim is emitted and OPA `same_domain` checks work correctly
- Fix `enforce_create_permission`: honor `crypto_officer.users` and `default_username` for the `Create` right even when OPA is active, so KMS-native CryptoOfficers (e.g. split-key ceremony participants) can still create keys; OPA remains the authoritative gatekeeper for all other users
- OPA test provisioning: send plaintext passwords to the auth server's `create_userpass` endpoint (the server now computes the Argon2id hash itself) and drop the obsolete `argon2`/`sha2` dev-dependencies
- Add 5 unit tests for `handle_auth_verifier` (full pipeline: HTTP `Authorization` header → `AuthenticatedUser.domain` + `.roles`) and 5 unit tests for `handle_jwt` (full pipeline: Authorization header → `AuthenticatedUser.domain` + `.roles` + username resolution) in `crate/server/src/middlewares/`; these are the definitive proof that `domain` and `roles` survive the middleware pipeline without being dropped
