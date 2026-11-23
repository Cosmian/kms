# Architecture Overview — Eviden KMS

**Analysis date**: 2026-11-14
**Scope**: Full repository (`Cosmian/kms`), branch `rbac_rego`, commit `17926f40b` (pull request #998, workspace version 5.29.0), including the `authentication/` submodule (pinned at `012d661`) and the CI/CD, packaging and dependency surface
**Analyst**: AI Threat Model Analyst

## System Description

Eviden KMS (Cosmian KMS) is a source-available key management system written in Rust and built for FIPS 140-3 deployments. It stores and operates on cryptographic objects (symmetric keys, key pairs, certificates, secret data, split keys) and serves them over KMIP 2.1 and 1.4 (JSON and binary TTLV over HTTPS, plus a dedicated mutual-TLS socket). It also exposes cloud key-custody protocols (Google CSE, AWS XKS, Azure EKM, Microsoft DKE), a PKI surface (EST, SCEP, OCSP, CRL), JOSE and tokenization APIs, and a Vault and SPIRE compatible transit API.

The users are security administrators (Web UI and `ckms` CLI), applications that delegate cryptography (PKCS#11, Windows CNG, the Kubernetes KMS v2 plugin, the Secrets Store CSI provider and the `KMSSecret` operator), and cloud services that call the KMS to unwrap data-encryption keys. The branch under review adds an OPA and Rego authorization layer in front of object retrieval and an external Authentication Server (the `authentication/` submodule, which hosts the Auth Verifier service) that issues and verifies session tokens.

## Component Inventory

| Component | Location | Purpose | Trust Level |
|-----------|----------|---------|-------------|
| HTTP listener and app-wide middleware | `crate/server/src/start_kms_server.rs`, `crate/server/src/tls_config.rs` | OpenSSL TLS termination (client certificate optional), cookie session and identity middleware, security headers, optional per-IP rate limiter, scope and route wiring | Untrusted boundary |
| Native authentication stack | `crate/server/src/middlewares/` (`ensure_auth.rs`, `tls_auth.rs`, `jwt/`, `auth_verifier/`, `api_token/`, `session_auth.rs`, `spire_token.rs`) | Turns a Vault or SPIRE token, client certificate, IdP JWT, Auth Verifier token, API token or UI session cookie into a `UserId`; any one valid method authenticates | Semi-trusted |
| UI backend for frontend | `crate/server/src/routes/ui_auth.rs` | OIDC code flow with PKCE, SAML and SVID login, sealed `auth_session` cookie | Semi-trusted |
| Audit pipeline | `crate/server/src/middlewares/audit/`, `crate/server/src/core/audit/`, `crate/access/src/audit/` | Opt-in audit trail (file sink, hash chain) | Trusted |
| KMIP HTTP routes | `crate/server/src/routes/kmip/` | JSON and binary TTLV handlers, identity extraction, OPA scope creation | Untrusted input |
| KMIP socket server | `crate/server/src/socket_server.rs` | Binary TTLV over mutually authenticated TLS, one thread per connection, 256 MiB process-wide byte budget | Untrusted input, mTLS identity |
| KMIP dispatcher and operations | `crate/server/src/core/operations/` (`dispatch.rs`, `message.rs`, one file per operation) | Role gate, Create gate, algorithm policy, operation logic | Trusted |
| KMS core and authorization | `crate/server/src/core/kms/` (`mod.rs`, `permissions.rs`), `crate/server/src/core/retrieve_object_utils.rs`, `crate/access/src/access.rs` | Owner and grant checks, Crypto Officer and ceremony logic, HSM routing | Trusted |
| OPA client | `crate/server/src/core/opa/` | Optional Rego decision per object retrieval (fail-closed, 5 s timeout, no authentication or TLS); policy sample in `test_data/opa/kms.rego` | Semi-trusted (external) |
| Google CSE routes | `crate/server/src/routes/google_cse/` | Workspace client-side encryption: wrap, unwrap, privileged unwrap, rewrap, JWT validation in handlers | Separate trust domain |
| AWS XKS routes | `crate/server/src/routes/aws_xks/` | External key store with a static SigV4 key | Separate trust domain |
| Azure EKM routes | `crate/server/src/routes/azure_ekm/` | External key manager, mTLS only | Separate trust domain |
| Microsoft DKE routes | `crate/server/src/routes/ms_dke/` | Double key encryption endpoints behind the auth stack | Separate trust domain |
| PKI routes | `crate/server/src/routes/{est,scep,ocsp,crl,csr,enrollment}*` | Certificate enrolment, revocation status, CRL generation and fetching | Untrusted input |
| SPIRE and Vault compatible routes | `crate/server/src/routes/spire/` | Transit and PKI sign-intermediate APIs, auth proxy to the Auth Verifier | Semi-trusted |
| JOSE and tokenization routes | `crate/server/src/routes/jose/`, `crate/server/src/routes/tokenize/` | JWE and JWS operations, format-preserving tokenization | Untrusted input |
| Crypto layer | `crate/crypto/` (`build.rs` builds OpenSSL 3.6.5) | Algorithms, key generation, FPE, split keys; FIPS builds load only the FIPS provider | Trusted |
| Database backends | `crate/server_database/src/` | SQLite, PostgreSQL, MySQL and Redis-findex stores for objects, permissions, ceremony state | Trusted (local or network) |
| HSM abstraction and vendor loaders | `crate/interfaces/src/hsm/`, `crate/hsm/` (`base_hsm`, `softhsm2`, `utimaco`, `proteccio`, `crypt2pay`, `smartcardhsm`, `luna`, `kryoptic`, `aws_cloudhsm`, `azure_cloud_hsm`, `gcp_cloud_hsm`) | PKCS#11 key operations on hardware or cloud HSMs | Trusted (external) |
| Authentication Server and Auth Verifier | `authentication/` (git submodule) | Login, sessions, JWKS publication, SAML, admin UI; the KMS accepts its session tokens as bearer credentials | Semi-trusted (separate service) |
| Web UI | `ui/src/` | React single-page application served under `/ui`, WASM client in the browser | Untrusted (browser) |
| CLI and client libraries | `crate/clients/{ckms,clap,client,client_utils,wasm}` | `ckms` commands, HTTP client, login and token persistence | Semi-trusted (user host) |
| PKCS#11 module and Windows CNG provider | `crate/clients/pkcs11/{module,provider}`, `crate/clients/cng` | Exposes KMS keys to local applications | Semi-trusted (user host) |
| Kubernetes integrations | `crate/clients/k8s/{plugin,csi_provider,operator}` | KMS v2 encryption plugin, Secrets Store CSI provider, `KMSSecret` operator | Semi-trusted (cluster) |
| Packaging and deployment | `pkg/`, `nix/`, `charts/cosmian-kms/`, `resources/` | Systemd unit, default `kms.toml`, Docker images, Helm chart | Trusted (operator) |
| Build and release pipeline | `.github/workflows/`, `.mise/`, `crate/crypto/build.rs` | CI, packaging, signing, publishing, documentation generation | Trusted (supply chain) |
| Supply-chain controls | `deny.toml`, `.cargo/audit.toml`, `supply-chain/`, `sbom/`, `cbom/` | Advisory ignores, cargo-vet exemptions, SBOM, VEX, CBOM | Trusted (supply chain) |

## Asset Inventory

| Asset | Location | Sensitivity | Protection |
|-------|----------|-------------|-----------|
| Managed key material (symmetric keys, private keys, secret data) | Database rows, optionally wrapped by an at-rest key-encryption key; HSM-resident keys | CRITICAL | Owner and grant checks, `Extractable` and `Sensitive` attributes, optional OPA decision, optional at-rest KEK, HSM boundary |
| KMIP object attributes, links and access grants | Database | HIGH | Owner and grant checks; rows are not authenticated against tampering by the database administrator |
| Crypto Officer configuration, ceremony state and sealing key | Server configuration, database | HIGH | Role gate, optional ceremony; sealing key is an ordinary database key loaded at startup |
| Identity-provider trust anchors (JWKS, client CA bundle, SPIRE bundle) | Server configuration, remote endpoints | CRITICAL | Per-issuer JWKS managers, algorithm allow-list, issuer and expiry checks |
| Session key and `auth_session` cookies | Process memory, or derived from the public URL and `ui_session_salt`; browser | HIGH | HttpOnly, SameSite Lax, encrypted and signed cookie; no server-side session state |
| API token key | Database (symmetric key read per request) | HIGH | Constant-time comparison |
| Cloud-provider secrets (XKS SigV4 secret, CSE AES key, CSE RSA migration key) | Server configuration | CRITICAL | Process memory, configuration file permissions; some are printed or logged (see findings) |
| TLS private key, DB credentials, HSM slot passwords, OIDC client secrets | Server configuration and environment | CRITICAL | File and environment permissions; partial log masking |
| JOSE content-encryption keys | In-process unwrap cache | HIGH | Authorization precedes cache use |
| OPA policy (Rego) and its decision channel | OPA server, network | HIGH | Fail-closed on error; no authentication or TLS on the client side |
| Audit log | File sink on the server | MEDIUM | Opt-in; hash chain without a key; bounded queue may drop events |
| Client configuration and exports (`ckms.toml`, exported keys, PKCS#12 files) | User host | HIGH | Operating-system file permissions (default umask on several writers) |
| Release credentials (repository PAT, crates.io token, GPG key, cosign identity) | GitHub secrets, CI runners | CRITICAL | Pinned actions, fork pull requests get no secrets; see supply-chain findings |
| Source, lock files and build artifacts | Git repository, release pages, registries | CRITICAL | Full-SHA action pinning, crates.io-only lock file, SHA-256 pinned OpenSSL, signed packages and images |

## Trust Boundary Summary

| ID | Boundary | What crosses it | Controls today |
|----|----------|-----------------|----------------|
| TB1 | Network edge to the HTTPS listener | Every HTTP request, optional client certificate | TLS, optional client certificate, 64 MiB body limit, request-head timeout; rate limiter off by default |
| TB2 | Network edge to the KMIP socket server | Binary TTLV frames with a mandatory client certificate | Mutual TLS, certificate CN checks, connection and byte budgets; no OPA scope and no audit |
| TB3 | Credential to identity (native authentication stack) | Tokens, cookies, certificates mapped to a `UserId` | Method precedence, reserved-identity rejection, per-method validation; fail-open to `default_username` when no method is configured |
| TB4 | Identity to authorization | `UserId`, roles and domain claims into the dispatcher and the core | Role gate (only when a Crypto Officer exists), Create gate, algorithm policy, owner and grant checks; flat identity namespace |
| TB5 | KMS core to OPA | Retrieval decision input (operation, object, roles, domain) | Fail-closed, 5 s timeout, no redirects; no authentication, no TLS |
| TB6 | KMS core to the database | Key blobs, attributes, permissions, ceremony rows | Database TLS options, optional at-rest KEK; no per-row authentication |
| TB7 | KMS core to the HSM | PKCS#11 calls, slot passwords | Admin-gated key creation, no software fallback; keys created extractable by default |
| TB8 | KMS to identity infrastructure | JWKS and token endpoints, Authentication Server liveness and login calls, SPIRE and Vault `lookup-self` | Timeouts and caches on most paths; some clients have no timeout or redirect policy |
| TB9 | Cloud service to provider routes | Google bearer JWTs, AWS SigV4 requests, Azure client certificates, DKE tokens | Per-provider validation; permissive CORS on three of them; no audit |
| TB10 | KMS to outbound networks | CRL distribution point fetches, source KACLS calls | Private-range blocklist, pinned DNS and no redirects for KACLS; CRL fetch has no DNS resolution and unbounded body |
| TB11 | Kubernetes tenants to cluster components to KMS | Custom resources, SecretProviderClass, KMS v2 key identifiers | One global KMS identity per component; no per-tenant binding |
| TB12 | User host to KMS | `ckms.toml`, exported key files, PKCS#11 and CNG calls | File modes and attributes advertised by the module differ from what is enforced |
| TB13 | Source to CI runners to released artifacts | Secrets, third-party tools, signing keys, packages and images | Full-SHA action pinning, no `pull_request_target`, signed artifacts; long-lived tokens persist in some jobs |

## Authorization Layers (shipped behaviour)

| Layer | Where | Applies to | Default |
|-------|-------|-----------|---------|
| Authentication | `crate/server/src/middlewares/` | Default scope, `/v1/crypto`, `/tokenize`, UI session; separate rules per cloud scope | Optional; no method configured means every caller is `default_username` (`admin`) |
| Role gate | `crate/server/src/core/operations/dispatch.rs`, `message.rs`, `crate/access/src/access.rs` | Every KMIP operation, including each batch item | Skipped entirely when no Crypto Officer is configured |
| Create gate | `crate/server/src/core/kms/permissions.rs` | Operations that create objects | Default user is allowed |
| Algorithm policy | `crate/server/src/core/operations/dispatch.rs` | Create, encrypt and related operations | Opt-in (`kmip.policy_id` defaults to none) |
| Owner and grant check | `crate/server/src/core/retrieve_object_utils.rs` | Object retrieval and most operations | Always on; a `Get` grant implies several other operations |
| OPA decision | `crate/server/src/core/opa/` | Retrieval-based operations on the KMIP HTTP path | Mode-dependent; not consulted on the socket server or on non-KMIP routes |

## Runtime Properties That Shape the Threat Model

| Property | Value | Evidence |
|----------|-------|----------|
| Process model | One OS thread per actix worker (default: number of cores), each with a single-threaded runtime; connections are pinned to a worker | `crate/server/src/start_kms_server.rs` (worker count, lines 1936-1947) |
| Failure mode | `panic = "abort"` in release and dev profiles; arithmetic overflow checks on | `Cargo.toml` lines 179 and 203 |
| Execution budget | No per-request deadline or concurrency limit; only idle and request-head timeouts; global 64 MiB body limit | `crate/server/src/start_kms_server.rs` lines 1405-1410 and 1922-1930 |
| Cryptographic provider | FIPS builds load only the OpenSSL FIPS provider and abort at startup if it fails to load | `crate/server/src/openssl_providers.rs` line 419, `crate/server/src/main.rs` lines 225-226 |
| Randomness | Every random byte is drawn through `KmsRng` | `crate/crypto/src/` |
| Audit | Off by default; wired on only two scopes | `crate/server/src/start_kms_server.rs` lines 1858 and 1888 |
| Default identity | `default_username` defaults to `admin` | `crate/server/src/config/command_line/clap_config.rs` line 60, `crate/server/src/middlewares/ensure_auth.rs` lines 58-59 |
| Shipped defaults | The packaged `kms.toml` binds the HTTP server to `0.0.0.0:9998`, serves plain HTTP unless a TLS section is configured and, with no authentication method configured, serves every request as `admin`; a startup warning is logged but the server still starts | `pkg/kms.toml` lines 2 and 186-191, `crate/server/src/middlewares/ensure_auth.rs` lines 50-59, `crate/server/src/start_kms_server.rs` lines 1111-1118 |
| Systemd unit | Runs as root with `ProtectSystem=strict` and `NoNewPrivileges=yes` | `pkg/cosmian_kms.service` lines 8, 23, 99 |

*Generated by AI Threat Model Analyst. All findings require human review before remediation.*
