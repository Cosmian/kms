# STRIDE-A Analysis — Eviden KMS

**Analysis date**: 2026-11-14
**Scope**: Full repository, branch `rbac_rego` at commit `17926f40b` (PR #998, workspace version 5.29.0), including the `authentication/` submodule
**Analyst**: AI Threat Model Analyst

**Reading guide.** Threats T-001 to T-051 correspond one to one to findings F-001 to F-051 of `3-findings.md`; the Status column gives the finding ID, and the finding card holds the full analysis, the CVSS 4.0 vector and the proposed fix. Threats T-052 onward are controls that were checked and produced no finding. Threat IDs are grouped by component, not ranked; the Narrative index near the end ranks the CRITICAL and HIGH threats.

Status values:

- `Open` — traced statically in the source, not executed.
- `Reproduced locally` — measured on a local scratch server (F-042 and F-051 only).
- `Open (hypothesis)` — F-022 only: the code path is real, the privileged identity collision was not demonstrated.
- `No evidence — control verified` — a control checked at the cited lines that showed no weakness; a note names any residual finding.

In the CVSS column the first figure is the CVSS 4.0 base score. `†` marks a rated severity that is capped below the band of the base score, and `‡` marks one that is raised above it. The reasons are in the Adjustments register of `0-assessment.md` and in the Rating basis row of each card. The STRIDE-A categories are Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege and Abuse.

## Analysis Matrix

### Group 1 — Authentication and identity (TB1, TB3, TB4, TB8)

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-001 | Server defaults and authentication fallback | Elevation of Privilege | Shipped defaults serve plain HTTP on `0.0.0.0` and treat every request as the admin user | `crate/server/src/middlewares/ensure_auth.rs:41-59`; `pkg/kms.toml:2,186,191` | 9.2 base, rated HIGH † | CWE-1188 | Open — F-003 |
| T-002 | Authentication server — session management API | Elevation of Privilege | Auth Verifier `/sessions` API has no owner or realm authorisation (session-JWT theft, revocation bypass, mass logout) | `authentication/server/src/server/auth_verifier.rs:539-552` | 9.3 CRITICAL | CWE-862 | Open — F-001 |
| T-003 | Authentication server — bootstrap administrator | Spoofing | Auth Verifier ships a default super-admin (`admin` / `change_me`) that the KMS accepts on its bearer path | `authentication/server/src/database/trait.rs:72-141` | 8.9 HIGH | CWE-1392 | Open — F-004 |
| T-004 | Auth Verifier login rate limiter and KMS Web UI login relay | Denial of Service | Auth Verifier login rate limiter is keyed on the connection IP | `authentication/server/src/middleware/login_rate_limit.rs:112-119` | 6.3 MEDIUM | CWE-307 | Open — F-020 |
| T-005 | Auth Verifier token validation | Denial of Service, Spoofing | Auth Verifier JWKS is refetched only when the cache is empty | `crate/server/src/middlewares/auth_verifier/token.rs:214-220` | 2.3 LOW | CWE-324 | Open — F-036 |
| T-006 | JWT authentication middleware | Spoofing, Elevation of Privilege | User identity is the unverified `email` claim | `crate/server/src/middlewares/jwt/jwt_token_auth.rs:144-166` | 7.6 base, rated MEDIUM † | CWE-290 | Open — F-014 |
| T-007 | Identity mapping (mTLS, JWT, Auth Verifier) | Spoofing, Elevation of Privilege | `default_username` collision: an identity equal to the admin name inherits its privileges (hypothesis) | `crate/server/src/middlewares/tls_auth.rs:203-212` | 6.0 MEDIUM | CWE-290 | Open (hypothesis) — F-022 |
| T-008 | TLS and mTLS client authentication (HTTPS listener and KMIP socket server) | Spoofing, Repudiation | No CRL or OCSP revocation checking on mTLS client certificates | `crate/server/src/tls_config.rs:208-218`; `crate/server/src/socket_server.rs:623` | 7.6 base, rated MEDIUM † | CWE-299 | Open — F-015 |
| T-009 | Web UI backend-for-frontend | Spoofing | BFF OIDC callback does not require the `iss` and `aud` claims to be present in the ID token | `crate/server/src/routes/ui_auth.rs:67-71,338-341` | n/a (INFO) | CWE-287 | Open — F-046 |
| T-010 | Web UI backend-for-frontend session | Spoofing, Repudiation, Elevation of Privilege | UI session cookie is stateless and irrevocable; TTL not enforced server-side | `crate/server/src/start_kms_server.rs:1393-1400,721-752` | 6.0 MEDIUM | CWE-613 | Open — F-024 |
| T-011 | Web UI session key derivation | Spoofing, Information Disclosure | Session-key KDF uses the public URL as the password (offline test via an anonymous cookie) | `crate/server/src/start_kms_server.rs:947,955-958,727-748` | 9.1 base, rated LOW † | CWE-331 | Open — F-033 |
| T-012 | Outbound authentication clients | Denial of Service, Spoofing | Vault-token and login clients have no timeout or redirect policy and accept `http://` | `crate/server/src/routes/ui_auth.rs:498-500,852-853` | 6.3 base, rated LOW † | CWE-400 | Open — F-034 |

### Group 2 — Authorization and KMIP operations (TB2, TB4, TB5)

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-013 | KMIP operations — split key | Information Disclosure | CreateSplitKey and JoinSplitKey export a non-extractable or sensitive key in plaintext | `crate/server/src/core/operations/create_split_key.rs:71,129,373,566-587` | 7.1 HIGH | CWE-424 | Open — F-008 |
| T-014 | Access control — role gate | Elevation of Privilege, Abuse | DeriveKey creates objects outside the Create permission gate | `crate/access/src/access.rs:147,161-168` | 2.3 LOW | CWE-862 | Open — F-037 |
| T-015 | KMIP operations — usage limits and Undo | Tampering, Abuse | UsageLimits bypass through batch Undo and non-atomic read-modify-write | `crate/server/src/core/operations/batch_undo.rs:91,116-122,355-362` | 5.3 MEDIUM | CWE-841 | Open — F-031 |
| T-016 | KMIP wrapping | Information Disclosure | Existence and state oracle on wrap and unwrap key lookup | `crate/server/src/core/wrapping/unwrap.rs:188-281` | 2.3 LOW | CWE-200 | Open — F-039 |
| T-017 | JOSE and SPIRE transit routes | Elevation of Privilege, Tampering | `kmip.policy_id` is not enforced at JOSE and SPIRE transit entry points | `crate/server/src/routes/jose/keys.rs:324-327,370`; `crate/server/src/core/operations/dispatch.rs:218-220` | 2.3 LOW | CWE-693 | Open — F-038 |
| T-018 | OPA integration | Elevation of Privilege | OPA roles and domain are not established on non-KMIP routes | `crate/server/src/core/opa/context.rs:35-36` | n/a (INFO) | CWE-863 | Open — F-049 |
| T-019 | KMIP operations — DeriveKey, RSA key generation, FPE | Denial of Service | Unbounded work in DeriveKey, RSA key generation and FPE pins a worker thread | `crate/server/src/core/operations/derive_key.rs:63,249-251,338-344` | 7.1 HIGH | CWE-770 | Open — F-009 |
| T-020 | KMIP operations — CreateSplitKey | Denial of Service | CreateSplitKey multiplies the key size by the part count (memory exhaustion from about 1 KB) | `crate/server/src/core/operations/create_split_key.rs:122,129` | 7.1 HIGH | CWE-770 | Open — F-010 |
| T-021 | KMIP socket server | Denial of Service | KMIP socket in-flight memory budget can be starved by a few slow mTLS clients | `crate/server/src/socket_server.rs:36,313,473-476,537` | 2.3 LOW | CWE-400 | Open — F-040 |

### Group 3 — Storage, HSM boundary and rotation (TB6, TB7)

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-022 | Database layer — MySQL backend | Spoofing | MySQL `ssl-ca` adds to the system trust store instead of pinning the CA | `crate/server_database/src/stores/sql/mysql.rs:152-170` | 7.6 HIGH | CWE-295 | Open — F-007 |
| T-023 | Database layer — at-rest integrity | Tampering, Information Disclosure | Database rows and ceremony records are unauthenticated (no AAD binding) | `crate/server_database/src/ceremony_keys.rs:105,135` | 5.9 MEDIUM | CWE-353 | Open — F-027 |
| T-024 | Database layer and CRL generation | Tampering, Denial of Service | Backend errors collapse to empty results; fail-open CRL generation | `crate/server_database/src/core/database_objects.rs:497,541,610,625,677` | 6.3 MEDIUM | CWE-755 | Open — F-019 |
| T-025 | Auto-rotation scheduler and SQL object store | Denial of Service | Unbounded `RotateInterval` or `RotateOffset` crash-loops the server once auto-rotation is enabled | `crate/server_database/src/stores/sql/locate_query.rs:710-728` | 6.0 MEDIUM | CWE-1284 | Reproduced locally — F-051 |
| T-026 | HSM boundary — key creation | Information Disclosure | HSM keys are created extractable and non-sensitive, contradicting the documentation | `crate/interfaces/src/hsm/hsm_store.rs:346,390` | 6.0 base, rated HIGH ‡ | CWE-1188 | Open — F-011 |

### Group 4 — PKI (TB1, TB10)

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-027 | PKI — CRL generation | Denial of Service, Tampering, Repudiation | Unbounded `validity_days` aborts the whole server and lets a CRL carry a far-future `nextUpdate` | `crate/server/src/core/operations/generate_crl.rs:360-362,397`; `crate/server/src/routes/crl.rs:23-24,48-101` | 7.1 HIGH | CWE-1284 | Reproduced locally — F-042 |
| T-028 | PKI — OCSP responder | Denial of Service | Unauthenticated OCSP responder amplifies CPU and database work (opt-in feature) | `crate/server/src/routes/ocsp/handler.rs:341` | 8.2 HIGH | CWE-400 | Open — F-006 |
| T-029 | KMIP Validate — CRL retrieval | Denial of Service | CRL fetch buffers the response before the size cap; CRL cache is unbounded | `crate/server/src/core/operations/validate.rs:595,769-795` | 6.0 MEDIUM | CWE-770 | Open — F-025 |
| T-030 | Certificate validation — CRL fetch | Information Disclosure, Elevation of Privilege | CRL distribution-point SSRF guard checks IP literals only | `crate/server/src/core/certificate/mod.rs:12-13,27,47,83,99` | 5.3 MEDIUM | CWE-918 | Open — F-032 |
| T-031 | KMIP Import — certificate validation | Tampering, Denial of Service | Import marks an Active certificate Compromised on any CRL fetch error | `crate/server/src/core/operations/import.rs:115,130,137-150` | 2.1 LOW | CWE-754 | Open — F-041 |
| T-032 | PKI — EST and SCEP enrolment | Spoofing, Elevation of Privilege | EST first-enrolment and SCEP trust model is coarse (documented design) | `crate/server/src/config/command_line/est_config.rs:50-59` | n/a (INFO) | CWE-285 | Open — F-050 |

### Group 5 — Cloud provider routes (TB9)

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-033 | Google CSE routes (`/google_cse`) | Information Disclosure | Google CSE `privilegedunwrap` returns the DEK to any IdP-authenticated caller | `crate/server/src/routes/google_cse/operations.rs:756-806,1175-1230` | 8.2 base, rated CRITICAL ‡ | CWE-863 | Open — F-002 |
| T-034 | AWS XKS routes (`/aws`) | Denial of Service | AWS XKS SigV4 middleware buffers the whole body before authentication, with no size cap | `crate/server/src/routes/aws_xks/sigv4_middleware.rs:168-172,208` | 8.2 HIGH | CWE-770 | Open — F-005 |
| T-035 | Cloud routes — Google CSE and Azure EKM configuration | Spoofing, Elevation of Privilege | Dangerous opt-out switches (CSE token validation, Azure EKM client authentication) are not gated behind `insecure` | `crate/server/src/config/command_line/google_cse_config.rs:20-30` | 8.3 base, rated MEDIUM † | CWE-306 | Open — F-013 |
| T-036 | MS DKE routes (`/ms_dke`) | Information Disclosure | MS DKE scope uses permissive CORS with credentials | `crate/server/src/start_kms_server.rs:1451-1476` | 6.0 MEDIUM | CWE-942 | Open — F-026 |
| T-037 | Google CSE routes and dependency policy | Information Disclosure | The Marvin (RUSTSEC-2023-0071) ignore justification is false for the CSE migration JWT | `crate/server/src/routes/google_cse/operations.rs:994-999` | 2.3 LOW | CWE-1395 | Open — F-035 |

### Group 6 — Logging, errors and local files

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-038 | Server start-up logging | Information Disclosure | Secrets printed in info-level startup logs | `crate/server/src/start_kms_server.rs:573` | 6.7 MEDIUM | CWE-532 | Open — F-018 |
| T-039 | HTTP error responses | Information Disclosure | Raw internal error text returned in 5xx bodies (regression of COSMIAN-2026-013) | `crate/server/src/routes/mod.rs:98-113` | 5.3 MEDIUM | CWE-209 | Open — F-029 |
| T-040 | Audit subsystem | Repudiation | Audit logging is opt-in and covers only two production call sites | `crate/server/src/start_kms_server.rs:1858,1888` | 5.3 MEDIUM | CWE-778 | Open — F-030 |
| T-041 | Clients — `ckms` CLI file output | Information Disclosure | `ckms.toml`, exported keys and decrypt outputs are written with the default umask | `crate/clients/ckms/src/config.rs:57,65` | 5.7 MEDIUM | CWE-276 | Open — F-028 |

### Group 7 — Clients (TB11, TB12)

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-042 | Kubernetes operator (`KMSSecret` controller) | Elevation of Privilege, Tampering, Information Disclosure | Kubernetes operator is a confused deputy for KMSSecret tenants | `crate/clients/k8s/operator/src/controller.rs:41,102,168-172` | 6.1 MEDIUM | CWE-441 | Open — F-021 |
| T-043 | Clients — Kubernetes CSI provider | Elevation of Privilege, Information Disclosure | CSI provider is a confused deputy: any pod can request any readable KMS object | `crate/clients/k8s/csi_provider/src/service.rs:128,156` | 6.0 MEDIUM | CWE-441 | Open — F-023 |
| T-044 | Clients — Kubernetes KMS provider plugin | Elevation of Privilege, Information Disclosure | Kubernetes KMS v2 plugin decrypts under a caller-supplied `key_id` | `crate/clients/k8s/plugin/src/service.rs:134-140` | 1.8 LOW | CWE-639 | Open — F-044 |
| T-045 | Clients — Windows CNG key storage provider | Information Disclosure, Elevation of Privilege | Windows CNG key storage provider makes every key plaintext-exportable | `crate/clients/cng/src/provider.rs:354-357,1059-1060` | 6.8 MEDIUM | CWE-693 | Open — F-017 |
| T-046 | Clients — PKCS#11 module | Information Disclosure | PKCS#11 module advertises keys as non-extractable but serves `CKA_VALUE` | `crate/clients/pkcs11/module/src/core/object.rs:150-151,201-213,249-301` | 2.0 LOW | CWE-693 | Open — F-043 |
| T-047 | Clients — ckms CLI | Tampering, Information Disclosure | `ckms login` and `logout` persist one-off overrides into `ckms.toml` | `crate/clients/ckms/src/commands.rs:185-186,208-211` | 2.1 LOW | CWE-295 | Open — F-045 |

### Group 8 — Supply chain (TB13)

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-048 | CI/CD — release and publish workflows | Tampering, Elevation of Privilege, Information Disclosure | Long-lived PAT and crates.io token exposed to workflows that run third-party code | `.github/workflows/release.yml:32,103,281` | 9.1 base, rated MEDIUM † | CWE-522 | Open — F-012 |
| T-049 | CI/CD — self-hosted runners | Elevation of Privilege, Tampering | Self-hosted runner host SSH key mounted into a mutable root container (8 jobs) | `.github/workflows/packaging.yml:114-118,225-229,302-306` | 7.0 base, rated MEDIUM † | CWE-522 | Open — F-016 |
| T-050 | Repository hygiene (Auth Verifier submodule) | Information Disclosure | A database file and 20 test certificate and key files are tracked in the Auth Verifier submodule | `authentication/auth_verifier.db`; `authentication/server/src/tests/certificates/ec/`; `authentication/server/src/tests/certificates/rsa/` | n/a (INFO) | CWE-540 | Open — F-047 |
| T-051 | Dependencies | Denial of Service, Information Disclosure | Advisories for quinn-proto, quinn-udp and rustix in `Cargo.lock`, none reachable, none in the VEX | `Cargo.lock`; `.cargo/audit.toml`; `sbom/openvex.json` | n/a (INFO) | CWE-1395 | Open — F-048 |

### Group 9 — Controls verified (no evidence of a threat)

Each row below was checked at the cited lines and held. They are listed so that a reader can tell a control that was examined from an area that was never looked at. Where a control is only partial, the Status column names the finding that covers the remainder.

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-052 | TLS and mTLS client authentication | Spoofing | TLS session resumption is disabled for client-certificate acceptors (session cache off, tickets off), so a client identity cannot outlive its handshake | `crate/server/src/tls_config.rs:223-224,234-251`; `crate/server/src/socket_server.rs:625` | n/a | CWE-294 | No evidence — control verified |
| T-053 | API token and XKS access key checks | Spoofing | The API token and the XKS access key are compared in constant time | `crate/server/src/middlewares/api_token/api_token_auth.rs:19,88`; `crate/server/src/routes/aws_xks/sigv4_middleware.rs:362` | n/a | CWE-208 | No evidence — control verified |
| T-054 | Web UI OIDC login flow | Spoofing | The UI login uses PKCE, a per-login `state` checked on the callback, a nonce and session renewal after login | `crate/server/src/routes/ui_auth.rs:36,43-58,97-105,124-131,172-194` | n/a | CWE-384, CWE-352 | No evidence — control verified |
| T-055 | mTLS identity extraction | Spoofing | Wildcard and reserved common names are rejected as mTLS identities | `crate/server/src/middlewares/tls_auth.rs:166,205` | n/a | CWE-290 | No evidence — control verified |
| T-056 | Auth Verifier and JWT identity extraction | Spoofing | Reserved service identities cannot be claimed through a bearer token | `crate/server/src/middlewares/auth_verifier/token.rs:123,170`; `crate/server/src/middlewares/jwt/jwt_token_auth.rs:96,114` | n/a | CWE-290 | No evidence — control verified |
| T-057 | Auth Verifier session-liveness cache | Spoofing | The session-liveness cache is bounded (30 s lifetime, 100,000 entries) and fails closed on a network error or a non-success status | `crate/server/src/middlewares/auth_verifier/session.rs:28,31,90-121` | n/a | CWE-613 | No evidence — control verified |
| T-058 | JWT bearer authentication | Spoofing | The bearer path requires the standard claims to be present before validating them | `crate/server/src/middlewares/jwt/jwt_config.rs:330-350` | n/a | CWE-287 | No evidence — control verified; residual risk in F-046 (the UI callback path) |
| T-059 | EST and SCEP enrolment | Spoofing | Certificates issued through EST or SCEP cannot authenticate as KMS users, and repeated enrolment failures lock the caller out with a doubling delay | `crate/server/src/middlewares/tls_auth.rs:181-190`; `crate/server/src/routes/enrollment_guard.rs:24-48` | n/a | CWE-307 | No evidence — control verified; residual risk in F-050 |
| T-060 | KMIP binary (TTLV) parser | Denial of Service | The binary TTLV parser bounds nesting depth (64), field size (64 MiB) and item count (100,000), and a batch is limited to 10,000 items | `crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs:29,40,46`; `crate/server/src/core/operations/message.rs:35` | n/a | CWE-770 | No evidence — control verified |
| T-061 | AWS XKS SigV4 verification | Denial of Service | SigV4 signature verification is gated by a CPU semaphore sized to the core count and by a 5-minute freshness window | `crate/server/src/routes/aws_xks/sigv4_middleware.rs:52-58,212-226` | n/a | CWE-770 | No evidence — control verified; residual risk in F-005 (the body is buffered before the permit) |
| T-062 | CRL signing | Tampering | CRL signing refuses a CA certificate that lacks the `cRLSign` key usage | `crate/server/src/core/operations/generate_crl.rs:269-289` | n/a | CWE-295 | No evidence — control verified |
| T-063 | OpenSSL build script | Tampering | The OpenSSL source tarball is verified against a pinned SHA-256 before it is built | `crate/crypto/build.rs:10,20,92,126,271-273` | n/a | CWE-494 | No evidence — control verified |
| T-064 | Symmetric ciphers | Tampering | A minimum GCM authentication-tag length is enforced | `crate/crypto/src/crypto/symmetric/symmetric_ciphers.rs:263-283,770` | n/a | CWE-326 | No evidence — control verified |
| T-065 | RSA encryption | Information Disclosure | The PKCS#1 v1.5 encryption module is compiled only in non-FIPS builds | `crate/crypto/src/crypto/rsa/mod.rs:9-10` | n/a | CWE-327 | No evidence — control verified; PKCS#1 v1.5 signatures remain in FIPS builds (permitted by FIPS 186-5), see the conditional note R-08 |
| T-066 | OpenSSL provider initialisation | Information Disclosure | FIPS builds load only the FIPS provider | `crate/server/src/openssl_providers.rs:417-421` | n/a | CWE-327 | No evidence — control verified |
| T-067 | JOSE decrypt route | Information Disclosure | JOSE decrypt authorises the caller before consulting the CEK cache, rejects unsupported algorithms and enforces a 2048-bit RSA minimum | `crate/server/src/routes/jose/decrypt.rs:264-274,327-343`; `crate/server/src/routes/jose/algorithm.rs:217-218,283`; `crate/server/src/routes/jose/keys.rs:324-330` | n/a | CWE-863 | No evidence — control verified; residual risk in F-038 |
| T-068 | KMIP CreateSplitKey | Information Disclosure | CreateSplitKey refuses HSM-backed source keys | `crate/server/src/core/operations/create_split_key.rs:105-109` | n/a | CWE-200 | No evidence — control verified; residual risk in F-008 (software keys) |
| T-069 | HSM object access | Elevation of Privilege | HSM object creation is reserved to the HSM administrator, and HSM listing and access are gated | `crate/interfaces/src/hsm/hsm_store.rs:143-146,297,461`; `crate/server/src/core/operations/locate.rs:83-94`; `crate/server/src/core/retrieve_object_utils.rs:457-466` | n/a | CWE-862 | No evidence — control verified; residual risk in F-011 (the extractable default) |
| T-070 | CRL distribution-point fetch | Information Disclosure | The CRL fetch applies the SSRF controls added for COSMIAN-2026-021 (IP literal and internal name checks, no redirects, timeout) | `crate/server/src/core/certificate/mod.rs:12-13,19-30,39-47` | n/a | CWE-918 | No evidence — control verified; residual risk in F-032 (DNS names are not resolved) |
| T-071 | Google CSE rewrap | Elevation of Privilege | The CSE rewrap SSRF guard blocks IP literals, resolves the host name, pins the first resolved address and disables redirects | `crate/server/src/routes/google_cse/operations.rs:76-100` | n/a | CWE-918 | No evidence — control verified |
| T-072 | Azure EKM start-up | Spoofing | The server refuses to start the Azure EKM scope without client-certificate authentication unless the explicit opt-out is set | `crate/server/src/start_kms_server.rs:1233-1236` | n/a | CWE-306 | No evidence — control verified; residual risk in F-013 (the explicit opt-out) |
| T-073 | KMIP dispatcher and batch processing | Elevation of Privilege | The role gate is applied to single operations and to every batched item, and the Create permission gate is applied before object creation | `crate/server/src/core/operations/dispatch.rs:114-116,157-161,213`; `crate/server/src/core/operations/message.rs:785` | n/a | CWE-862 | No evidence — control verified; residual risk in F-037 (DeriveKey) and the gate is skipped when no Crypto Officer is configured |
| T-074 | Database layer — PostgreSQL backend | Spoofing | The PostgreSQL backend pins the configured CA instead of adding it to the system roots | `crate/server_database/src/stores/sql/pgsql.rs:96-98,164-166` | n/a | CWE-295 | No evidence — control verified (contrast F-007 for MySQL) |
| T-075 | Web UI static routes | Tampering | The UI responses carry anti-clickjacking headers (`X-Frame-Options` and a `frame-ancestors` policy) | `crate/server/src/start_kms_server.rs:1385-1390` | n/a | CWE-1021 | No evidence — control verified |
| T-076 | Packaged systemd service | Elevation of Privilege | The packaged unit applies filesystem protection, a private temporary directory, a capability bounding set and `NoNewPrivileges` | `pkg/cosmian_kms.service:23,25,50-55,99` | n/a | CWE-250 | No evidence — control verified; residual risk in F-003 (the unit still runs as root) |
| T-077 | CI/CD — GitHub Actions workflows | Tampering | Every external action reference is pinned to a full commit SHA (143 references counted, none unpinned) and no workflow is triggered by `pull_request_target` | `.github/workflows/packaging-docker.yml:61` (example of the pinning) | n/a | CWE-829 | No evidence — control verified |
| T-078 | CI/CD — container image publication | Tampering | Container images are signed with cosign keyless signing | `.github/workflows/packaging-docker.yml:19,60-61,122` | n/a | CWE-345 | No evidence — control verified |
| T-079 | Web UI dependencies | Tampering | pnpm dependency build scripts are disabled by an empty allow-list | `ui/package.json:90` | n/a | CWE-829 | No evidence — control verified |
| T-080 | OPA integration | Elevation of Privilege | The OPA client fails closed: any transport error, non-success status or unparsable answer is a denial, with a 5 s timeout and no redirects | `crate/server/src/core/opa/client.rs:1,39,42,54,64,73,79,254`; `crate/server/src/core/kms/permissions.rs:296-297` | n/a | CWE-636 | No evidence — control verified; residual risk in F-049 (no authentication or TLS towards OPA, by design) |

## Threat Narrative

Narratives are given for every CRITICAL and HIGH threat. The analysis of the MEDIUM, LOW and INFO threats is in the finding cards of `3-findings.md`. Every narrative is a static trace except T-027, whose crash was reproduced on a local debug build.

### Narrative index

| T-ID | F-ID | Severity (rated) | Threat |
| --- | --- | --- | --- |
| T-002 | F-001 | 🔴 CRITICAL | Auth Verifier `/sessions` API has no owner or realm authorisation |
| T-033 | F-002 | 🔴 CRITICAL ‡ | Google CSE `privilegedunwrap` returns the DEK to any IdP-authenticated caller |
| T-001 | F-003 | 🟠 HIGH † | Shipped defaults serve plain HTTP on `0.0.0.0` and treat every request as the admin user |
| T-003 | F-004 | 🟠 HIGH | Auth Verifier ships a default super-admin that the KMS accepts on its bearer path |
| T-034 | F-005 | 🟠 HIGH | AWS XKS SigV4 middleware buffers the whole body before authentication |
| T-028 | F-006 | 🟠 HIGH | Unauthenticated OCSP responder amplifies CPU and database work |
| T-022 | F-007 | 🟠 HIGH | MySQL `ssl-ca` adds to the system trust store instead of pinning the CA |
| T-013 | F-008 | 🟠 HIGH | CreateSplitKey and JoinSplitKey export a non-extractable or sensitive key in plaintext |
| T-027 | F-042 | 🟠 HIGH | Unbounded `validity_days` aborts the whole server |
| T-019 | F-009 | 🟠 HIGH | Unbounded work in DeriveKey, RSA key generation and FPE pins a worker thread |
| T-020 | F-010 | 🟠 HIGH | CreateSplitKey multiplies the key size by the part count |
| T-026 | F-011 | 🟠 HIGH ‡ | HSM keys are created extractable and non-sensitive |

### T-002: Auth Verifier `/sessions` API has no owner or realm authorisation (F-001)

**Attack scenario**: A holder of any valid session cookie, in any realm, calls `POST /sessions/realms/{realm}/clients` with the victim's realm id (`_` is well known), username and authentication scheme, and learns the victim's live session id. `GET /sessions/{id}` then returns the victim's signed session JWT in `cookie_string`, and the attacker presents it to the KMS as a bearer token. Signature, expiry and the liveness check all pass because the victim's session is live, so the attacker holds every permission the victim has. The same scope lets the caller re-create a revoked session with `POST /sessions`, which defeats the revocation check added for COSMIAN-2026-043, and sign out every user of a realm with `DELETE /sessions/realms/{id}` or `DELETE /sessions/expired`.

**Pre-conditions**: a valid session in any realm (a low-privilege account is enough), network reachability of the Auth Verifier, and a live victim session.

**Impact**: takeover of any Auth Verifier user, administrators included, on every KMS that accepts Auth Verifier bearer tokens; bypass of session revocation; denial of service by mass sign-out. Rated 9.3 CRITICAL (`AV:N/AC:L/AT:N/PR:L/UI:N`, high impact on the vulnerable system and on the KMS behind it).

**Evidence**: `authentication/server/src/server/auth_verifier.rs:539-552` registers the `/sessions` scope with only `CookieAuthSameServer`, `ExtractRealm` and CORS, while the sibling scopes add `AdminAuth` (`:508-509,522-523,554-555`); `authentication/server/src/middleware/cookie_auth.rs:139-162`; `authentication/server/src/server/endpoints/sessions_endpoints.rs:17,38,51,99,119,133,142` (no owner or realm check in any handler); `authentication/server/src/session/cookies.rs:12-16` (the session id is the SHA-256 of the cookie); `authentication/server/src/server/endpoints/client_endpoints.rs:132` (the session id is logged at info level) and `:138` (returned to the caller); `crate/server/src/middlewares/auth_verifier/token.rs:119-128` (the KMS maps `sub` to the user); `authentication/server/documentation/docs/authorization_and_administration.md:197-199` promises access only "if session is in an administered realm"; `authentication/server/src/tests/sessions_api.rs` has no negative test.

**Mitigations present**: `AdminAuth` protects the sibling scopes; the KMS checks session liveness against the Auth Verifier through a 30 s cache that fails closed (`crate/server/src/middlewares/auth_verifier/session.rs:28,31`), which restricts a stolen token to a live session, although `POST /sessions` can re-create a revoked one.

**Gaps**: no owner or realm check in any `/sessions` handler; `GET` returns `cookie_string`; the session id is logged at info level; no negative test; the documentation describes a restriction the code does not implement.

### T-033: Google CSE `privilegedunwrap` returns the DEK to any IdP-authenticated caller (F-002)

**Attack scenario**: Google CSE is enabled and the attacker holds a token from any identity provider configured for CSE, for example any employee's Google token. The attacker obtains a wrapped DEK blob and the exact `resource_name` it was wrapped with (the AAD), for instance from a shared document's metadata, and calls `POST /google_cse/privilegedunwrap` with the token, the blob and the resource name. The server accepts the token, runs the decrypt as the default user and returns the plaintext DEK, and the attacker decrypts the document.

**Pre-conditions**: CSE enabled (off by default: the scope is registered only when `kms_public_url` is set and `google_cse.enable` is true, `crate/server/src/start_kms_server.rs:1423-1425`), a token from a configured identity provider, and the wrapped blob with its exact resource name.

**Impact**: disclosure of the data-encryption key of any CSE-protected document the attacker can name, which defeats the purpose of client-side encryption. Rated CRITICAL by the key-escrow amplifier (key material released without the owner's consent) from a base of 8.2 HIGH; the independent verifier would have kept HIGH.

**Evidence**: `crate/server/src/start_kms_server.rs:1423-1434` (permissive CORS, no authentication middleware on the scope); `crate/server/src/routes/google_cse/jwt.rs:250` (the token is tried against every configured provider, first match wins), `:289-292` (the only privileged-specific check is that the resource is a `/drive/` one), `:312-313` (a privileged-unwrap token maps to `kms_default_username`, with no role or allow-list); `crate/server/src/middlewares/jwt/jwt_config.rs:348` (audience validation is off when none is configured); `crate/server/src/config/command_line/idp_auth_config.rs:104-111`; `crate/server/src/routes/google_cse/operations.rs:756-761,771,783-785,800-806,1175-1230`; `crate/server/src/tests/google_cse/token_validation.rs:518-550` shows an ordinary user token getting the DEK back; `SECURITY.md:1375` records that any CSE-authenticated user could invoke the route and `:1379` that access is restricted to administrative users; the documentation sample leaves the audience empty (`documentation/docs/integrations/cloud_providers/google_workspace_client_side_encryption_cse/getting_started/index.md:172`). History: #517 (5.8.0) added the audience check, #656 (`f9e80e3ed`) replaced it with a self-referential one, and #948 restored it only for whitelist configurations.

**Mitigations present**: the audience check restored for whitelist configurations (#948); the `/drive/` resource check; the JWT validation built with `Validation::new(header.alg)` and the `kid` and `crit` rejection.

**Gaps**: self-referential audience; no administrator allow-list for the privileged routes; the `resource_name` and `kacls_url` claims are not bound to the request; the documentation claims an administrator restriction that is not coded.

### T-001: Shipped defaults serve plain HTTP on `0.0.0.0` and treat every request as the admin user (F-003)

**Attack scenario**: An operator installs the deb, rpm or Docker image and starts the server without editing the default configuration, or deploys the Helm chart with default values. A host that can reach TCP port 9998 sends KMIP requests with no credentials. `ensure_auth` serves each request as `admin`, so the attacker creates keys, exports or unwraps any key the default user can reach, and administers HSM slots (the default HSM administrator is also `admin`).

**Pre-conditions**: network reachability of the port and an operator who has not configured authentication. The server logs a warning at start.

**Impact**: unauthenticated administrative access over plain HTTP to every key the default user owns or can reach. The base score is 9.2; the severity is rated HIGH because the exposure comes from a documented insecure default that the operator must change (see the Adjustments register in `0-assessment.md`).

**Evidence**: `crate/server/src/middlewares/ensure_auth.rs:41-47` lets an already-authenticated request through, `:49-55` rejects only when an authentication method is configured, and `:57-59` otherwise injects `AuthMethod::DefaultUser` with `default_username`; `pkg/kms.toml:2` sets `default_username = "admin"`, `:186-189` state that the server serves plain HTTP unless TLS is configured and set port 9998, and `:191` binds `hostname = "0.0.0.0"`; `crate/server/src/start_kms_server.rs:1111-1118` emits only a `warn!`; `pkg/cosmian_kms.service:8` runs the service as `User=root`; `nix/docker.nix:415-416` leaves the container user at root; `charts/cosmian-kms/values.yaml:144` disables the network policy and `:191,193` set `defaultUsername: admin` and `hostname: 0.0.0.0`; `documentation/docs/configuration/authentication.md:7-9` documents the fallback.

**Mitigations present**: the start-up warning; the unit's `ProtectSystem=strict` (`pkg/cosmian_kms.service:23`) and `NoNewPrivileges=yes` (`:99`); the package does not start the service automatically and installs the configuration with mode 0400; the fallback is documented.

**Gaps**: the default binds every interface, serves plain HTTP, runs as root and leaves the Helm network policy off; nothing refuses a non-loopback listener when no authentication is configured.

### T-003: Auth Verifier ships a default super-admin that the KMS accepts on its bearer path (F-004)

**Attack scenario**: A KMS deployment uses the Auth Verifier for authentication and the administrator has not changed the initial password (nothing forces the change). An attacker with network access to the Auth Verifier logs in as `admin` with `change_me` against realm `_` and obtains a session JWT, then sends it to the KMS as a bearer token. The KMS accepts it as user `admin`, which is the default user, so the attacker gets the privileges that identity carries: Create-gate bypass, unwrap of any key and default HSM administrator.

**Pre-conditions**: the Auth Verifier is configured as an authentication source of the KMS, the initial password is unchanged and the attacker can reach the Auth Verifier.

**Impact**: administrator-level access to the KMS. Rated 8.9 HIGH with an adjacent-network attack vector (`AV:A`), because the deb and rpm packages bind `localhost:8443`; the same vector scores 9.5 with `AV:N` and 8.8 with `AV:L`.

**Evidence**: `authentication/server/src/database/trait.rs:72-73` (the constants) and `:84-141` (`initialize_db` creates the user with `allow_expired_passwords: true` at `:92` and `change_password: true` at `:119`); `authentication/server/src/middleware/username_password.rs:155-156` (a TODO: the forced change is not enforced); `crate/server/src/middlewares/auth_verifier/token.rs:119-128` (the KMS maps `sub` to the user); `crate/server/src/config/command_line/clap_config.rs:129-130` and `crate/server/src/config/command_line/hsm_config.rs:6,103` (the default user is also the HSM administrator); `crate/server/src/config/command_line/auth_verifier_config.rs:24-29` (rejects only an empty realm list); `authentication/server/documentation/docs/server_configuration.md:337`, `authentication/server/documentation/docs/installation.md:116-130` and `documentation/docs/integrations/spire_spiffe.md:766,788` state the credentials.

**Mitigations present**: the deb and rpm packages bind `localhost:8443` (`authentication/pkg/auth_verifier.toml:22,25`); the Helm chart exposes the Auth Verifier through a ClusterIP service; the documentation states the default credentials.

**Gaps**: the forced password change is not enforced; the KMS bearer path does not check the realm although the documentation promises it; the Docker development fallback binds `0.0.0.0` (with a warning); the Helm chart has no network policy by default.

### T-034: AWS XKS SigV4 middleware buffers the whole body before authentication (F-005)

**Attack scenario**: AWS XKS is enabled (off by default) and the attacker can reach the HTTPS port. The attacker opens several connections to `/aws/...` and streams bodies of many gigabytes behind a syntactically valid request head, sending slowly to avoid any idle limit. Each connection accumulates the body in a `BytesMut` before any signature check, so the server process exhausts its memory and is killed. Every KMS route is unavailable until the service manager restarts it.

**Pre-conditions**: XKS enabled and a reachable listener. No credentials are needed.

**Impact**: unauthenticated denial of service of the whole KMS, because one process serves every route. Rated 8.2 HIGH. The cloud-route amplifier is declined because the impact is availability only and no key material is exposed; a reviewer who applies it literally would rate this CRITICAL.

**Evidence**: `crate/server/src/routes/aws_xks/sigv4_middleware.rs:168` (`req.into_parts()`), `:172` (the body is folded into a `BytesMut`), `:208-209` (the CPU permit is acquired after the read), `:56-58` (the semaphore) and stale comments at `:51,189` that assume a 64 MB cap; `crate/server/src/start_kms_server.rs:1405-1410` sets a 64 MiB `PayloadConfig`, but a raw `Payload` is not limited in actix-web 4.18.2 (dependency source `actix-web-4.18.2/src/types/payload.rs:96-101`), `:1483-1496` wires the scope (middleware at `:1488`), and `:1922-1930` shows that `client_request_timeout` (10 s) and `keep_alive` bound only the request head and the idle time; the correct pattern exists in `crate/server/src/routes/enrollment.rs:209-218` (`MAX_ENROLLMENT_BODY` and `to_bytes_limited`).

**Mitigations present**: the CPU semaphore (permits equal to the core count, acquired after buffering); the head and idle timeouts above; XKS is off by default.

**Gaps**: no size cap and no body-read timeout; the permit is taken after the buffering; a single process serves every route, so an out-of-memory kill is a total outage.

### T-028: Unauthenticated OCSP responder amplifies CPU and database work (F-006)

**Attack scenario**: An operator has enabled the OCSP responder for a CA that has issued many certificates. The attacker sends many `POST /ocsp/` requests, each with a nonce (which bypasses the response cache) and 128 `CertID`s for the maximum amplification. Each `CertID` triggers a scan and parse of every certificate issued by the CA, and the response is then signed. The workers and the database connection pool saturate, and the other KMS routes slow down or time out.

**Pre-conditions**: OCSP enabled (`ocsp_enabled` is false by default and a CA UID must be configured) and reachable. No credentials are needed. Request cost estimates were not measured.

**Impact**: unauthenticated resource exhaustion that degrades or blocks the whole KMS. Rated 8.2 HIGH; `AT:P` reflects that the responder is disabled by default and needs a configured CA.

**Evidence**: `crate/server/src/routes/ocsp/handler.rs:321-327` (the cache is used only for a single query without a nonce and with an uncompromised CA), `:341` (`for query in &queries`), `:472-478` (a one-element `HashSet` per serial) and `:117` (cache limited to 10,000 entries); `crate/server/src/core/certificate/find.rs:83-100` (`find_all` loads every certificate linked to the CA, then `retrieve_object_arc` and `X509::from_der` run for each); `crate/interfaces/src/stores/objects_store.rs:390-401` (the default implementation traverses every linked certificate and says that SQL backends should override it with an indexed query; `find_certificate_by_serial` is never implemented or called); `crate/server/src/start_kms_server.rs:1806-1808` (public routes); `crate/server/src/config/command_line/ocsp_config.rs:26-31`; `crate/crypto/src/openssl/ocsp.rs:58,214` (128 `CertID` cap), `:198` and `:386,480` (`OCSP_basic_sign`).

**Mitigations present**: the 128 `CertID` cap per request; the response cache (up to 10,000 entries, single query without a nonce only); the 4,096-byte cap on the GET path; the optional rate limiter (off by default); the responder is off by default.

**Gaps**: the indexed serial lookup is never implemented; no rate limit by default; the nonce path always bypasses the cache.

### T-022: MySQL `ssl-ca` adds to the system trust store instead of pinning the CA (F-007)

**Attack scenario**: The operator runs MySQL with a private CA and configures `ssl-mode=VERIFY_CA&ssl-ca=/etc/kms/db-ca.pem`, expecting that only this CA is accepted. An attacker on the network path between the KMS and the database (same subnet or cluster network, ARP or DNS spoofing) answers with a certificate that chains to any publicly trusted CA. With `VERIFY_CA` any such certificate is enough; with `VERIFY_IDENTITY` the certificate must also match the database host name, which is much harder for an internal name. The KMS accepts the session, sends its database credentials and reads or writes the key records through the attacker's server.

**Pre-conditions**: MySQL backend with a `VERIFY_*` mode and an on-path attacker holding a certificate signed by a system root CA. The library default comes from its source documentation; the handshake was not executed.

**Impact**: capture of the database credentials and read or tamper access to the key records, which are wrapped but not authenticated (see F-027). Rated 7.6 HIGH with `AV:A`, `AC:H` and `AT:P`; the same vector scores 9.1 with `AV:N`.

**Evidence**: `crate/server_database/src/stores/sql/mysql.rs:164-169` (in the `VERIFY_*` branch the CA file is passed to `with_root_certs`) and `:158-161` (`REQUIRED` and `PREFERRED` accept invalid certificates and skip domain validation); `mysql_async-0.37.1/src/opts/mod.rs:243-244` (dependency source: the option that restricts trust to the given roots is off by default); the correct sibling is `crate/server_database/src/stores/sql/pgsql.rs:96-98,164-166`; `documentation/docs/configuration/database/configuration.md:330` (the `ssl-ca` row) and `:370-371` (`ssl-mode`).

**Mitigations present**: the PostgreSQL backend pins the CA correctly (T-074); `VERIFY_IDENTITY` adds a host-name check.

**Gaps**: the built-in roots are never disabled for the MySQL connection (`with_disable_built_in_roots(true)` is not set); no live TLS test presents a publicly rooted certificate against a private CA.

### T-013: CreateSplitKey and JoinSplitKey export a non-extractable or sensitive key in plaintext (F-008)

**Attack scenario**: The owner creates an AES key with `Extractable=false` or `Sensitive=true` so that `Get` and `Export` never return its bytes. The attacker holds a `Get` grant on it, or owns it through a stolen low-privilege session. The attacker calls `CreateSplitKey` with `split_key_threshold` equal to `split_key_parts` (an XOR split); the server reads the raw bytes and writes the shares, which the attacker owns. The attacker then calls `JoinSplitKey` with the shares and `Get` on the reconstructed object, which carries no `Sensitive` or `Extractable` flag, and receives the key in plaintext.

**Pre-conditions**: a `Get` grant on the target key and the right to create objects (the default when no Crypto Officer is configured).

**Impact**: plaintext export of a key that the owner marked as never extractable, which voids the owner's non-export policy for every grantee. Rated 7.1 HIGH. The key-escrow amplifier is declined because the caller already holds the `Get` grant; a reviewer who reads the flags as the owner's refusal to export would apply it and rate this CRITICAL. Related advisories: GHSA-8mmx-f92q-2gq8, GHSA-c75c-3cmm-48h7 and COSMIAN-2026-045.

**Evidence**: `crate/server/src/core/operations/create_split_key.rs:68-75` (the source is retrieved with `KmipOperation::Get`), `:105-109` (only HSM keys are refused), `:129` (`extract_key_bytes_ref(owm.object())`) and `:373` (`sensitive: Some(true)` on the shares only); `crate/server/src/core/operations/join_split_key.rs:80-84` (the shares are retrieved with `Get`), `:583` (`build_reconstructed_object`) and `:626` (`..Attributes::default()`); the bypassed `check_extractable_and_sensitive` in `crate/server/src/core/operations/export_get.rs:66-107` (Extractable and NeverExtractable at `:72-73`, Sensitive at `:103`, private to that module); `crate/server/src/core/kms/permissions.rs:276-285` (the Create gate: the default user and Crypto Officers, open to all when no Crypto Officer is configured).

**Mitigations present**: `Extractable`, `NeverExtractable` and `Sensitive` are enforced on `Get` and `Export`; the shares are stamped Sensitive; HSM keys are refused (T-068); the Create gate.

**Gaps**: the source key is not checked for the flags; the reconstructed object loses them.

### T-027: Unbounded `validity_days` aborts the whole server (F-042)

**Attack scenario**: The attacker is an authenticated user. When no Crypto Officer is configured every user holds the Create right, so the attacker can create a CA certificate that carries the `cRLSign` key usage (a CA without it is refused) and owns its private key. The attacker calls `GET /certificates/<ca>/crl?validity_days=4294967295`. The CRL is built and signed, the date addition at `generate_crl.rs:397` panics, and the whole server process aborts. All tenants lose every endpoint until the service manager restarts the process (about 3 seconds with the shipped unit), and the attacker repeats the call for a sustained outage. Without a crash, `validity_days=36500` produces a CRL whose `nextUpdate` is a century away, cached and served publicly with a long `max-age`, and the refresh cron never replaces it.

**Pre-conditions**: an authenticated user with the `Get` right on the private key of a CA that carries `cRLSign` (an own CA is enough when no Crypto Officer is configured; the Crypto Officer role is also needed when Crypto Officers are configured).

**Impact**: remote denial of service of the whole KMS (every route, every tenant), repeatable after each restart, and a CRL that relying parties would keep trusting long after later revocations. Measured on a local debug build (non-FIPS, SQLite, no authentication): `validity_days` of 7, 36,500 and 2,900,000 were accepted, and 2,950,000 aborted the server with "resulting value is out of range" at `generate_crl.rs:397:23`. The effect on a relying party was not measured. Rated 7.1 HIGH (`PR:L`); with Crypto Officers configured (`PR:H`) the same vector scores 6.9 MEDIUM.

**Evidence**: `crate/server/src/routes/crl.rs:23-24` (`validity_days: Option<u32>`), `:31-38`, `:48-101` (`get_crl`) and `:196-204,226` (cache headers derived from `nextUpdate`); `crate/server/src/start_kms_server.rs:1909` (the authenticated route; the public `get_crl_public` at `:1805` serves the cached CRL only and takes no parameter); `crate/server/src/core/operations/generate_crl.rs:211-217` (Crypto Officer gate), `:166-168`, `:312-328`, `:360-362` (lower bound only), `:363-381` and `:397` (the unchecked date addition); `crate/server/src/cron.rs:118-130`; `Cargo.toml:179,203` (`panic = "abort"`); `pkg/cosmian_kms.service:10-11` (`Restart=on-failure`, `RestartSec=3s`); `charts/cosmian-kms/templates/deployment.yaml:141-142` (liveness probe). The tag `cosmian-kms-5.29.0` has the same code (static comparison), so the defect is in a released version.

**Mitigations present**: the route is authenticated; the Crypto Officer gate applies when configured; a CA without `cRLSign` is refused (T-062); the service manager restarts the process after 3 s and the Helm liveness probe restarts the pod.

**Gaps**: no upper bound on `validity_days`; the date addition is unchecked; the same class exists in the rotation scheduler (F-051, also reproduced).

### T-019: Unbounded work in DeriveKey, RSA key generation and FPE pins a worker thread (F-009)

**Attack scenario**: The attacker authenticates as any user who can hold an Active key of their own (in the default configuration no authentication is needed). The attacker sends `DeriveKey` with PBKDF2, the default 600,000 iterations and a requested length of 64 KiB or more, and the derivation runs on the worker thread that accepted the connection. Repeating the request on as many connections as the server has workers pins all of them, and the HTTP API stops answering until the derivations end, because the work cannot be cancelled.

**Pre-conditions**: any authenticated user (anonymous by default) who owns an Active key; `DeriveKey` is allowed for both roles.

**Impact**: denial of service of the HTTP API from a few requests. The same class covers RSA key generation up to 16,384 bits (5.3) and, in non-FIPS builds, FPE FF1 (6.0). Rated 7.1 HIGH, the band of the most severe member (DeriveKey); in the default no-authentication configuration the attacker is anonymous (`PR:N`) and the same vector scores 8.7. The cost figures (PBKDF2 over 64 KiB at 600,000 iterations is about 1.2 billion HMAC-SHA-256 evaluations, minutes to tens of minutes of one core) are estimates, not executed.

**Evidence**: `crate/server/src/core/operations/derive_key.rs:61-63` (a doc comment states that the derivation runs synchronously, so larger iteration counts would pin a worker thread), `:249-251` (no upper bound on the bit length), `:338-344` (the length check runs after the derivation) and `:281-285,981-983,1041`; `crate/crypto/src/crypto/rsa/operation.rs:27,222-224,245`, `crate/server/src/core/operations/create_key_pair.rs:114-115` and `crate/server/src/routes/jose/keys.rs:324-327,370` (RSA up to 16,384 bits); `crate/crypto/src/crypto/fpe/ff1.rs:121,593,609`; `crate/server/src/core/kms/other_kms_methods.rs:195-198` (the 8,192-bit `MAX_SYMMETRIC_KEY_BITS` cap guards symmetric Create only); `crate/access/src/access.rs:147-155` (DeriveKey is allowed for both roles); only three `spawn_blocking` call sites exist (`crate/server/src/core/operations/create.rs:57-62`, `crate/server/src/routes/aws_xks/sigv4_middleware.rs:227`, `crate/server/src/core/audit/file_sink.rs:181`); the optional rate limiter is off by default and counts requests, not cost (`crate/server/src/start_kms_server.rs:1381-1384`); a batch may carry up to 10,000 items.

**Mitigations present**: the PBKDF2 iteration count is capped at 10,000,000 (`crate/server/src/core/operations/derive_key.rs:63`); OpenPGP key generation was moved to `spawn_blocking`.

**Gaps**: no cap on the derived length, no cost budget, no `spawn_blocking` for these operations and no per-request deadline.

### T-020: CreateSplitKey multiplies the key size by the part count (F-010)

**Attack scenario**: The attacker, anonymous by default or any user who may import and create objects, imports a `SecretData` object of about 32 MiB. The attacker calls `CreateSplitKey` on it with `split_key_parts` and `split_key_threshold` both set to 255; the request is about 1 KB. The server allocates about 8 GiB of shares and then serializes them for the database. The operating system kills the process, which takes down every route, and the attacker repeats the request after each restart.

**Pre-conditions**: the right to import and create objects, and a host whose memory is below the amplified size.

**Impact**: remote denial of service of the whole KMS from a small request. Rated 7.1 HIGH; in the default no-authentication configuration the attacker is anonymous (`PR:N`), which scores 8.7. The memory figures (shares about parts times size; database serialization about 3.6 characters per byte) are estimates, not executed.

**Evidence**: `crate/server/src/core/operations/create_split_key.rs:122` (part-count cap only) and `:129` (no size check); `crate/crypto/src/crypto/split_key/mod.rs:43` (an empty secret is rejected), `:54` (n-1 random shares are allocated and filled) and `:62`; `crate/server/src/core/operations/import.rs:1054` (`process_secret_data`, no size check); `crate/server/src/core/kms/other_kms_methods.rs:195-198`; `crate/server/src/start_kms_server.rs:1405-1410` (the 64 MiB body limit is the only bound); `Cargo.toml:179,203`.

**Mitigations present**: the 255-part cap; the 64 MiB body limit; an empty secret is rejected.

**Gaps**: no cap on the source size or on the total share bytes; the shares are materialised before they are stored; no per-user quota.

### T-026: HSM keys are created extractable and non-sensitive (F-011)

**Attack scenario**: An HSM administrator creates an AES key with `ckms sym keys create` and no `--sensitive`, trusting the documentation that HSM keys never leave the device, and grants `Get` on it to another user or service. The grantee sends `Get` or `Export`; the HSM returns the value because the key is extractable and not sensitive, and the KMS passes it to the caller. The key now exists outside the HSM, and the confidentiality guarantee of the HSM boundary is lost without any alert.

**Pre-conditions**: a key created with the default attributes and a `Get` or `Export` grant to a second principal.

**Impact**: key material leaves the HSM although the documentation says it cannot. The base score is 6.0 MEDIUM; the severity is raised one tier to HIGH by the HSM-boundary amplifier, because the finding is in the HSM path and the impact is key confidentiality. With `AT:N` the base score would be 7.1.

**Evidence**: `crate/interfaces/src/hsm/hsm_store.rs:335,498` (`sensitive` defaults to false), `:346` (the key is exported from the HSM on every retrieval) and `:390` (a metadata-only stub is returned only for sensitive keys); `crate/hsm/base_hsm/src/session/aes.rs:118`, `crate/hsm/base_hsm/src/session/rsa.rs:61` and `crate/hsm/base_hsm/src/session/ec.rs:213` (`extractable` is true whenever `sensitive` is false); `crate/clients/clap/src/actions/symmetric/keys/create_key.rs:65` (`--sensitive` defaults to false); `crate/server/src/core/operations/export_get.rs:103`; `crate/server/src/core/retrieve_object_utils.rs:457-466` (HSM administrators reach every key of their instance) and `:481-492` (a `Get` grant also grants `Export`); `crate/server/src/core/operations/generate_csr.rs:159-163` (an error message that tells the user to create the key with `--sensitive`); the false statement is at `documentation/docs/hsm_support/hsm_operations.md:364-365`, and the correct ones at `documentation/docs/hsm_support/luna.md:389-393` and `documentation/docs/hsm_support/luna_quick_reference.md:58`.

**Mitigations present**: only the HSM administrator can create HSM objects (`crate/interfaces/src/hsm/hsm_store.rs:297,461`, T-069); `Get` refuses Sensitive keys; the `--sensitive` flag exists.

**Gaps**: the default is non-sensitive and extractable, and the documentation claims the opposite.

## Coverage

The matrix lists all 51 findings of `3-findings.md` exactly once (T-001 to T-051) and 29 controls that were checked and held (T-052 to T-080). Areas that were not analysed are listed under Scope Limitations in `0-assessment.md`.
