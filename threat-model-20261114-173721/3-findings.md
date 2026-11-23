# Security Findings — Eviden KMS

**Analysis date**: 2026-11-14
**Scope**: Full repository, branch `rbac_rego` at commit `17926f40b` (PR #998, workspace version 5.29.0), including the `authentication/` submodule
**Evidence basis**: Every finding is a static trace of the code at the cited lines, except F-042 and F-051, which were also reproduced by a local run (the cards give the commands and what was measured). Both runs used a debug build of `cosmian_kms` on SQLite with no authentication configured, against a scratch database under `/tmp`. No FIPS build or release build was run, and no test was added to the repository. "Confidence" is the analyst's estimate, out of 10, that the described condition exists and is reachable as stated.

## Summary

| Severity | Count |
| --- | --- |
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 10 |
| 🟡 MEDIUM | 22 |
| 🔵 LOW | 12 |
| ⚪ INFO | 5 |
| **Total rated findings** | **51** |

A further 24 agent-reported hardening notes (R-01 to R-24) were not independently re-verified. They are listed in the appendix at the end of this file and are not counted above.

### How the severities were set

- **CVSS 4.0 base score.** Each score is computed from the vector printed on the card, using the reference CVSS 4.0 algorithm. The vector describes the least-privileged realistic attacker against the shipped or documented configuration. Subsequent-system impact (SC, SI, SA) is scored only where the evidence shows a downstream effect.
- **Rated severity.** The band of the base score (CRITICAL 9.0 and above, HIGH 7.0 to 8.9, MEDIUM 4.0 to 6.9, LOW 0.1 to 3.9), except where the index shows a marker.
- **† Cap (lowers the rating).** A MEDIUM cap applies when the attack needs a prior compromise of a credential, third party or developer account, an explicit operator opt-out switch, or an identity provider or secret configured against a documented operator requirement. A HIGH cap applies to a documented insecure default. A LOW cap applies where the trigger is an independent failure the attacker cannot cause. The base score stays visible so a reviewer can disagree with the cap.
- **‡ KMS amplifier (raises the rating).** Applied only where the finding itself demonstrates the condition and the impact is key confidentiality, key integrity or authentication bypass: F-002 (key escrow, HIGH to CRITICAL) and F-011 (HSM boundary, one tier up from MEDIUM to HIGH).
- **Declined amplifiers** are stated on the card, together with the rating that would apply if the reviewer disagrees (F-005, F-008, F-021, F-023, F-030).
- **Order.** Findings are ordered by rated severity, then by base score, then by exploitability, then by business impact. IDs were assigned in a first ranking pass and are kept stable. F-042 was re-rated from LOW to HIGH after a local run and F-051 was added from the same run, so the index order differs from the ID order for those two only.
- **Measured findings.** F-042 and F-051 were reproduced on a local debug build. Their ratings use the measured behaviour, not a static estimate.
- **Verdicts.** Where the final severity differs from the tier suggested by the independent verifier, the card says so.

The adjustments register, the OWASP numbering method and the CVSS conventions are repeated in `0-assessment.md`.

## Ranked Index

| ID | Severity | CVSS 4.0 base | Adj. | Title | Conf. |
| --- | --- | --- | --- | --- | --- |
| F-001 | 🔴 CRITICAL | 9.3 | | Auth Verifier `/sessions` API has no owner or realm authorisation (session-JWT theft, revocation bypass, mass logout) | 9/10 |
| F-002 | 🔴 CRITICAL | 8.2 | ‡ | Google CSE `privilegedunwrap` returns the DEK to any IdP-authenticated caller | 9/10 |
| F-003 | 🟠 HIGH | 9.2 | † | Shipped defaults serve plain HTTP on `0.0.0.0` and treat every request as the admin user | 9/10 |
| F-004 | 🟠 HIGH | 8.9 | | Auth Verifier ships a default super-admin (`admin` / `change_me`) that the KMS accepts on its bearer path | 8/10 |
| F-005 | 🟠 HIGH | 8.2 | | AWS XKS SigV4 middleware buffers the whole body before authentication, with no size cap | 9/10 |
| F-006 | 🟠 HIGH | 8.2 | | Unauthenticated OCSP responder amplifies CPU and database work (opt-in feature) | 7/10 |
| F-007 | 🟠 HIGH | 7.6 | | MySQL `ssl-ca` adds to the system trust store instead of pinning the CA | 8/10 |
| F-008 | 🟠 HIGH | 7.1 | | CreateSplitKey and JoinSplitKey export a non-extractable or sensitive key in plaintext | 8/10 |
| F-042 | 🟠 HIGH | 7.1 | | Unbounded `validity_days` aborts the whole server and lets a CRL carry a far-future `nextUpdate` | 9/10 |
| F-009 | 🟠 HIGH | 7.1 | | Unbounded work in DeriveKey, RSA key generation and FPE pins a worker thread | 8/10 |
| F-010 | 🟠 HIGH | 7.1 | | CreateSplitKey multiplies the key size by the part count (memory exhaustion from about 1 KB) | 7/10 |
| F-011 | 🟠 HIGH | 6.0 | ‡ | HSM keys are created extractable and non-sensitive, contradicting the documentation | 7/10 |
| F-012 | 🟡 MEDIUM | 9.1 | † | Long-lived PAT and crates.io token exposed to workflows that run third-party code | 8/10 |
| F-013 | 🟡 MEDIUM | 8.3 | † | Dangerous opt-out switches (CSE token validation, Azure EKM client authentication) are not gated behind `insecure` | 9/10 |
| F-014 | 🟡 MEDIUM | 7.6 | † | User identity is the unverified `email` claim | 6/10 |
| F-015 | 🟡 MEDIUM | 7.6 | † | No CRL or OCSP revocation checking on mTLS client certificates | 7/10 |
| F-016 | 🟡 MEDIUM | 7.0 | † | Self-hosted runner host SSH key mounted into a mutable root container (8 jobs) | 6/10 |
| F-017 | 🟡 MEDIUM | 6.8 | | Windows CNG key storage provider makes every key plaintext-exportable | 8/10 |
| F-018 | 🟡 MEDIUM | 6.7 | | Secrets printed in info-level startup logs | 8/10 |
| F-019 | 🟡 MEDIUM | 6.3 | | Backend errors collapse to empty results; fail-open CRL generation | 6/10 |
| F-020 | 🟡 MEDIUM | 6.3 | | Auth Verifier login rate limiter is keyed on the connection IP | 6/10 |
| F-021 | 🟡 MEDIUM | 6.1 | | Kubernetes operator is a confused deputy for KMSSecret tenants | 6/10 |
| F-051 | 🟡 MEDIUM | 6.0 | | Unbounded `RotateInterval` or `RotateOffset` crash-loops the server once auto-rotation is enabled | 9/10 |
| F-022 | 🟡 MEDIUM | 6.0 | | `default_username` collision: an identity equal to the admin name inherits its privileges (hypothesis) | 5/10 |
| F-023 | 🟡 MEDIUM | 6.0 | | CSI provider is a confused deputy: any pod can request any readable KMS object | 6/10 |
| F-024 | 🟡 MEDIUM | 6.0 | | UI session cookie is stateless and irrevocable; TTL not enforced server-side | 8/10 |
| F-025 | 🟡 MEDIUM | 6.0 | | CRL fetch buffers the response before the size cap; CRL cache is unbounded | 7/10 |
| F-026 | 🟡 MEDIUM | 6.0 | | MS DKE scope uses permissive CORS with credentials | 5/10 |
| F-027 | 🟡 MEDIUM | 5.9 | | Database rows and ceremony records are unauthenticated (no AAD binding) | 6/10 |
| F-028 | 🟡 MEDIUM | 5.7 | | `ckms.toml`, exported keys and decrypt outputs are written with the default umask | 6/10 |
| F-029 | 🟡 MEDIUM | 5.3 | | Raw internal error text returned in 5xx bodies (regression of COSMIAN-2026-013) | 10/10 |
| F-030 | 🟡 MEDIUM | 5.3 | | Audit logging is opt-in and covers only two production call sites | 7/10 |
| F-031 | 🟡 MEDIUM | 5.3 | | UsageLimits bypass through batch Undo and non-atomic read-modify-write | 6/10 |
| F-032 | 🟡 MEDIUM | 5.3 | | CRL distribution-point SSRF guard checks IP literals only | 7/10 |
| F-033 | 🔵 LOW | 9.1 | † | Session-key KDF uses the public URL as the password (offline test via an anonymous cookie) | 6/10 |
| F-034 | 🔵 LOW | 6.3 | † | Vault-token and login clients have no timeout or redirect policy and accept `http://` | 6/10 |
| F-035 | 🔵 LOW | 2.3 | | The Marvin (RUSTSEC-2023-0071) ignore justification is false for the CSE migration JWT | 7/10 |
| F-036 | 🔵 LOW | 2.3 | | Auth Verifier JWKS is refetched only when the cache is empty | 6/10 |
| F-037 | 🔵 LOW | 2.3 | | DeriveKey creates objects outside the Create permission gate | 6/10 |
| F-038 | 🔵 LOW | 2.3 | | `kmip.policy_id` is not enforced at JOSE and SPIRE transit entry points | 6/10 |
| F-039 | 🔵 LOW | 2.3 | | Existence and state oracle on wrap and unwrap key lookup | 6/10 |
| F-040 | 🔵 LOW | 2.3 | | KMIP socket in-flight memory budget can be starved by a few slow mTLS clients | 6/10 |
| F-041 | 🔵 LOW | 2.1 | | Import marks an Active certificate Compromised on any CRL fetch error | 6/10 |
| F-045 | 🔵 LOW | 2.1 | | `ckms login` and `logout` persist one-off overrides into `ckms.toml` | 6/10 |
| F-043 | 🔵 LOW | 2.0 | | PKCS#11 module advertises keys as non-extractable but serves `CKA_VALUE` | 6/10 |
| F-044 | 🔵 LOW | 1.8 | | Kubernetes KMS v2 plugin decrypts under a caller-supplied `key_id` | 6/10 |
| F-046 | ⚪ INFO | n/a | | BFF OIDC callback does not require the `iss` and `aud` claims to be present in the ID token | 6/10 |
| F-047 | ⚪ INFO | n/a | | A database file and 20 test certificate and key files are tracked in the Auth Verifier submodule | 7/10 |
| F-048 | ⚪ INFO | n/a | | Advisories for quinn-proto, quinn-udp and rustix in `Cargo.lock`, none reachable, none in the VEX | 8/10 |
| F-049 | ⚪ INFO | n/a | | OPA roles and domain are not established on non-KMIP routes | 6/10 |
| F-050 | ⚪ INFO | n/a | | EST first-enrolment and SCEP trust model is coarse (documented design) | 6/10 |

Marker legend: † the rating was capped below the band of the base score, ‡ the rating was raised by a KMS amplifier. Baseline status (new, variant of a published advisory, regression) is on each card and is judged against `SECURITY.md` and the earlier PR #998 security review.

## Finding Cards

Cards are in ID order, not rank order: use the Ranked Index for priority. Each card has a field table, a description, the evidence as `file:line` references, an attack scenario and a proposed fix. Proposed fixes are suggestions for human review: none was applied. File paths are relative to the repository root. Paths beginning with `authentication/` are in the Auth Verifier submodule.

---

### [F-001] 🔴 CRITICAL — Auth Verifier `/sessions` API has no owner or realm authorisation (session-JWT theft, revocation bypass, mass logout)

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege |
| **CWE** | CWE-862: Missing Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 9.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N` |
| **Rating basis** | Band of the base score; no cap and no amplifier |
| **Baseline** | New (extends COSMIAN-2026-043, whose liveness check assumes the session store is trustworthy) |
| **Component** | Authentication server — session management API |
| **File** | `authentication/server/src/server/auth_verifier.rs:539-552` |
| **Confidence** | 9/10 |
| **Status** | Open |

#### Description

The `/sessions` scope of the Auth Verifier is protected only by cookie authentication and realm extraction. Its sibling scopes `/admins/realms`, `/realms` and `/admins` also wrap `AdminAuth`. No handler in the sessions endpoints compares the caller's identity with the session it reads, writes or deletes. Any holder of a valid session cookie in any realm can therefore read another user's signed session JWT, delete arbitrary sessions or a whole realm's sessions, and write a session record. The stolen JWT is accepted by the KMS bearer path, so the weakness in the authentication server becomes full impersonation on the KMS.

#### Evidence

- `authentication/server/src/server/auth_verifier.rs:539-552`: the `/sessions` scope carries only `CookieAuthSameServer`, `ExtractRealm` and CORS. The scopes at `:508-509`, `:522-523` and `:554-555` add `AdminAuth`.
- `authentication/server/src/middleware/cookie_auth.rs:139-162`: authenticates the caller but exposes no ownership check to the handlers.
- `authentication/server/src/server/endpoints/sessions_endpoints.rs`: `POST ""` (`:17`) stores an arbitrary record. `GET /{id}` (`:38`) and `POST /{id}` (`:51`) return `cookie_string`, the signed JWT. `POST /realms/{realm}/clients` (`:99`) is an enumeration oracle for session ids. `DELETE ""` (`:119`), `DELETE /expired` (`:133`) and `DELETE /realms/{id}` (`:142`) delete arbitrary ids or a whole realm. No handler reads the caller's claims.
- `authentication/server/src/session/cookies.rs:12-16`: the session id is the SHA-256 of the cookie. The id is returned to the client at `authentication/server/src/server/endpoints/client_endpoints.rs:138` and logged at info level at `:132`.
- `crate/server/src/middlewares/auth_verifier/token.rs:119-128`: the KMS bearer path validates the signature, `exp` and session liveness, takes the identity from `sub`, and does not check the realm.
- `authentication/server/documentation/docs/authorization_and_administration.md:197-199` promises "if session is in an administered realm"; the check does not exist. `authentication/server/src/tests/sessions_api.rs` contains no negative test.

#### Attack Scenario

1. The attacker obtains any valid `_ea_` session cookie from the Auth Verifier, in any realm (a low-privilege account is enough).
2. The attacker calls `POST /sessions/realms/{realm}/clients` with the victim's realm id (`_` is well known), username and authentication scheme, and learns the victim's live session id.
3. The attacker calls `GET /sessions/{id}` and receives the victim's signed session JWT in `cookie_string`.
4. The attacker presents the JWT as a bearer token to the KMS. Signature, `exp` and liveness all pass, because the victim's session is live. The KMS maps `sub` to the victim's `UserId`, and the attacker holds every permission the victim has, including administrator rights if the victim is an administrator.
5. Variants with the same root cause: `POST /sessions` re-creates a revoked session record and so defeats the COSMIAN-2026-043 revocation check, and `DELETE /sessions/realms/{id}` or `DELETE /sessions/expired` signs out every user of a realm.

Preconditions: a valid session in any realm, network reachability of the Auth Verifier, and a live victim session. Static trace, not executed.

**Proposed Fix** (review before applying)

- Require `AdminAuth` plus a realm-administration check for any cross-user or cross-realm operation, and an ownership check (stored username and realm equal to the caller's claims) for self-service operations.
- Never return `cookie_string` from `GET`. Make session upsert internal, restrict `DELETE /expired` and `DELETE /realms/{id}` to administrators, and stop logging session ids.
- Keep the KMS self-delete caller working (`crate/server/src/routes/ui_auth.rs:836-861`).
- Add negative tests for cross-user read, delete and upsert.

---

### [F-002] 🔴 CRITICAL — Google CSE `privilegedunwrap` returns the DEK to any IdP-authenticated caller

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-863: Incorrect Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 8.2 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | ‡ Base 8.2 is HIGH. Raised one tier to CRITICAL by the key-escrow amplifier: the finding itself shows key material leaving the KMS without the key owner's consent. The independent verifier suggested HIGH |
| **Baseline** | Incomplete fix and regression of COSMIAN-2025-008 (`SECURITY.md:1364-1380`) |
| **Component** | Google CSE routes (`/google_cse`) |
| **File** | `crate/server/src/routes/google_cse/operations.rs:756-806,1175-1230` |
| **Confidence** | 9/10 |
| **Status** | Open |

#### Description

The Google CSE `privilegedunwrap` operation decrypts a wrapped data encryption key (DEK) as the default user, the service identity that owns the CSE key. The only privileged-specific authentication check applies to resources whose name contains `/drive/`, and it compares the token audience with the audience of the same configuration (self-referential), so it is skipped when no audience is configured. The `resource_name` and `kacls_url` claims minted for migration tokens are never compared with the request. `SECURITY.md` states that access is restricted to users with administrative permissions, and no such restriction exists in the code or the configuration. `privileged_wrap` and `privileged_private_key_decrypt` have the same gating.

#### Evidence

- `crate/server/src/start_kms_server.rs:1427-1434`: the `/google_cse` scope has permissive CORS and no authentication middleware. It is registered at `:1423-1425` only when `kms_public_url` is set and `google_cse.enable` is true.
- `crate/server/src/routes/google_cse/jwt.rs:250`: loops over every configured identity provider, general ones and whitelisted KACLS ones, and the first match wins. `:289-292` is the only privileged-specific check (`/drive/` resources). `:312-313` maps a privileged-unwrap token to `kms_default_username` with no role or allow-list check.
- `crate/server/src/middlewares/jwt/jwt_config.rs:348`: audience validation is off when no audience is configured. `crate/server/src/config/command_line/idp_auth_config.rs:104-111` shows the same condition on the configuration side.
- `crate/server/src/routes/google_cse/operations.rs:756-761,771,783-785,800-806`: the request is authenticated and then `cse_wrapped_key_decrypt` runs as the default user with the resource name as AAD. `:1175-1230` holds the shared decrypt path.
- `crate/server/src/tests/google_cse/token_validation.rs:518-550`: the test uses an ordinary user token and expects the DEK back.
- `SECURITY.md:1375` ("Any CSE-authenticated user could invoke it") and `:1379` ("Access restricted to users with administrative permissions"). History: #517 (5.8.0) added the audience check, #656 (`f9e80e3ed`) replaced it with the self-referential check, and #948 restored it only for whitelist configurations.
- `documentation/docs/integrations/cloud_providers/google_workspace_client_side_encryption_cse/getting_started/index.md:172`: a documentation sample with an empty audience.

#### Attack Scenario

1. Google CSE is enabled. An attacker holds a token from one of the configured identity providers, for example any employee's Google token.
2. The attacker obtains a wrapped DEK blob and the exact `resource_name` it was wrapped with (the AAD), for instance from a shared document's metadata.
3. The attacker calls `POST /google_cse/privilegedunwrap` with the token, the blob and the resource name.
4. The server accepts the token, runs the decrypt as the default user and returns the plaintext DEK. The attacker decrypts the document.

Preconditions: CSE enabled (off by default), a token from a configured identity provider, and the wrapped blob with its exact resource name. Static trace, not executed.

**Proposed Fix** (review before applying)

- Accept `privileged_unwrap`, `privileged_wrap` and `privileged_private_key_decrypt` only from a whitelisted KACLS verifier with `aud` equal to `kacls-migration` for every resource type, or from an explicit administrator allow-list, and fail closed when no audience is configured.
- Bind the `resource_name` and `kacls_url` claims to the request.
- Never map an arbitrary IdP token to `default_username`.
- Add a negative test with an ordinary user token, flip the existing test, and fix the documentation sample.

---

### [F-003] 🟠 HIGH — Shipped defaults serve plain HTTP on `0.0.0.0` and treat every request as the admin user

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege |
| **CWE** | CWE-1188: Initialization of a Resource with an Insecure Default |
| **OWASP** | A02:2025 — Security Misconfiguration |
| **CVSS 4.0** | 9.2 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **Rating basis** | † Base 9.2 is CRITICAL. Capped to HIGH because this is a documented insecure default that logs a startup warning, and the operator must deploy it without configuring any authentication |
| **Baseline** | Known class (PR #998 review D1); new default-deployment angle |
| **Component** | Server defaults and authentication fallback |
| **File** | `crate/server/src/middlewares/ensure_auth.rs:50-59` |
| **Confidence** | 9/10 |
| **Status** | Open |

#### Description

When no authentication method is configured, `ensure_auth` injects the configured `default_username` (default `admin`) as the authenticated user with an empty role list. The packaged `pkg/kms.toml` binds the HTTP server to `0.0.0.0:9998`, serves plain HTTP unless a TLS section is added, and sets `default_username = "admin"`. The default user can create objects without the Create gate and can unwrap any key, so an operator who installs the package and does not configure authentication exposes a full-privilege, unauthenticated KMS on every interface. A startup warning is logged but the server still starts. The Docker image and the systemd unit run as root, and the Helm chart ships with the network policy disabled.

#### Evidence

- `crate/server/src/middlewares/ensure_auth.rs:41-47` passes through an already-authenticated request. `:49-55` rejects the request only when `auth_is_configured`. `:57-59` injects `AuthMethod::DefaultUser` with `default_username` otherwise.
- `pkg/kms.toml:2` (`default_username = "admin"`), `:186` (the comment that HTTPS starts only if a TLS configuration is provided) and `:191` (`hostname = "0.0.0.0"`).
- `crate/server/src/start_kms_server.rs:1111-1118`: the only mitigation, a `warn!` that every request is served as the default user. The server continues to start.
- `pkg/cosmian_kms.service:8` (`User=root`); `nix/docker.nix:415-416` (the image runs as root unless `--user` is passed); `charts/cosmian-kms/values.yaml:144` (`networkPolicy.enabled: false`), `:191` and `:193` (`defaultUsername: admin`, `hostname: 0.0.0.0`).
- `documentation/docs/configuration/authentication.md:7-9` documents non-authenticated mode as the default.
- Mitigations present: systemd `ProtectSystem=strict` (`pkg/cosmian_kms.service:23`) and `NoNewPrivileges` (`:99`); the package does not start the service automatically and installs the configuration file with mode 0400.

#### Attack Scenario

1. An operator installs the deb, rpm or Docker image and starts the server without editing the default configuration, or deploys the Helm chart with default values.
2. A host that can reach TCP port 9998 sends KMIP requests with no credentials.
3. `ensure_auth` serves each request as `admin`. The attacker creates keys, exports or unwraps any key the default user can reach, and administers HSM slots (the default HSM administrator is also `admin`).

Preconditions: network reachability of the port and an operator who has not configured authentication. The server logs a warning at start. Static trace, not executed.

**Proposed Fix** (review before applying)

- Bind `127.0.0.1` by default, or refuse to start on a non-loopback address without authentication and TLS unless an explicit opt-in flag is set.
- Run the container as a dedicated non-root user and make the Helm chart fail when no authentication is configured. Enable the network policy by default.
- State the risk in the packaged `pkg/kms.toml` next to `default_username`.

---

### [F-004] 🟠 HIGH — Auth Verifier ships a default super-admin (`admin` / `change_me`) that the KMS accepts on its bearer path

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing |
| **CWE** | CWE-1392: Use of Default Credentials |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 8.9 — `CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N` |
| **Rating basis** | Band of the base score. Adjacent network because the packages bind `localhost` and Helm uses a ClusterIP service. With `AV:N` the same vector scores 9.5, with `AV:L` 8.8 |
| **Baseline** | Instance of PR #998 review D1 and item 6, with new facets |
| **Component** | Authentication server — bootstrap administrator |
| **File** | `authentication/server/src/database/trait.rs:72-84` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

On first start the Auth Verifier creates an administrator `admin` with the fixed password `change_me` in the realm `_`. The realm is seeded with `allow_expired_passwords: true`, so the "change password" flag set on the account is never enforced. The values are not configurable. A login as this administrator produces a signed session JWT whose `sub` is `admin`. The KMS bearer path accepts that token (it checks the signature, expiry and liveness but not the realm), maps it to the KMS user `admin`, which equals the default `default_username`, and so grants the default user's privileges. The KMS documentation states that admin-realm sessions must never authenticate to the KMS, and the code does not enforce it on the bearer path.

#### Evidence

- `authentication/server/src/database/trait.rs:72-73` (the constants), `:84-141` (`initialize_db` creates realm `_` and the administrator), `:92` (`allow_expired_passwords: true`), `:119` (`change_password: true`).
- `authentication/server/src/middleware/username_password.rs:155-156`: a TODO and the `allow_expired_passwords` branch; the forced change is not enforced.
- `crate/server/src/middlewares/auth_verifier/token.rs:119-128`: signature, `exp` and liveness are checked; the identity is `sub`; there is no realm check.
- `crate/server/src/config/command_line/clap_config.rs:129-130` (`default_username` defaults to `admin`) and `crate/server/src/config/command_line/hsm_config.rs:6,103` (the default HSM administrator is `admin`).
- `crate/server/src/config/command_line/auth_verifier_config.rs:24-29` rejects only an empty realm list.
- Documentation: `authentication/server/documentation/docs/server_configuration.md:337` and `authentication/server/documentation/docs/installation.md:116-130` state the credentials and that the change is not enforced; `documentation/docs/integrations/spire_spiffe.md:766,788` use them in examples; `documentation/docs/configuration/ui.md:188-190` says admin-realm sessions must never authenticate to the KMS.
- Deployment: the deb and rpm bind `localhost:8443` (`authentication/pkg/auth_verifier.toml:22,25`); Helm exposes a ClusterIP service with no network policy; the Docker development fallback binds `0.0.0.0` with a warning.

#### Attack Scenario

1. A KMS deployment uses the Auth Verifier for authentication and the administrator has not changed the initial password (nothing forces the change).
2. An attacker with network access to the Auth Verifier logs in with `admin` / `change_me` against realm `_` and obtains a session JWT.
3. The attacker sends the JWT as a bearer token to the KMS. The KMS accepts it as user `admin`, the default user, with the privileges that identity carries (Create-gate bypass, unwrap of any key, default HSM administrator).

Preconditions: the Auth Verifier is configured as an authentication source of the KMS, the password is unchanged, and the attacker can reach the Auth Verifier. Static trace, not executed.

**Proposed Fix** (review before applying)

- Generate a random initial administrator password and print it once, or enforce `change_password` at first login.
- Reject tokens of the admin realm `_` on the KMS bearer path, as the documentation already states.
- Apply the SPIRE-style `default_username` collision guard to every external identity source (see F-022).

---

### [F-005] 🟠 HIGH — AWS XKS SigV4 middleware buffers the whole body before authentication, with no size cap

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 8.2 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The cloud-route amplifier (§6 of the skill) is declined because the impact is availability only and no key material is exposed. A reviewer who applies it literally would rate this CRITICAL |
| **Baseline** | Same class as COSMIAN-2026-032, 036 and 037 |
| **Component** | AWS XKS routes (`/aws`) |
| **File** | `crate/server/src/routes/aws_xks/sigv4_middleware.rs:168-172,208` |
| **Confidence** | 9/10 |
| **Status** | Open |

#### Description

The SigV4 middleware must hash the request body to verify the signature, so it reads the entire body into memory before it knows whether the caller is legitimate. The read has no size limit and no timeout. The global 64 MiB `PayloadConfig` limits only the `Bytes` and `String` extractors, not a raw `Payload`. The verification semaphore that bounds CPU use is acquired after the body has been buffered. An unauthenticated client can therefore stream an arbitrarily large body to the `/aws` scope and grow the process memory until the operating system kills it. Because the server is built with `panic = "abort"` and shares one process for every route, the whole KMS goes down.

#### Evidence

- `crate/server/src/routes/aws_xks/sigv4_middleware.rs:168` (`req.into_parts()`), `:172` (`fold(BytesMut::new(), ...)` appends every chunk), `:208-209` (the permit is acquired after the read), `:56-58` (the semaphore), comments at `:51` and `:189` that assume a 64 MB cap.
- `crate/server/src/start_kms_server.rs:1405-1410`: `PayloadConfig::new(64 MiB)`. In actix-web 4.18.2 (`src/types/payload.rs:96-101`) a raw `Payload` is not limited by it. No `Content-Length` guard exists in `crate/server/src`.
- `crate/server/src/start_kms_server.rs:1483-1496`: the `/aws` scope wiring with the SigV4 middleware at `:1488`. `:1922-1930`: `client_request_timeout` (10 s) and `keep_alive` bound only the request head and idle time.
- The correct pattern already exists in the code base: `crate/server/src/routes/enrollment.rs:209-218` (`MAX_ENROLLMENT_BODY` and `to_bytes_limited`).

#### Attack Scenario

1. AWS XKS is enabled (`aws_xks_config.enable`, off by default). The attacker can reach the HTTPS port.
2. The attacker opens several connections to `/aws/...` and streams bodies of many gigabytes with a syntactically valid request head, sending slowly to avoid any idle limit.
3. Each connection accumulates the body in a `BytesMut` before any signature check. The server process exhausts memory and is killed. All KMS routes are unavailable until it restarts.

Preconditions: XKS enabled and a reachable listener. No credentials are needed. Static trace, not executed.

**Proposed Fix** (review before applying)

- Read the body with `to_bytes_limited` and XKS-specific bounds (plaintext up to 4,300 bytes and AAD up to 8,192 bytes plus JSON overhead). Reject an oversized declared `Content-Length` before reading. Reject a bad access key id or date before reading the body.
- Add a body-read timeout, take the permit before buffering, set `max_connections`, and correct the stale comments.

---

### [F-006] 🟠 HIGH — Unauthenticated OCSP responder amplifies CPU and database work (opt-in feature)

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-400: Uncontrolled Resource Consumption |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 8.2 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `AT:P` reflects that the responder is disabled by default and needs a configured CA |
| **Baseline** | New |
| **Component** | PKI — OCSP responder |
| **File** | `crate/server/src/routes/ocsp/handler.rs:341` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

The OCSP responder is public by design (RFC 6960). For every `CertID` in a request, the handler looks up the certificate status through a path that scans every certificate linked to the CA, loads each one from the database and parses its DER. The store's per-serial lookup that would use an indexed query is documented but never implemented or called. A request may carry up to 128 `CertID`s (`MAX_OCSP_QUERIES_PER_REQUEST`), and the response cache is bypassed whenever the request has a nonce or more than one query. One cheap request therefore costs up to 128 full scans of the CA's issued certificates, plus a signature. No rate limit is enabled by default.

#### Evidence

- `crate/server/src/routes/ocsp/handler.rs:321-327` (the cache is used only for a single query without a nonce and with an uncompromised CA), `:341` (`for query in &queries`), `:472-478` (a one-element `HashSet` per serial passed to the lookup).
- `crate/server/src/core/certificate/find.rs:83-100`: `find_all` over every certificate linked to the CA, then `retrieve_object_arc` and `X509::from_der` for each candidate.
- `crate/interfaces/src/stores/objects_store.rs:390-401`: the default implementation traverses all linked certificates and says SQL backends should override it with an indexed query; `find_certificate_by_serial` is never implemented or called.
- `crate/server/src/start_kms_server.rs:1806-1808`: the public routes. `crate/server/src/config/command_line/ocsp_config.rs:26-31`: `ocsp_enabled` defaults to `false`, and a CA UID must be configured.
- `crate/crypto/src/openssl/ocsp.rs:58,214` (the 128 `CertID` cap), `:198` (request parsing) and `:386,480` (response construction and `OCSP_basic_sign`). The cache holds at most 10,000 entries (`crate/server/src/routes/ocsp/handler.rs:117`).

#### Attack Scenario

1. An operator has enabled the OCSP responder for a CA that has issued many certificates (a large PKI).
2. The attacker sends many `POST /ocsp/` requests, each with a nonce (cache bypass) and 128 `CertID`s for the maximum amplification.
3. Each `CertID` triggers a scan and parse of every certificate issued by the CA, then the response is signed. The workers and the database connection pool saturate, and the other KMS routes slow down or time out.

Preconditions: OCSP enabled and reachable. No credentials are needed. Static trace, not executed. Request cost estimates were not measured.

**Proposed Fix** (review before applying)

- Perform one lookup per request for all serials, or implement the indexed serial and issuer query for each SQL store.
- Cache negative results, rate-limit the nonce path, and warn at start when OCSP is enabled without a limiter. The per-request cap of 128 `CertID`s (`crate/crypto/src/openssl/ocsp.rs:58,214`) already exists and could be lowered.

---

### [F-007] 🟠 HIGH — MySQL `ssl-ca` adds to the system trust store instead of pinning the CA

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing |
| **CWE** | CWE-295: Improper Certificate Validation |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 7.6 — `CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The attacker must sit on the path between the KMS and the database (`AV:A`) and must hold a certificate that a system root CA signed (`AC:H`, `AT:P`). With `AV:N` the same vector scores 9.1 |
| **Baseline** | Variant of COSMIAN-2026-029 (the PostgreSQL equivalent, fixed) |
| **Component** | Database layer — MySQL backend |
| **File** | `crate/server_database/src/stores/sql/mysql.rs:152-170` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

In the `VERIFY_CA` and `VERIFY_IDENTITY` modes the code passes the operator's `ssl-ca` file to `SslOpts::with_root_certs`. In `mysql_async` 0.37.1 that setting is merged with the system roots unless `with_disable_built_in_roots(true)` is also set (its documentation says "By default system built-in certs _will be_ used"). The KMS never sets it. An operator who pins a private CA therefore still trusts every public CA. The PostgreSQL backend pins correctly, and the MySQL documentation describes `ssl-ca` as the CA "for server verification" and `VERIFY_CA` as "verified against the CA", which readers take as pinning. The `REQUIRED` and `PREFERRED` modes perform no verification at all, which is documented.

#### Evidence

- `crate/server_database/src/stores/sql/mysql.rs:164-169`: `.with_root_certs(vec![PathBuf::from(ca_path.as_ref()).into()])` in the `VERIFY_*` branch. `:158-161`: `REQUIRED` and `PREFERRED` use `with_danger_accept_invalid_certs(true)` and `with_danger_skip_domain_validation(true)`. A search of `crate/` finds no call to `with_disable_built_in_roots`.
- `mysql_async-0.37.1/src/opts/mod.rs:243-244` (dependency source): the option that restricts trust to `with_root_certs` is off by default.
- Correct sibling: `crate/server_database/src/stores/sql/pgsql.rs:96-98` (`pinned_ca_store`, with its comment that `set_ca_file` would add to the system CAs) and `:164-166` (use of the pinned store).
- Documentation: `documentation/docs/configuration/database/configuration.md:330` (`ssl-ca` row) and `:370-371` (`ssl-mode` behaviour).

#### Attack Scenario

1. The operator runs MySQL with a private CA and configures `ssl-mode=VERIFY_CA&ssl-ca=/etc/kms/db-ca.pem`, expecting that only this CA is accepted.
2. An attacker on the network path between the KMS and the database (same subnet or cluster network, ARP or DNS spoofing) answers with a certificate that chains to any publicly trusted CA. With `VERIFY_CA` any such certificate is enough. With `VERIFY_IDENTITY` the certificate must also match the database host name, which is much harder for an internal name.
3. The KMS accepts the session, sends its database credentials, and reads or writes the key records through the attacker's server.

Preconditions: MySQL backend with a `VERIFY_*` mode and an on-path attacker. Static trace. The library default comes from its source documentation. The handshake was not executed.

**Proposed Fix** (review before applying)

- Call `.with_disable_built_in_roots(true)` whenever `ssl-ca` is set, document that `ssl-ca` pins the CA, and keep the system roots only when no `ssl-ca` is given.
- Add a live TLS test: a server presenting a publicly rooted certificate must be refused when `ssl-ca` points at a private CA. Mirror the PostgreSQL matrix test.

---

### [F-008] 🟠 HIGH — CreateSplitKey and JoinSplitKey export a non-extractable or sensitive key in plaintext

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-424: Improper Protection of Alternate Path |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 7.1 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The key-escrow amplifier is declined because the caller already holds the `Get` grant. A reviewer who reads the Extractable and Sensitive flags as the owner's refusal to export would apply it and rate this CRITICAL |
| **Baseline** | Variant of GHSA-8mmx-f92q-2gq8, GHSA-c75c-3cmm-48h7 and COSMIAN-2026-045, which close other bypasses of the same controls |
| **Component** | KMIP operations — split key |
| **File** | `crate/server/src/core/operations/create_split_key.rs:71,129,373,566-587` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

`Get` and `Export` refuse a key whose `Extractable` is false, whose `NeverExtractable` is true, or that is `Sensitive`. `CreateSplitKey` reads the same key with only the `Get` permission and copies its raw bytes into shares, without any of these checks. The shares are stamped `Sensitive`, but `JoinSplitKey` rebuilds the secret with default attributes, so the reconstructed object carries no `Sensitive` or `Extractable` flag, belongs to the caller, and can be fetched with `Get`. A caller who may `Get` a key that the owner marked non-exportable can therefore obtain its plaintext through a split with threshold equal to the number of parts, followed by a join.

#### Evidence

- `crate/server/src/core/operations/create_split_key.rs:68-75` (source retrieved with `KmipOperation::Get`), `:129` (`extract_key_bytes_ref(owm.object())`), `:373` (`sensitive: Some(true)` on the shares only), `:105-109` (only HSM keys are refused).
- `crate/server/src/core/operations/join_split_key.rs:80-84` (shares retrieved with `Get`), `:583` (`build_reconstructed_object`), `:626` (`..Attributes::default()`).
- The bypassed control: `check_extractable_and_sensitive` in `crate/server/src/core/operations/export_get.rs:66-107` (Extractable and NeverExtractable at `:72-73`, Sensitive at `:103`). It is private to that module, and neither split file contains an equivalent check.
- `crate/server/src/core/kms/permissions.rs:276-285`: the `Create` gate passes the default user and Crypto Officers, and is open to every user when no Crypto Officer is configured.

#### Attack Scenario

1. The owner creates an AES key with `Extractable=false` or `Sensitive=true` so that `Get` and `Export` never return its bytes. The attacker holds a `Get` grant on it, or owns it through a stolen low-privilege session.
2. The attacker calls `CreateSplitKey` with `split_key_threshold` equal to `split_key_parts` (XOR split). The server reads the raw bytes and writes the shares, which the attacker owns.
3. The attacker calls `JoinSplitKey` with the shares and then `Get` on the reconstructed object, which has no `Sensitive` or `Extractable` flag. The response carries the key in plaintext.

Preconditions: a `Get` grant on the target key and the right to create objects (the default when no Crypto Officer is configured). Static trace, not executed.

**Proposed Fix** (review before applying)

- `CreateSplitKey` must refuse sources with `Extractable=false`, `NeverExtractable=true` or `Sensitive=true`. Reuse `check_extractable_and_sensitive` by making it visible to the sibling module.
- The shares and the reconstructed key must inherit `Sensitive`, `Extractable` and `NeverExtractable` from the source.
- Add a regression test in which a `Get` grantee splits and joins a non-extractable key and must be refused.

---

### [F-009] 🟠 HIGH — Unbounded work in DeriveKey, RSA key generation and FPE pins a worker thread

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 7.1 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` (vector of the most severe member, K-1) |
| **Rating basis** | Band of the base score of the most severe member. In the default no-authentication configuration the attacker is anonymous (`PR:N`) and the same vector scores 8.7 |
| **Baseline** | Variant of COSMIAN-2026-036. The RSA member is the residual that fix left in place |
| **Component** | KMIP operations — DeriveKey, RSA key generation, FPE |
| **File** | `crate/server/src/core/operations/derive_key.rs:63,249-251,338-344` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

Three operations run CPU-bound work inline on the actix worker that accepted the connection, with no cap on the work a request can ask for, no deadline and no way to cancel. An actix worker is single-threaded, so one such request stalls every other connection on that worker, and as many requests as there are workers (the core count by default) stall the whole HTTP API. The code base already knows this: `create.rs:57-59` moves OpenPGP key generation to `spawn_blocking` because on the worker thread it "would stall every other connection served by that worker". Only three call sites use `spawn_blocking`. The members share this root cause and differ in the dimension left unbounded.

| Member | Operation | What is unbounded | Member score | Where |
| --- | --- | --- | --- | --- |
| K-1 | DeriveKey (PBKDF2 and HKDF) | Derived length up to `i32::MAX` bits (256 MiB). Only the iteration count is capped (10,000,000). The length is checked after the derivation | 7.1 | `derive_key.rs:63,249-251,281-285,338-344,981-983,1041` |
| K-2 | RSA key generation (CreateKeyPair, ReKey, Certify, JOSE `/v1/crypto/keys`) | Modulus up to 16,384 bits, generated inline. The code comment says it "still runs for minutes" | 5.3 (`VA:L`) | `crypto/src/crypto/rsa/operation.rs:27,222-224,245`; `create_key_pair.rs:114-115`; `rekey/keypair/sql.rs:273`; `certify/resolve_subject.rs:351`; `routes/jose/keys.rs:324-327,370` |
| K-6 | FPE FF1 encrypt and decrypt (non-FIPS builds only) | Numeral count up to `u32::MAX`. The cost is quadratic per round | 6.0 (`AT:P`) | `crypto/src/crypto/fpe/ff1.rs:121,593,609`; `encrypt.rs:399`; `decrypt.rs:506`; additional data is capped at 4,096 bytes (`kmip_fpe.rs:27`) |

#### Evidence

- `crate/server/src/core/operations/derive_key.rs:61-63`: the doc comment on `MAX_PBKDF2_ITERATIONS` admits that larger values "would pin a worker thread". `:249-251` converts the requested bit length to bytes with no upper bound. `:338-344` is the only length check and runs after the derivation. `:981-983` and `:1041` allocate the output and derive inline.
- `crate/server/src/core/kms/other_kms_methods.rs:195-198`: the 8,192-bit cap (`MAX_SYMMETRIC_KEY_BITS`) guards symmetric Create only, not DeriveKey.
- `crate/access/src/access.rs:147-155`: DeriveKey is allowed for both roles. In the default configuration there is no role gate.
- `crate/server/src/core/operations/create.rs:57-62`, `crate/server/src/routes/aws_xks/sigv4_middleware.rs:227` and `crate/server/src/core/audit/file_sink.rs:181` are the only `spawn_blocking` sites in `crate/server/src`.
- The optional rate limiter is off by default and counts requests, not their cost (`crate/server/src/start_kms_server.rs:1381-1384`). A batch may carry up to 10,000 items.
- Cost estimates from the analysis agents, not executed: PBKDF2 with a 64 KiB output at 600,000 iterations needs about 1.2 billion HMAC-SHA-256 evaluations, which is minutes to tens of minutes of one core; 1 MiB is hours; the 256 MiB maximum is effectively unbounded. A 16,384-bit RSA key takes about 4 to 20 minutes. FF1 with 10,000 numerals takes about 0.8 s, with 100,000 about 77 s and with 1,000,000 about 2 hours.

#### Attack Scenario

1. The attacker authenticates as any user who can hold an Active key of their own. In the default configuration no authentication is needed.
2. The attacker sends `DeriveKey` with PBKDF2, the default 600,000 iterations and a requested length of 64 KiB or more. The derivation runs on the worker thread that accepted the connection.
3. Repeating the request on as many connections as the server has workers pins all of them. The HTTP API stops answering until the server restarts, because the work cannot be cancelled.

Preconditions: any authenticated user (anonymous by default). Static trace, not executed.

**Proposed Fix** (review before applying)

- Cap the derived length (8,192 bits by default, configurable) and bound the number of blocks times iterations.
- Run the KDFs, RSA key generation and FPE on `spawn_blocking` behind a bounded semaphore, with a per-request CPU budget and a request deadline.
- Lower the default RSA maximum to 8,192 bits unless configured, and cap the FPE numeral count at a few thousand.

---

### [F-010] 🟠 HIGH — CreateSplitKey multiplies the key size by the part count (memory exhaustion from about 1 KB)

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 7.1 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. In the default no-authentication configuration the attacker is anonymous (`PR:N`), which scores 8.7 |
| **Baseline** | New |
| **Component** | KMIP operations — CreateSplitKey |
| **File** | `crate/server/src/core/operations/create_split_key.rs:122,129` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

`CreateSplitKey` limits the number of parts to 255 but not the size of the source key. For the XOR split the threshold must equal the number of parts, so a request with 255 parts allocates 255 shares as large as the key. A `SecretData` object of about 32 MiB can be imported, because the import path has no size cap and the 8,192-bit cap applies only to symmetric Create. A request of about 1 KB can then ask for roughly 8 to 16 GiB of share material, followed by database writes of the shares as JSON integer arrays, which are several times larger than the raw bytes. The build uses `panic = "abort"` and one process serves every route, so an out-of-memory kill ends the HTTP workers and the KMIP socket server together.

#### Evidence

- `crate/server/src/core/operations/create_split_key.rs:122` (part-count cap only), `:129` (source bytes extracted with no size check).
- `crate/crypto/src/crypto/split_key/mod.rs:43` (an empty secret is rejected), `:54` (each of the n-1 random shares is allocated and filled, which touches every page), `:62` (the last share).
- `crate/server/src/core/operations/import.rs:1054`: `process_secret_data` has no size check. `crate/server/src/core/kms/other_kms_methods.rs:195-198`: the 8,192-bit cap does not apply here.
- `crate/server/src/start_kms_server.rs:1405-1410`: the 64 MiB body limit is the only bound on the imported size. `Cargo.toml:179,203`: `panic = "abort"`.
- The memory estimates (share material about `parts × size`, database serialization about 3.6 characters per byte) come from the analysis agent and were not executed.

#### Attack Scenario

1. The attacker, anonymous by default or any user who may import and create objects, imports a `SecretData` object of about 32 MiB.
2. The attacker calls `CreateSplitKey` on it with `split_key_parts` and `split_key_threshold` both set to 255. The request is about 1 KB.
3. The server allocates about 8 GiB of shares and then serializes them for the database. The operating system kills the process, which takes down every route. The attacker repeats the request after each restart.

Preconditions: the right to import and create objects and a host whose memory is below the amplified size. Static trace, not executed.

**Proposed Fix** (review before applying)

- Cap the source size accepted for splitting (8 KiB is ample for symmetric keys) and the total share bytes per request.
- Persist the shares incrementally instead of materializing them all, and apply a per-user quota.

---

### [F-011] 🟠 HIGH — HSM keys are created extractable and non-sensitive, contradicting the documentation

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-1188: Initialization of a Resource with an Insecure Default |
| **OWASP** | A02:2025 — Security Misconfiguration |
| **CVSS 4.0** | 6.0 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | ‡ Raised from MEDIUM (base 6.0) to HIGH by the HSM-boundary amplifier (+1 tier): the finding is in the HSM path and the impact is key confidentiality. With `AT:N` the base score would be 7.1 |
| **Baseline** | New. Related to COSMIAN-2026-041, 042 and 045 |
| **Component** | HSM boundary — key creation |
| **File** | `crate/interfaces/src/hsm/hsm_store.rs:346,390` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

An HSM key is created extractable and non-sensitive unless the caller passes `--sensitive`, which defaults to false. `hsm_store.rs` forwards `attributes.sensitive.unwrap_or(false)` to the HSM layer, and for AES, RSA and EC that layer sets `CKA_EXTRACTABLE` to true whenever the key is not sensitive. When such a key is retrieved, the KMS reads the key material out of the HSM, and `Get` refuses only keys that are marked sensitive. Anyone who holds `Get` or `Export` on the key then receives the raw key, because for HSM keys a `Get` grant also counts as an `Export` grant. The documentation page for HSM operations states the opposite: "HSM keys are always created with `CKA_SENSITIVE=true`". The Luna pages describe the real behaviour for that vendor, and the server knows the gap, since CSR generation refuses non-sensitive HSM keys.

#### Evidence

- `crate/interfaces/src/hsm/hsm_store.rs:335,498` (`sensitive.unwrap_or(false)` and `unwrap_or_default()`), `:346` (the key is exported from the HSM on every retrieval), `:390` (a metadata-only stub is returned only for sensitive keys).
- `crate/hsm/base_hsm/src/session/aes.rs:118`, `rsa.rs:61` and `ec.rs:213`: `extractable` is true whenever `sensitive` is false.
- `crate/clients/clap/src/actions/symmetric/keys/create_key.rs:65`: `--sensitive` defaults to `false`.
- `crate/server/src/core/operations/export_get.rs:103`: only sensitive objects are refused.
- `crate/server/src/core/retrieve_object_utils.rs:457-466` (HSM administrators reach every key of their instance) and `:481-492` (a `Get` grant on an HSM key also grants `Export`).
- `crate/server/src/core/operations/generate_csr.rs:159-163`: "HSM key is extractable; create it with --sensitive".
- `documentation/docs/hsm_support/hsm_operations.md:364-365` claims the opposite. `documentation/docs/hsm_support/luna.md:389-393` and `luna_quick_reference.md:58` describe the real behaviour for Luna.

#### Attack Scenario

1. An HSM administrator creates an AES key with `ckms sym keys create` and no `--sensitive`, trusting the documentation that HSM keys never leave the device. The administrator grants `Get` on it to another user or service.
2. The grantee sends `Get` or `Export` for the key. The HSM returns the value because the key is extractable and not sensitive, and the KMS passes it to the caller.
3. The key now exists outside the HSM. The confidentiality guarantee of the HSM boundary is lost without any alert.

Preconditions: a key created with the default attributes and a `Get` or `Export` grant to a second principal. Static trace, not executed.

**Proposed Fix** (review before applying)

- Default HSM-created keys to `sensitive=true` and `extractable=false`, and refuse `false` unless an operator opt-in is set.
- Correct `hsm_operations.md`, and add a test that `Get` on a default-created HSM key returns the metadata stub only.

---

### [F-012] 🟡 MEDIUM — Long-lived PAT and crates.io token exposed to workflows that run third-party code

| Field | Value |
| --- | --- |
| **STRIDE** | Tampering, Elevation of Privilege, Information Disclosure |
| **CWE** | CWE-522: Insufficiently Protected Credentials |
| **OWASP** | A03:2025 — Software Supply Chain Failures |
| **CVSS 4.0** | 9.1 — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | † Capped from CRITICAL (base 9.1) to MEDIUM. The attack needs a prior compromise of a third party (a hostile release of a dependency or of a PyPI package), which this repository does not control. A reviewer who counts a hijacked dependency as in scope would keep CRITICAL |
| **Baseline** | New |
| **Component** | CI/CD — release and publish workflows |
| **File** | `.github/workflows/release.yml:32,103,281` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

Two long-lived credentials are present in jobs that also compile and run code the project does not control. The release workflows check out the repository with a personal access token (`repo` and `workflow` scopes) and leave it in the job's git configuration, then run `cargo build --workspace`, whose build scripts and procedural macros come from every dependency. The crates.io token is set in the environment of the step that runs `cargo publish`, which compiles the workspace again. Neither secret is bound to a protected environment with required reviewers.

| Member | Credential | Exposed to | Where |
| --- | --- | --- | --- |
| G-1 | `PAT_TOKEN`, a personal access token with `repo` and `workflow` scopes | Build scripts and macros of all dependencies in the same job, and an unpinned, unhashed `pip install cyclonedx-bom` | `release.yml:32,103,178,281`; `update-generated-docs.yml:69,87,138` |
| G-3 | `CRATES_IO` registry token | The workspace compilation performed by `cargo publish --all-features --workspace` | `cargo-publish.yml:61-66`; `test_all.yml:381-399`; `main.yml:6-8` |

#### Evidence

- `.github/workflows/release.yml:32` (the token has `repo` and `workflow` scopes), `:103` and `:281` (checkout with `PAT_TOKEN`), `:178` (`cargo build --workspace` in the same job), `:352` (runs a script taken from the checked-out branch).
- `.github/workflows/update-generated-docs.yml:69` (checkout with the PAT), `:87` (`pip install cyclonedx-bom --quiet`, not pinned and without hashes), `:138` (`git push origin "$REF"`).
- `.github/workflows/cargo-publish.yml:64-66` (`CARGO_REGISTRY_TOKEN` on the step that runs `cargo publish`), `.github/workflows/test_all.yml:381-399` (called for every tag once the tests pass), `.github/workflows/main.yml:6-8` (starts on every tag).
- Only `supply-chain.yml:74`, `test_all.yml:21` and `test-group.yml:67` set `persist-credentials: false`. The only job `environment:` is `xks-remote-approval` (`test_all.yml:280`).
- The analysis agents also flagged `nix-update-hashes.yml`, `package-and-commit-sbom.yml` and `main.yml:82`. Verification judged the exposure there overstated, so they are not counted.

#### Attack Scenario

1. An attacker publishes a hostile release of a crate in the dependency tree (it reaches the build through a merged lock-file update) or of the unpinned `cyclonedx-bom` package.
2. At the next release run, its build script or installer runs in the job that holds the PAT in the git configuration, or the crates.io token in the step environment, and sends the value out.
3. With the PAT the attacker pushes to branches and tags and edits workflows (`workflow` scope). With the registry token the attacker publishes a malicious version of the workspace crates.

Preconditions: a hostile dependency or PyPI release reaches a release run. All `uses:` references are pinned to full commit SHAs and fork pull requests get no secrets, which leaves dependencies and the pip package as the entry points. Static trace, not executed.

**Proposed Fix** (review before applying)

- Compile in a job that holds no credential. Give a minimal final job a short-lived token (a GitHub App installation token or a fine-grained PAT limited to this repository) to push and tag, bound to a protected `environment` with required reviewers.
- Set `persist-credentials: false` on every checkout that does not push. Pin `cyclonedx-bom` by version and hash, or remove the vestigial install.
- Verify the crates without a token, then run `cargo publish --no-verify` in a minimal job under a protected environment, or use crates.io Trusted Publishing. Restrict the trigger to release tags (`v*`).

---

### [F-013] 🟡 MEDIUM — Dangerous opt-out switches (CSE token validation, Azure EKM client authentication) are not gated behind `insecure`

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing, Elevation of Privilege |
| **CWE** | CWE-306: Missing Authentication for Critical Function |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 8.3 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | † Capped from HIGH (base 8.3) to MEDIUM. Each switch is an explicit operator opt-out whose help text says it is for tests. The cloud-route amplifier is declined for the same reason: it needs the operator to turn the control off |
| **Baseline** | New |
| **Component** | Cloud routes — Google CSE and Azure EKM configuration |
| **File** | `crate/server/src/config/command_line/google_cse_config.rs:20-30` |
| **Confidence** | 9/10 |
| **Status** | Open |

#### Description

`--google-cse-disable-tokens-validation` makes the Google CSE handlers skip token validation and act as the configured default user, so an anonymous caller can ask for the plaintext data-encryption key of any wrapped document key that user can unwrap. `--azure-ekm-disable-client-auth` removes the mutual-TLS and authentication middleware from the Azure EKM scope, and the handlers then fall back to the default user. Neither switch is behind the `insecure` build feature, unlike the comparable JWT relaxation in `jwt_config.rs`. The Azure switch logs a `warn!` at start-up, the CSE switch only a `debug!` line when a request arrives, and neither makes the server refuse to start.

#### Evidence

- `crate/server/src/config/command_line/google_cse_config.rs:20-30`: the `disable_tokens_validation` option and its environment variable `KMS_GOOGLE_CSE_DISABLE_TOKENS_VALIDATION`.
- `crate/server/src/start_kms_server.rs:980-982`: the switch also removes CSE authentication from the server configuration.
- `crate/server/src/routes/google_cse/operations.rs:288-290` (`get_user_and_resource_name` returns `default_username` with `debug!("no token validation")`) and `:783-785` (`privileged_unwrap` does the same before unwrapping the key).
- `crate/server/src/config/command_line/azure_ekm_config.rs:35-45`: "WARNING: This bypasses mTLS authentication entirely."
- `crate/server/src/start_kms_server.rs:1499-1503` (only a `warn!`) and `:1521-1527` (the authentication middleware is installed only when the switch is off).
- `crate/server/src/core/kms/permissions.rs:371-379`: `get_user` falls back to `default_username` when no authenticated user is attached. The Azure handlers call it at `routes/azure_ekm/mod.rs:104,133,160,187`.

#### Attack Scenario

1. An operator enables `--google-cse-disable-tokens-validation` to debug an integration and keeps it in a production configuration. The server starts without a warning.
2. A network client that can reach `/google_cse` sends `privilegedunwrap` with a wrapped key and no valid tokens. The server treats the caller as the default user.
3. The server returns the plaintext data-encryption key of the document. With the Azure switch the same caller can use the EKM wrap and unwrap operations without a certificate.

Preconditions: the operator set a switch, and the routes are reachable. Static trace, not executed.

**Proposed Fix** (review before applying)

- Compile both switches behind the `insecure` feature, or refuse to start in release builds when either is set.
- Make `get_user` fail closed when an authentication method is configured but no identity is attached to the request. Log a `warn!` at start-up for every opt-out switch that remains.

---

### [F-014] 🟡 MEDIUM — User identity is the unverified `email` claim

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing, Elevation of Privilege |
| **CWE** | CWE-290: Authentication Bypass by Spoofing |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 7.6 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | † Capped from HIGH (base 7.6) to MEDIUM. The attack needs an identity provider (or a tenant of one) that lets a user choose a verified-looking `email`, which the documentation tells operators not to allow |
| **Baseline** | Known open item D1 of the PR #998 review (flat identity namespace). The new angle is that `email_verified` is never read |
| **Component** | JWT authentication middleware |
| **File** | `crate/server/src/middlewares/jwt/jwt_token_auth.rs:144-166` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The KMS uses the token's `email` claim as the user identity, or `sub` when `email` is absent. It never reads `email_verified`, and it does not add the issuer or realm to the identity. The same rule applies to the browser login callback. An identity provider that lets a user set an unverified `email`, or two listed issuers that both issue the same value, therefore yield the same KMS user, with the same ownership and the same native grants, including an administrator name. The documentation states the requirement ("Only trust issuers whose identity namespace you control, and do not let users choose their own `email`"), but nothing in the code enforces or warns about it.

#### Evidence

- `crate/server/src/middlewares/jwt/jwt_token_auth.rs:144-149` (a non-blank `email` becomes the identity) and `:151-166` (otherwise `sub`). `:56` returns the first configured issuer that validates the token.
- `crate/server/src/routes/ui_auth.rs:359-379`: the callback takes `email` from the ID token and opens the session for it.
- `crate/interfaces/src/user_id.rs:23` rejects only an empty identity. The string `email_verified` does not occur in `crate/`.
- `documentation/docs/configuration/authorization/opa-authverifier-setup.md:23-24` documents the requirement.

#### Attack Scenario

1. The KMS trusts an identity provider (for example a multi-tenant or self-registration directory) where users can set their own `email`, or a second listed issuer is less strictly managed.
2. The attacker registers an account whose `email` equals the name of a KMS administrator or key owner, and signs in. The token validates because it is correctly signed.
3. The KMS maps the token to the victim's identity and grants the victim's keys and permissions.

Preconditions: an identity provider that allows unverified or self-chosen `email` values. Static trace, not executed.

**Proposed Fix** (review before applying)

- Reject tokens with `email_verified=false`, or build the identity from `(iss, sub)` or from a per-issuer configured claim.
- Log a start-up warning when more than one issuer is configured and the identity is not namespaced.

---

### [F-015] 🟡 MEDIUM — No CRL or OCSP revocation checking on mTLS client certificates

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing, Repudiation |
| **CWE** | CWE-299: Improper Check for Certificate Revocation |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 7.6 — `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | † Capped from HIGH (base 7.6) to MEDIUM. The attack needs a client certificate or key that was already compromised and then revoked, and the limitation is documented for EST. The vector uses `PR:L` because the certificate belonged to a legitimate principal. With `PR:N` it scores 9.1 |
| **Baseline** | New. A documented limitation for EST only |
| **Component** | TLS and mTLS client authentication (HTTPS listener and KMIP socket server) |
| **File** | `crate/server/src/tls_config.rs:208-218` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

Both listeners verify a client certificate against the configured CA store and nothing more. A search of `crate/server/src` and `crate/crypto/src` for `CRL_CHECK`, `X509VerifyFlags`, `add_crl` and `set_verify_callback` finds no revocation check, only code that publishes CRLs. The user identity is derived once per connection, and the HTTP listener closes a connection only after 120 seconds without traffic, so a connection that stays active outlives a revocation. Revoking a certificate in the KMS PKI therefore does not stop it from authenticating. The EST page states the limitation ("The TLS layer does not check revocation of other client certificates"), but the SPIRE integration page tells operators to "Revoke via CRL/OCSP" and to "Revoke the old certificate" after a key compromise.

#### Evidence

- `crate/server/src/tls_config.rs:208` (the client CA store), `:217-218` (`set_verify_cert_store`, `SslVerifyMode::PEER`: on the HTTPS listener a client certificate is optional).
- `crate/server/src/socket_server.rs:623`: `PEER | FAIL_IF_NO_PEER_CERT` for the KMIP socket server. `:36` caps the connections at 1,024.
- `crate/server/src/middlewares/tls_auth.rs:90`: the certificate and its chain are mapped to a user once per connection.
- `crate/server/src/start_kms_server.rs:1922-1924`: keep-alive is an idle timeout of 120 seconds.
- `documentation/docs/use_cases/pki-enrollment-est.md:246-247` (the limitation) and `documentation/docs/integrations/spire_spiffe_kmip_plugin.md:412,429` (the revocation advice).
- Mitigations present: certificates issued through EST are refused for authentication, and TLS session resumption is off.

#### Attack Scenario

1. A client key of a user or of a KMIP service (for example the SPIRE server) leaks. The administrator revokes the certificate and publishes a CRL.
2. The attacker connects to the HTTPS listener or the KMIP socket with the revoked certificate. The server checks the chain and the validity dates only, and maps the certificate to the user.
3. The attacker keeps the user's access until the certificate expires or the CA is removed. A connection that was already open stays authenticated after the revocation.

Preconditions: mTLS client authentication is in use and a revoked certificate with its key is in the attacker's hands. Static trace, not executed.

**Proposed Fix** (review before applying)

- Enable `X509_V_FLAG_CRL_CHECK` with the CRLs of the client CAs (the KMS already generates them), or an OCSP check, with a fail-open or fail-closed setting.
- Re-evaluate the cached identity periodically and cap the age of a connection. Correct the SPIRE page, or implement the check it assumes.

---

### [F-016] 🟡 MEDIUM — Self-hosted runner host SSH key mounted into a mutable root container (8 jobs)

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege, Tampering |
| **CWE** | CWE-522: Insufficiently Protected Credentials |
| **OWASP** | A03:2025 — Software Supply Chain Failures |
| **CVSS 4.0** | 7.0 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:H/SA:N` |
| **Rating basis** | † Capped from HIGH (base 7.0) to MEDIUM. The jobs run only for tags, pushes to `develop` and `main`, the schedule and manual dispatch, so exploitation needs a prior compromise of a maintainer account, of the image or of a build dependency |
| **Baseline** | New |
| **Component** | CI/CD — self-hosted runners |
| **File** | `.github/workflows/packaging.yml:114-118,225-229,302-306` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

Eight jobs run on self-hosted runners inside the image `cosmian/docker_doc_ci`, which has no tag or digest and is therefore mutable, and bind-mount the SSH private key of the runner host (`/home/cosmian/.ssh/id_rsa`) into the container at `/root/.ssh/id_rsa`. The key logs in as `cosmian@package.cosmian.com`, the server that hosts the release packages, with a remote shell (the benchmark job pipes a script into `ssh … bash`). Anyone who can run code in one of these containers can read the key and replace published packages. `flamegraph.yml:126` also turns host-key checking off (`StrictHostKeyChecking=no`), whereas `benchmark.yml:354` uses `yes` with a pinned known-hosts file.

#### Evidence

- Mount lines: `.github/workflows/packaging.yml:118,229,306`, `packaging-apk.yml:270`, `packaging-kubernetes.yml:266`, `build_windows.yml:222`, `benchmark.yml:332`, `flamegraph.yml:112`. Each job names `image: cosmian/docker_doc_ci` without a tag or digest (for example `packaging.yml:116`) and runs on `[self-hosted, not-sgx]` (`packaging.yml:114`).
- `.github/workflows/flamegraph.yml:126-134` (`StrictHostKeyChecking=no`, remote `mkdir` and `tar` as `cosmian@package.cosmian.com`) and `.github/workflows/benchmark.yml:354-361`.
- Triggers: `.github/workflows/nightly.yml:9-19` (push to `develop`, `main` and every tag, manual dispatch, daily schedule), `packaging.yml:4-6` (called or dispatched by hand), `packaging-kubernetes.yml:18-25` (tags `v*`), `benchmark.yml:45,93` and `flamegraph.yml:22` (dispatch and schedule). None of these files has a `pull_request` trigger, so the `pull_request` clauses of the `publish-release` conditions (for example `packaging.yml:108`) cannot fire.

#### Attack Scenario

1. An attacker with write access to the repository (a compromised maintainer account) dispatches the packaging workflow on a branch whose workflow file prints the mounted key. Alternatively the attacker pushes a hostile `cosmian/docker_doc_ci` image, or a build dependency runs in one of the jobs.
2. The code reads `/root/.ssh/id_rsa` and sends it out.
3. The attacker logs in to `package.cosmian.com` and replaces the packages that users download.

Preconditions: one of the prior compromises above. Static trace, not executed. Whether the key has more rights on the package server than uploading is not visible from the repository.

**Proposed Fix** (review before applying)

- Pin the image by digest and use ephemeral runners. Replace the host key with a short-lived credential (OIDC) or an upload-only key restricted by `command=` and `restrict` options, under a protected `environment`.
- Use `StrictHostKeyChecking=yes` with a known-hosts entry everywhere. Publish the package GPG fingerprint off the package host, so clients can detect a swapped package.

---

### [F-017] 🟡 MEDIUM — Windows CNG key storage provider makes every key plaintext-exportable

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure, Elevation of Privilege |
| **CWE** | CWE-693: Protection Mechanism Failure |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 6.8 — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The attacker is a local process on the Windows host |
| **Baseline** | New. Related to F-011 |
| **Component** | Clients — Windows CNG key storage provider |
| **File** | `crate/clients/cng/src/provider.rs:354-357,1059-1060` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

When Windows opens or imports a key through the Cosmian KSP, the provider builds the key context with `allow_export: true` and `allow_plaintext_export: true`. The private-key export path is gated only by `allow_export`, so a local application that opens the key can export it as PKCS#8 in plaintext. The KSP never sets `Sensitive` or `Extractable` on the KMS key (the client source does not mention either attribute), so the KMS hands out the material as well. The documentation says the opposite: "Export policy is disabled by default ... so private keys cannot be extracted from the device" and "Private keys never leave the KMS".

#### Evidence

- `crate/clients/cng/src/provider.rs:354-357` (`open_key`) and `:1059-1060` (`import_key`): both set `allow_export: true` and `allow_plaintext_export: true`.
- `crate/clients/cng/src/provider.rs:968-971`: the private blob export is refused only when `allow_export` is false. `:399` shows that a key still being created starts with `ExportPolicy::default()` (both flags false, `key.rs:78-81`); the permissive policy is applied each time Windows opens or imports the persisted key. `crate/clients/cng/src/key.rs:393` implements `export_private_pkcs8`.
- `crate/server/src/core/operations/export_get.rs:72-73,103`: the KMS refuses a plaintext export only when `Extractable` is false, `NeverExtractable` is true or `Sensitive` is true. A key created without those attributes is exported.
- No occurrence of `sensitive` or `extractable` (any case) in `crate/clients/cng/src`.
- `documentation/docs/integrations/cloud_providers/microsoft/windows_cng_ksp.md:64,139,225,428,688` state that export is disabled and that private keys never leave the KMS.

#### Attack Scenario

1. A service on a Windows host uses a certificate key held in the KMS through the Cosmian KSP (for example for TLS or code signing).
2. Malware, or any user process that can call `NCryptOpenKey` on that provider, opens the key and calls `NCryptExportKey` with `PKCS8_PRIVATEKEY`.
3. The provider fetches the key material from the KMS and returns the plaintext private key. The key is now outside the KMS and can be used elsewhere without any KMS audit trail.

Preconditions: code running on the Windows host with access to the provider and the KMS credentials that the KSP is configured with. Static trace, not executed.

**Proposed Fix** (review before applying)

- Create the KMS keys with `Sensitive=true` and `Extractable=false` unless export is explicitly requested, and derive the export policy from the KMS attributes on open and import.
- Correct the documentation until the behaviour matches, and add a test that `NCryptExportKey` of a private blob returns `NTE_PERM` for a key opened normally.

---

### [F-018] 🟡 MEDIUM — Secrets printed in info-level startup logs

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-532: Insertion of Sensitive Information into Log File |
| **OWASP** | A09:2025 — Security Logging and Alerting Failures |
| **CVSS 4.0** | 6.7 — `CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The reader is someone with access to the log sinks who does not otherwise hold the secrets |
| **Baseline** | Incomplete fix of COSMIAN-2026-014 and COSMIAN-2026-038 |
| **Component** | Server start-up logging |
| **File** | `crate/server/src/start_kms_server.rs:573` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

At the default `info` level the server logs two complete configuration dumps with the pretty `Debug` formatter: the parsed command-line and file configuration, then the derived server parameters. Each dump hides some secrets and prints others. The server parameters print the proxy basic-auth password and the custom proxy authentication header in clear. The command-line configuration prints the Google CSE migration key PEM, which the server parameters do mask, and, in non-FIPS builds, the Redis URL with its credentials next to a fixed `password: [****]` label. Values that the operator supplied through `secret://` references are resolved before the dump, so the feature meant to keep a secret out of configuration files does not keep it out of the logs. A characterisation test pins the proxy-password leak as expected behaviour, and the two advisories above describe the masking as done.

#### Evidence

- `crate/server/src/main.rs:14-15` (default `RUST_LOG` is `info`) and `:229` (`info!("Command line / file config: {clap_config:#?}")`).
- `crate/server/src/start_kms_server.rs:573`: `info!("KMS Server configuration: {server_params:#?}")`.
- `crate/server/src/config/params/proxy_params.rs:59-60`: the `Debug` implementation prints `basic_auth_password` and `custom_auth_header`.
- `crate/server/src/config/command_line/clap_config.rs:749-752` prints `google_cse_migration_key`; `crate/server/src/config/params/server_params.rs:1503-1505` masks the same value as `[PEM key provided]`.
- `crate/server/src/config/command_line/db.rs:247-253` prints the Redis URL as is.
- `crate/server/src/routes/lint_cleanup_characterization_tests.rs:207-208` asserts that the proxy password appears in the output.

#### Attack Scenario

1. The KMS runs with default logging and ships its standard output to a log platform, a container log API or a syslog collector that more people can read than hold the KMS secrets.
2. A reader of the start-up lines copies the proxy credentials, the custom proxy header, the CSE migration key or the Redis URL.
3. The reader uses the proxy credentials to send traffic as the KMS, the Redis URL to reach the Redis store directly, or the migration key to sign CSE migration tokens.

Preconditions: the secrets are configured and the logs are readable by a party that should not have them. Static trace, not executed.

**Proposed Fix** (review before applying)

- Print every credential as `[configured]`. Wrap secrets in a `Secret<T>` type whose `Debug` is redacted, and change the pinned test to assert the redaction.
- Stop logging `ClapConfig` wholesale: log an allow-list of non-secret fields at `info` and the rest at `trace`.

---

### [F-019] 🟡 MEDIUM — Backend errors collapse to empty results; fail-open CRL generation

| Field | Value |
| --- | --- |
| **STRIDE** | Tampering, Denial of Service |
| **CWE** | CWE-755: Improper Handling of Exceptional Conditions |
| **OWASP** | A10:2025 — Mishandling of Exceptional Conditions |
| **CVSS 4.0** | 6.3 — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `AC:H` and `AT:P` because the failure must be confined to one query at the moment a CRL is generated |
| **Baseline** | New |
| **Component** | Database layer and CRL generation |
| **File** | `crate/server_database/src/core/database_objects.rs:497,541,610,625,677` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

Five lookup wrappers turn any backend error into an empty list (`unwrap_or_default`, or `unwrap_or(vec![])`) and return `Ok`. Nothing is logged, and the metrics wrapper records a success, so callers cannot tell "no object" from "the query failed". CRL generation searches the revoked certificates through one of these wrappers. If that query fails, for example on a statement timeout or on one row the backend cannot decode, the server signs a valid CRL with fewer entries or none, persists it (a persistence failure only logs a warning), caches it and serves it publicly. The OCSP responder uses the same helper and answers `unknown` instead of `tryLater`. The HSM name lookup cache keeps an empty `hsm::` result for one hour, so a swallowed error hides a key for that long. Other call sites follow the same pattern.

#### Evidence

- `crate/server_database/src/core/database_objects.rs:497` (`find_with_options`), `:541` (`find_all_with_options`), `:610` (`find_wrapped_by`), `:625` (`find_due_for_rotation`), `:677` (`find_by_rotate_name_uncached`): all return `Ok` after the error is swallowed.
- `crate/server/src/core/operations/generate_crl.rs:482-484` (the `?` after `find_all` can never see a backend error), `:421-426` (a failed persist only warns), `:429-433` (the new CRL is cached and served).
- `crate/server/src/core/certificate/find.rs:83-85`: the OCSP lookup swallows the error the same way.
- `crate/server_database/src/core/rotate_name_cache.rs:52,165-167`: an empty `hsm::` result is cached for 3,600 seconds. Same pattern at `crate/interfaces/src/hsm/hsm_store.rs:686,688` and `crate/server/src/core/operations/batch_undo.rs:220`.
- Mitigation present: the CRL signer loads the issuer certificate and key first, so a total database outage usually fails earlier. The default CRL validity is 7 days.

#### Attack Scenario

1. A certificate is revoked and listed in the published CRL. Later the database returns an error to the revoked-certificate query only (a statement timeout under load, a lock error, or one undecodable row).
2. The next regeneration (an explicit `generate-crl`, the scheduled job, or a revocation when `kms_public_url` is set) signs a CRL without the revoked certificate and replaces the cached copy.
3. Relying parties accept the revoked certificate again until a later regeneration succeeds, up to the CRL validity period.

Preconditions: a failure confined to that query at generation time. Static trace, not executed.

**Proposed Fix** (review before applying)

- Return the error from the five wrappers. Keep the previous CRL when the revoked-certificate search fails, and raise an alert.
- Answer `tryLater` or `internalError` on OCSP backend errors. Never cache an empty result that came from an error, and bound the HSM negative TTL.

---

### [F-020] 🟡 MEDIUM — Auth Verifier login rate limiter is keyed on the connection IP

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 6.3 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `AT:P` because the effect depends on the deployment: the limiter keys on the TCP peer, which is the KMS process or a reverse proxy |
| **Baseline** | New |
| **Component** | Auth Verifier — login rate limiter, and the KMS Web UI login relay |
| **File** | `authentication/server/src/middleware/login_rate_limit.rs:112-119` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The Auth Verifier throttles `/login` with a token bucket keyed on the TCP peer address (5 requests per second, burst 10, by default) and deliberately ignores forwarded headers. The KMS Web UI relays every browser login to the Auth Verifier from the KMS process (`POST /ui/login_as`, reachable without authentication), so all UI users share the KMS address as their key, as do all clients behind a reverse proxy. A caller that sends more than about 5 requests per second to `/ui/login_as` empties the shared bucket. Every genuine login then receives a 429 from the Auth Verifier, which the KMS turns into a 401. There is no per-account throttle. The KMS' own limiter is off unless `rate_limit_per_second` is set.

#### Evidence

- `authentication/server/src/middleware/login_rate_limit.rs:112-119`: the key is `req.peer_addr()`.
- `authentication/server/src/server/parameters/server_params.rs:96-102` (defaults 5 and 10) and `authentication/server/src/server/auth_verifier.rs:423-426,452-457` (the limiter is built once and wraps the `/login` scope, and the SAML login scope when that feature is built).
- `crate/server/src/routes/ui_auth.rs:441` (`#[post("/login_as")]`), `:515-516` (the credentials are posted to the Auth Verifier), `:530-535` (every non-success status becomes a 401).
- `crate/server/src/start_kms_server.rs:1125-1129`: the KMS logs that request rate limiting is disabled when the option is unset.

#### Attack Scenario

1. The Web UI login through the Auth Verifier is enabled.
2. An anonymous attacker posts about ten login attempts per second to `/ui/login_as`. The KMS relays each one from the same address, and the shared bucket stays empty.
3. Genuine users cannot sign in to the Web UI and see a 401. Bearer tokens and API keys keep working. The 5-per-second figure is an estimate from the defaults, not measured.

Preconditions: UI login through the Auth Verifier is enabled. Static trace, not executed.

**Proposed Fix** (review before applying)

- Pass the end-user address to the Auth Verifier through a header that it accepts only from the configured KMS, and key the bucket on the pair (username, address). Add per-account throttling with back-off.
- Rate-limit `/ui/login_as` on the KMS by client address, and return 429 rather than 401 when the upstream throttles.

---

### [F-021] 🟡 MEDIUM — Kubernetes operator is a confused deputy for KMSSecret tenants

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege, Tampering, Information Disclosure |
| **CWE** | CWE-441: Unintended Proxy or Intermediary (Confused Deputy) |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 6.1 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The multi-tenant amplifier (CRITICAL) is declined: what the operator can read depends on the grants of its KMS identity, which the repository does not define. If that identity is broad, a reviewer should rate this finding CRITICAL |
| **Baseline** | New |
| **Component** | Kubernetes operator (`KMSSecret` controller) |
| **File** | `crate/clients/k8s/operator/src/controller.rs:41,102,168-172` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The operator watches `KMSSecret` resources in every namespace and, for each one, reads the KMS object named in `spec.secretId` with a single KMS identity configured for the operator. A tenant who may create a `KMSSecret` in a namespace, but has no KMS access, can therefore make the operator copy any object that identity may read into a Secret in the tenant's namespace. The write uses server-side apply with `.force()` and no owner or managed-by check, so one key of an existing Secret in the same namespace can be overwritten. The operator also patches `restartedAt` on Deployments and StatefulSets that the resource names. The writes stay in the resource's own namespace, so there is no cross-namespace write. The resource fields are unvalidated strings, the repository ships no RBAC manifests, and the documentation lists RBAC advice only.

#### Evidence

- `crate/clients/k8s/operator/src/controller.rs:41` (`Api::all`), `:102` (`get_secret_bytes(&obj.spec.secret_id)`), `:141,216,249` (writes use the resource's namespace), `:168-172` (`PatchParams::apply(…).force()`), `:219-223` (the restart annotation).
- `crate/clients/k8s/operator/src/config.rs:44,91,96,160-161`: one global KMS identity. `crate/clients/k8s/operator/src/crd.rs:37-66`: plain `String` fields, no validation.
- `documentation/docs/integrations/kubernetes/operator.md:200-201`: RBAC advice only, no tenant-isolation guidance.
- Not verifiable from the repository: the KMS grants of the operator identity, and the cluster RBAC.

#### Attack Scenario

1. A tenant user holds the right to create `KMSSecret` objects in namespace `team-a`.
2. The user creates a `KMSSecret` whose `secretId` is the identifier of another team's key, and whose target is a Secret in `team-a`.
3. The operator reads the object with its own identity and writes the material into the Secret, which the tenant can read.

Preconditions: the operator identity has KMS read access beyond the tenant's own objects, and the tenant can create `KMSSecret` objects. Static trace, not executed.

**Proposed Fix** (review before applying)

- Add a namespace-to-key allow-list in the operator configuration, or an admission policy that restricts `secretId` per namespace. Use per-namespace KMS credentials where possible.
- Refuse to patch Secrets that the operator does not own (owner reference or managed-by label), drop `.force()`, and document the minimum RBAC and the tenancy model.

---

### [F-022] 🟡 MEDIUM — `default_username` collision: an identity equal to the admin name inherits its privileges (hypothesis)

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing, Elevation of Privilege |
| **CWE** | CWE-290: Authentication Bypass by Spoofing |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 6.0 — `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `AC:H` and `AT:P` because the attacker must obtain an identity with exactly that name from an authentication source the repository does not control |
| **Baseline** | New (the SPIRE path is already guarded; the flat identity namespace itself is the known decision D1 of the PR #998 review) |
| **Component** | Identity mapping (mTLS, JWT, Auth Verifier) |
| **File** | `crate/server/src/middlewares/tls_auth.rs:203-212` |
| **Confidence** | 5/10 |
| **Status** | Open (hypothesis) |

#### Description

The configured `default_username` (`admin` unless changed) is a privileged identity. It needs no `Create` grant (`permissions.rs:285`), it may use any key to unwrap (`unwrap.rs:262-264`), the JWKS endpoint looks up published keys as that identity (`jwks.rs:155`), and the HSM admin list defaults to the same name (`hsm_config.rs:6`, `hsm_store.rs:146`). The SPIRE path refuses an entity whose name equals `default_username`. The mTLS, JWT, Auth Verifier and session paths never compare against it: they refuse only `*` and the reserved service identities. A credential whose subject is the string `admin` is therefore mapped to the operator identity. The operators are meant to use exactly such a credential, so the open question is who else can obtain that string: a self-service IdP profile, an Auth Verifier realm administrator, or a CA that issues common names on request. That depends on deployments the repository does not show, hence the hypothesis status.

#### Evidence

- `crate/server/src/middlewares/tls_auth.rs:203-212`: only `*` and `reject_reserved_service_identity` are refused.
- `crate/server/src/middlewares/spire_token.rs:200-205`: the guard that the other paths lack. Within `crate/server/src/middlewares/`, `default_username` appears only in `spire_token.rs`, in `api_token/api_token_middleware.rs:48` (the API token maps to that identity by design) and in `ensure_auth.rs:59` (no authentication configured).
- `crate/server/src/core/kms/permissions.rs:285`, `crate/server/src/core/wrapping/unwrap.rs:262-264`, `crate/server/src/routes/jwks.rs:155`, `crate/server/src/config/command_line/hsm_config.rs:6`.
- `crate/server/src/start_kms_server.rs:344-355`: the operator is expected to hold a credential whose subject equals `default_username`.
- `documentation/docs/configuration/authorization/opa-authverifier-setup.md:23-24`: "The identity is not namespaced".

#### Attack Scenario

1. The KMS accepts identities from more than one source (a client-certificate CA, an IdP, an Auth Verifier realm) and keeps the default `default_username`.
2. A party who can choose the identity string in one source obtains a credential whose subject is `admin`.
3. The KMS maps it to the operator identity: keys are created without a grant, any key can unwrap, and the HSM administration is open.

Preconditions: an authentication source that lets a non-operator pick that name. Static trace, not executed.

**Proposed Fix** (review before applying)

- Bind `default_username` to one configured authentication method (for example a certificate fingerprint or an issuer and subject pair) and refuse the same string from every other method, as the SPIRE path does.
- Do not default `hsm_admin` to a guessable name, and namespace identities by issuer.

---

### [F-023] 🟡 MEDIUM — CSI provider is a confused deputy: any pod can request any readable KMS object

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege, Information Disclosure |
| **CWE** | CWE-441: Unintended Proxy or Intermediary (Confused Deputy) |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 6.0 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The multi-tenant amplifier (CRITICAL) is declined: the leak needs one provider identity that serves several tenants and holds grants beyond one tenant, which the repository does not show. If that is the deployment, a reviewer should rate this finding CRITICAL |
| **Baseline** | New |
| **Component** | Clients — Kubernetes CSI provider |
| **File** | `crate/clients/k8s/csi_provider/src/service.rs:128,156` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The provider fetches whatever object the mounting pod names (`kmsUID` in the `SecretProviderClass`) using one KMS identity that is shared by every workload on the node. It reads no pod, namespace or service-account attribute, so the KMS cannot tell tenants apart. The identifier need not be guessed: a value that starts with `[` is a JSON tag list that the KMS expands to every object carrying those tags. The KMS still enforces its own permissions for the provider identity and refuses to export non-extractable or sensitive objects without a wrapping spec, so only extractable, non-sensitive objects that the provider may read leak. The file name (`objectName`) is copied into the response without the checks that `provider.proto` demands (no absolute path, no `..`).

#### Evidence

- `crate/clients/k8s/csi_provider/src/service.rs:128` (`fetch_secret_bytes(&self.client, &spec.kms_uid)`), `:156` (`path: spec.object_name.clone()`), `:177-193` (`parse_attributes` has no path or tenant check).
- `crate/clients/k8s/csi_provider/src/main.rs:64,70`: one `KmsClient` with one `api_key`. No occurrence of `csi.storage.k8s.io`, `podInfoOnMount` or `pod.namespace` in `crate/clients/k8s/csi_provider/src`.
- `crate/server/src/core/uid_utils.rs:62-75`: a tag list resolves to every matching object. `crate/clients/k8s/csi_provider_proto/src/provider.proto:80-83`: the path rules.
- `documentation/docs/integrations/kubernetes/csi-provider.md:236-243`: four security bullets, none on tenant isolation; `:112` refers to a `daemonset.yaml` that is absent from the repository.
- Not verifiable: the upstream CSI driver's own pod or namespace scoping, and the provider's grants in a real deployment.

#### Attack Scenario

1. A tenant may create a `SecretProviderClass` and a pod in its own namespace.
2. The tenant sets `kmsUID` to another team's key identifier, or to a tag list that matches it.
3. The provider fetches the object with its shared identity and returns it as a file, which the tenant's pod reads.

Preconditions: one provider identity serves several tenants (the documented topology) and has read access to an extractable, non-sensitive object of another tenant. Static trace, not executed.

**Proposed Fix** (review before applying)

- Use per-workload KMS credentials (the pod service-account token that the CSI driver can pass), or a namespace-to-object allow-list in the provider configuration.
- Validate `objectName` as the proto requires, refuse tag lists, and document the tenancy model.

---

### [F-024] 🟡 MEDIUM — UI session cookie is stateless and irrevocable; TTL not enforced server-side

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing, Repudiation, Elevation of Privilege |
| **CWE** | CWE-613: Insufficient Session Expiration |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | 6.0 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `AT:P` because the cookie must first be captured (it is `HttpOnly`, so not by script). With an administrator's cookie (`VI:H`) the same vector scores 7.6 |
| **Baseline** | Variant of COSMIAN-2026-043 (the cookie variant; that fix covers the bearer token and the `_ea_` cookie) |
| **Component** | Web UI backend-for-frontend session |
| **File** | `crate/server/src/start_kms_server.rs:1393-1400,721-752` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

The Web UI session is an `actix-session` `CookieSessionStore` cookie: the whole state (`user_id`, `roles`, `domain`) is sealed into the cookie and nothing is kept on the server. The library documents that such a session cannot be invalidated before its natural expiry; its `delete` and `update_ttl` do nothing, and the 24-hour `session_ttl` only sets the browser `Max-Age`, outside the sealed payload, which holds no expiry. Logging out removes the cookie in the browser only. The cookie middleware re-checks nothing but the reserved identity, so a captured cookie keeps its roles after the account is disabled or the Auth Verifier session is revoked. The session middleware is wrapped on every native scope, so the cookie authenticates KMIP calls as well as the UI. With `ui_session_salt` set (the documented high-availability setting) the sealing key is stable, so rotating it is the only way to invalidate cookies. Code comments call this a server-side session, which it is not.

#### Evidence

- `crate/server/src/start_kms_server.rs:1393` (`CookieSessionStore`), `:1395-1398` (`HttpOnly`, `SameSite=Lax`, `Secure` only when the public URL is `https` or TLS is on, `:1267`), `:1400` (`session_ttl(24h)`), `:1275-1276,1292` (deterministic key with a salt, random per process without).
- `crate/server/src/routes/ui_auth.rs:57-62` (no timestamp in the state), `:590` (Auth Verifier liveness checked at login only), `:760` (`session.purge()`).
- `crate/server/src/middlewares/session_auth.rs:85-97` (only the reserved-identity re-check), `:3` (comment), `crate/server/src/start_kms_server.rs:2090-2092` (wrapped on the native scopes), `crate/server/src/core/kms/permissions.rs:528` (cached roles feed the OPA context).
- `actix-session-0.8.0` `src/storage/cookie.rs:46-47,56-58,66,92-98` and `src/middleware.rs:415-418`.
- `documentation/docs/configuration/ui.md:152,224,232-235`: revocation is described for the Auth Verifier session, not for this cookie.

#### Attack Scenario

1. A user signs in to the Web UI; the browser stores the sealed `auth_session` cookie.
2. The cookie is captured: plain-HTTP interception where `https` is not configured, a proxy or log capture, a shared workstation or a HAR file.
3. The user logs out or an administrator disables the account, and the cookie still authenticates. The attacker replays it against the UI backend or KMIP as that user, past the 24 hours, until the key changes.

Preconditions: a captured cookie. Static trace, not executed. Whether the cookie-session code shipped in a tagged release was not determined; that decides whether SECURITY.md needs an entry (AGENTS.md §5.5).

**Proposed Fix** (review before applying)

- Keep sessions server-side (idle and absolute timeouts, revocation), or add an `iat` claim and a per-user epoch or deny-list that `SessionAuth` checks, and re-resolve roles on each request.
- Revoke the Auth Verifier session on logout in every Auth Verifier flow, and correct the comments and the documentation.

---

### [F-025] 🟡 MEDIUM — CRL fetch buffers the response before the size cap; CRL cache is unbounded

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 6.0 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `PR:L` because a KMIP user who may call `Validate` or `Import` is needed; `AT:P` because the KMS must be able to reach an attacker-controlled host |
| **Baseline** | Incomplete fix of COSMIAN-2026-021 |
| **Component** | KMIP Validate — CRL retrieval |
| **File** | `crate/server/src/core/operations/validate.rs:595,769-795` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

The fix for COSMIAN-2026-021 added a 10 MiB cap on a fetched CRL, but the cap does not bound the allocation. The code reads `Content-Length` and treats a missing or chunked length as 0, then buffers the whole body with `response.bytes().await`, and only afterwards compares the length with the cap. A server that streams a chunked body keeps filling the KMS' memory until the 30-second deadline. Its comment says the cap prevents unbounded allocation, which it does not. The fetched bytes then enter a process-wide cache that is keyed by URI, has no entry or size limit, and drops only entries older than 300 seconds when a new one is inserted. Entries are cached before the CRL is parsed or verified. A caller who submits certificates with many distinct distribution points therefore grows the cache by up to 10 MiB per URI within each 5-minute window.

#### Evidence

- `crate/server/src/core/operations/validate.rs:769-770` (`content_length().unwrap_or(0)`), `:778` (`response.bytes().await`), `:782` (cap tested afterwards), `:765-766` and `:593` (comments), `:795` (insertion before parsing), `:45-47` (cache), `:794` (age-based pruning only), `:707` (30-second timeout).
- Callers: `crate/server/src/core/operations/import.rs:130-145` and `validate.rs:296`.

#### Attack Scenario

1. An authenticated user who may call `Validate` (or `Import`) submits a certificate whose CRL distribution point is a host that the attacker controls.
2. The attacker's server answers with a chunked body that never ends, or ends at 10 MiB, for each request, and the user sends many requests in parallel.
3. Memory use grows with the number of concurrent fetches and, for the cache, with the number of distinct URIs. The server runs with `panic = "abort"`, so an allocation failure ends the process. The memory figure depends on the attacker's bandwidth: an estimate, not executed.

Preconditions: a KMIP user with `Validate` or `Import`, and an outbound path from the KMS to the attacker's host. Static trace, not executed.

**Proposed Fix** (review before applying)

- Read the body as a stream with a byte counter and abort at the cap. Parse and verify the CRL before caching it.
- Bound the cache by entry count and total bytes, cap the distribution points per request, and limit concurrent fetches.

---

### [F-026] 🟡 MEDIUM — MS DKE scope uses permissive CORS with credentials

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-942: Permissive Cross-domain Policy with Untrusted Domains |
| **OWASP** | A02:2025 — Security Misconfiguration |
| **CVSS 4.0** | 6.0 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `UI:P` because a user inside the network must visit the attacker's page. The browser behaviour is an inference from the CORS response, not tested, hence 5/10 |
| **Baseline** | Variant of COSMIAN-2026-039, which restricted CORS on `/v1/crypto`, `/tokenize` and `/ui` only |
| **Component** | MS DKE routes (`/ms_dke`) |
| **File** | `crate/server/src/start_kms_server.rs:1451-1476` |
| **Confidence** | 5/10 |
| **Status** | Open |

#### Description

The `/ms_dke` scope is wrapped in `Cors::permissive()`. In the locked `actix-cors` 0.6.5 that policy allows every origin, method and header, exposes every response header, and supports credentials. The scope offers a decryption oracle for DKE content keys (`POST /ms_dke/{key_name}/{key_id}/decrypt`). The DKE documentation states that the Office client sends no authentication and that the deployment must rely on a firewall, so the network position is the control that CORS then defeats: any page that runs in a browser inside the firewall may call the endpoint and read the answer. The key URL is part of the sensitivity-label configuration (`index.md:81-90` of the DKE guide), so it is not secret from the users of the label. The `/google_cse` and `/aws` scopes use the same policy, but their requests carry a bearer token or a signature that a foreign page cannot forge, so the policy is inert there. The server configuration documentation says that these scopes keep the permissive policy because their integration contracts require it; the origins that DKE actually needs were not checked.

#### Evidence

- `crate/server/src/start_kms_server.rs:1476` (`.wrap(Cors::permissive())`) in the `/ms_dke` scope that starts at `:1451`; the authentication wrapper at `:1452-1455` is active only when a native authentication method is enabled, otherwise the default user is injected (`ensure_auth.rs:57-59`).
- `actix-cors-0.6.5/src/builder.rs:94-113` (all origins, credentials supported); the `allow_private_network_access` option exists only behind the `draft-private-network-access` feature and is `false` (`:114-115`).
- `crate/server/src/routes/ms_dke/mod.rs:182-220` (`decrypt` calls `kms.decrypt`).
- `documentation/docs/integrations/cloud_providers/microsoft_365_double_key_encryption_dke/index.md:62-63` (no authentication, firewalling is critical); `documentation/docs/configuration/server_configuration_file.md:870-872`.

#### Attack Scenario

1. An organisation runs DKE as documented: no client authentication, reachable only from the internal network.
2. An attacker who holds a DKE-protected document and knows the key URL and an encrypted content key (taken from the DKE protocol; not checked against Microsoft's specification) gets an employee to open a web page.
3. Script on the page posts the encrypted content key to the internal `/decrypt` URL from the employee's browser and reads the decrypted key, because the permissive policy allows it. The attacker decrypts the document.

Preconditions: DKE without authentication behind a firewall, and a browser that allows the request to a private address (Chrome's private-network preflight may block it; not tested). Static trace, not executed.

**Proposed Fix** (review before applying)

- Replace `Cors::permissive()` on `/ms_dke` with an explicit allow-list of the origins that the DKE protocol requires (to be confirmed against Microsoft's DKE documentation), without credentials.
- Document in the DKE guide that a firewall alone does not protect against browser-originated requests, and offer an authenticated deployment mode.

---

### [F-027] 🟡 MEDIUM — Database rows and ceremony records are unauthenticated (no AAD binding)

| Field | Value |
| --- | --- |
| **STRIDE** | Tampering, Information Disclosure |
| **CWE** | CWE-353: Missing Support for Integrity Check |
| **OWASP** | A08:2025 — Software or Data Integrity Failures |
| **CVSS 4.0** | 5.9 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The attacker needs write access to the database (`PR:H`). Two members share one root cause, a missing binding of stored data to its owner |
| **Baseline** | New |
| **Component** | Database layer — at-rest integrity |
| **File** | `crate/server_database/src/ceremony_keys.rs:105,135` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The server authenticates some stored data with AES-GCM, but binds it to nothing that identifies its owner, so a database writer can move valid records around. The ceremony records that activate the Crypto Officer role are sealed with the role name as the only associated data, and the unsealed payload (including `activated_by`) is discarded: any valid sealed record counts as an activation for whichever user's row holds it, and the revocation flag is a plaintext column. Stored key blobs are wrapped under the server KEK without the UID or owner as associated data, and the owner, state and read-access data are plain columns in the SQL backends. The module documentation claims that the GCM tag prevents forging ceremony records through direct database writes. On the SQL backends a writer already controls the plain ownership columns, so only the key-substitution effect is new there; on Redis-findex, where ownership is protected, the writer can at least undo a revocation.

| Member | Where | Weakness | Effect |
| --- | --- | --- | --- |
| Ceremony records | `ceremony_keys.rs:105,135`, `database_permissions.rs:223` | Associated data is the role only; the payload is not compared with the row | A copied record activates another configured candidate; a revoked record can be un-revoked (SQL column, Redis JSON flag) |
| Key blobs | `wrap.rs:64-67`, `wrap_key.rs:360`, `unwrap_key.rs:344` | Empty associated data; the KEK is optional | Blobs can be swapped between UIDs (valid under one KEK); without a KEK, key material is stored unwrapped |

#### Evidence

- `crate/server_database/src/ceremony_keys.rs:8-9` (claim), `:105` and `:135` (associated data is `role.as_bytes()`), `:198,214` (tests cover tampered bytes and a wrong role only).
- `crate/server_database/src/core/database_permissions.rs:213-224` (the unsealed payload is dropped); `crate/server_database/src/stores/sql/query.sql:211-226` (`activated_by` and `revoked_at` are plain columns); `crate/server_database/src/stores/redis/redis_with_findex.rs:870-891,918-919` (plaintext JSON with `revoked_at`).
- `crate/server/src/core/kms/permissions.rs:348`: an activated Crypto Officer owns every non-HSM object.
- `crate/server/src/core/wrapping/wrap.rs:64-67`; `crate/server/src/start_kms_server.rs:1119-1123` (start-up warning when no KEK is set). Contrast: `crate/server_database/src/stores/redis/objects_db.rs:176,199` bind the UID as associated data.
- Not verified: whether `authorized_kms_unwrapping_key` (`unwrap.rs:188`) accepts a swapped blob at runtime.

#### Attack Scenario

1. An attacker with write access to the database (stolen credentials, a SQL administrator, or a Redis writer) selects a valid sealed ceremony record, or a revoked one.
2. On SQL the attacker inserts the copied record for a configured candidate; on Redis the attacker clears `revoked_at`.
3. The server treats the user as an active Crypto Officer, with ownership rights over every non-HSM object, or accepts swapped key blobs as genuine.

Preconditions: database write access, a configured Crypto Officer candidate, and `crypto_officer_require_ceremony` enabled for the first path. Static trace, not executed.

**Proposed Fix** (review before applying)

- Use role, user and activation identifier as associated data, require the unsealed `activated_by` to equal the row user, and seal or MAC the revocation state. Mirror this for Redis.
- Bind each stored key blob to its UID and owner, and refuse to start without a KEK outside a development profile.

---

### [F-028] 🟡 MEDIUM — `ckms.toml`, exported keys and decrypt outputs are written with the default umask

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-276: Incorrect Default Permissions |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 5.7 — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `AV:L` and `PR:L` (another account on the same host); `AT:P` because the umask must be permissive and the parent directories traversable |
| **Baseline** | New |
| **Component** | Clients — `ckms` CLI file output |
| **File** | `crate/clients/ckms/src/config.rs:57,65` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The CLI creates its secret-bearing files with `fs::write` and `File::create`, so the file mode is `0666` minus the umask (`0644` with the usual `022`). The saved configuration `ckms.toml` serialises the OAuth access token, the Vault token, the PKCS#12 password, the database secret, the OAuth client secret and refresh token, the proxy password and any custom header (all in plain text). Exported key files and decrypt outputs are written the same way. The config writer sits in the external crate `cosmian_config_utils` 0.7.2. In the client crates only the Kubernetes components set restrictive modes (operator `0400`, plugin and CSI sockets `0660` and `0600`); no `set_permissions` or `mode(0o…)` call exists for the files above.

#### Evidence

- `crate/clients/ckms/src/config.rs:57,65` (`save` calls `to_toml`); `cosmian_config_utils-0.7.2/src/config_utils.rs:147` (`fs::write`) and `:182` (`create_dir_all`).
- `crate/clients/client/src/file_utils.rs:67-68` (`write_bytes_to_file`, `fs::write`); `crate/clients/clap/src/actions/shared/export_key.rs:171,177,194`; `crate/clients/clap/src/actions/symmetric/decrypt.rs:144-145` (`File::create`, default output `input.plain`).
- Secret-bearing fields: `crate/clients/client/src/http_client/client.rs:61,67,71,82,84,88,100`; `crate/clients/client/src/http_client/login.rs:19,32`; `crate/clients/client/src/http_client/proxy_params.rs:16`.

#### Attack Scenario

1. A user logs in with `ckms login` or exports a key to a file on a shared host (a jump host or a build server).
2. The file is created with mode `0644` in a directory that other accounts can traverse.
3. Another local account reads the token or the key and uses it against the KMS.

Preconditions: a multi-user host, a permissive umask, and a home or output directory that other accounts can enter. Static trace, not executed.

**Proposed Fix** (review before applying)

- Create these files with mode `0600` through `OpenOptions` and an atomic rename, create `~/.cosmian` with `0700`, and apply a restrictive ACL on Windows.
- Warn when an existing `ckms.toml` is group- or world-readable.

---

### [F-029] 🟡 MEDIUM — Raw internal error text returned in 5xx bodies (regression of COSMIAN-2026-013)

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-209: Generation of Error Message Containing Sensitive Information |
| **OWASP** | A10:2025 — Mishandling of Exceptional Conditions |
| **CVSS 4.0** | 5.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `PR:L` because most routes require authentication; a variant for an error raised before authentication scores 6.9 (no such route was traced) |
| **Baseline** | Regression of COSMIAN-2026-013 (reintroduced by commit `c45074fcd`, first in tag 5.29.0) |
| **Component** | HTTP error responses |
| **File** | `crate/server/src/routes/mod.rs:98-113` |
| **Confidence** | 10/10 |
| **Status** | Open |

#### Description

`error_response` builds the body from `self.to_string()` for every status, 5xx included, and the code comment says that the real message is returned on purpose. The tags 5.22.0 to 5.28.0 returned the fixed text `Internal server error`; commit `c45074fcd` (2026-10-09, "feat: add PGP support (via KMIP) and gnupg integration (#1240)") removed that branch, and tag 5.29.0 contains it. The 500-class variants include `Database` (whose text starts with `Database Error:`), `Redis`, `Findex`, `Certificate`, `Tls`, `CryptographicError`, `ServerError` and `Default`, so database, OpenSSL and path details reach the client. Some handlers add more text, for example `routes/utils.rs:37` returns the name of the public key that failed. SECURITY.md (COSMIAN-2026-013, `:1001-1016`) and CHANGELOG.md:1012 still state that the body is generic, and no test pins the behaviour. The SCEP handler shows the intended pattern: it logs the detail and returns a generic body to an unauthenticated caller (`scep/pki_operation.rs:190-193`).

#### Evidence

- `crate/server/src/routes/mod.rs:52-80` (statuses), `:98` (`self.to_string()`), `:100-104` (logged server-side), `:106-113` (body returned as `text/plain` with `nosniff`); `crate/server/src/error.rs:40`.
- Other sinks: `crate/server/src/routes/spire/error.rs:27`, `crate/server/src/routes/aws_xks/error.rs:225`, `crate/server/src/routes/aws_xks/sigv4_middleware.rs:160,212,240`, `crate/server/src/routes/google_cse/mod.rs:56`.
- `git log` for `c45074fcd` and `git tag --contains c45074fcd` (5.29.0 only); the earlier fix is `81c27ef63` (#928).

#### Attack Scenario

1. An authenticated caller sends a request that makes a back-end fail (a malformed object, a database constraint, a certificate parse error).
2. The server answers `500` with the internal error text, such as a database message, an OpenSSL error or a file path.
3. The caller uses it to map the deployment (back-end type, schema names, library versions) before a further attack.

Preconditions: a request that provokes a 500-class error. Static trace, not executed.

**Proposed Fix** (review before applying)

- Return a fixed body for every status of 500 or more and log the detail with a correlation identifier that the response carries.
- Add a regression test per 500-mapped variant, and correct SECURITY.md and CHANGELOG.md.

---

### [F-030] 🟡 MEDIUM — Audit logging is opt-in and covers only two production call sites

| Field | Value |
| --- | --- |
| **STRIDE** | Repudiation |
| **CWE** | CWE-778: Insufficient Logging |
| **OWASP** | A09:2025 — Security Logging and Alerting Failures |
| **CVSS 4.0** | 5.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `VI:L` is the integrity of the evidence trail; the finding concerns missing evidence, not the access itself. Declined amplifier: if the reviewer applies the cloud-provider route amplifier (§6 of the analysis principles) to the unaudited provider scopes, the rating would be CRITICAL; it is not applied here |
| **Baseline** | New (the documentation overstates coverage for the socket transport) |
| **Component** | Audit subsystem |
| **File** | `crate/server/src/start_kms_server.rs:1858,1888` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

The hash-chained audit pipeline is attached by `AuditMiddleware` to two Actix scopes only: `/v1/crypto` (`:1858`) and the default KMIP scope (`:1888`). EST and SCEP self-audit from the handlers. The only other production `enqueue` call is in the middleware itself, so these paths produce no per-request event: the KMIP socket server (its handler calls `handle_ttlv_bytes` directly), the Google CSE, MS DKE, AWS XKS and Azure EKM scopes, Tokenize, the Vault and SPIRE routes and the UI. Audit is also off by default. The documentation promises a trail of "every KMIP operation, including authentication failures", which the socket transport does not meet. Separately, a `/kmip` request that fails before the handler injects the operation context (invalid JSON, a root other than `RequestMessage`) is answered with HTTP 200 and an error TTLV; the middleware derives `Success` from the 200 status and names the operation `kmip`, so a rejected request is recorded as a success. Batch items that do reach the dispatcher are recorded correctly, with a per-item result (pinned by `tests/audit_middleware.rs`).

#### Evidence

- `crate/server/src/start_kms_server.rs:1858,1888` (the only `AuditMiddleware::new` calls); unwrapped scopes `:1429`, `:1476`, `:1487`, `:1520-1535`; socket handler `:626-636`.
- Production `enqueue` call sites: `crate/server/src/middlewares/audit/mod.rs:199,239`; `crate/server/src/routes/enrollment.rs:167`.
- Default off: `crate/server/src/config/command_line/audit_config.rs:123-129`; docs `documentation/docs/configuration/audit-logs.md:3-4,8`.
- Pre-decode failures: `crate/server/src/routes/kmip/handlers.rs:382-387,420-422,431,647-652`; `crate/server/src/middlewares/audit/mod.rs:228-236`; `crate/server/src/middlewares/audit/client_ip.rs:13-19`.

#### Attack Scenario

1. An operator enables audit and relies on it for compliance.
2. A holder of a valid mTLS certificate uses the KMIP socket server, or a caller uses a cloud-provider route, and exports or uses a key.
3. No event exists. During the investigation the chain verifies, so nothing signals the gap.

Preconditions: audit enabled and valid credentials for an unaudited transport. Static trace, not executed.

**Proposed Fix** (review before applying)

- Attach the audit hook to the socket handler and to each provider scope, or emit from the handlers (principal, key identifier, outcome).
- Record the KMIP `ResultStatus` rather than the HTTP status and record decode failures as `Failure`.
- Warn at start-up when audit is disabled or when a transport stays unaudited, turn it on in the packaged templates, and list the covered transports in the documentation.

---

### [F-031] 🟡 MEDIUM — UsageLimits bypass through batch Undo and non-atomic read-modify-write

| Field | Value |
| --- | --- |
| **STRIDE** | Tampering, Abuse |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow (the race: CWE-362) |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 5.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `PR:L`: the caller needs a crypto permission on the limited key. `VI:L`: a usage policy is bypassed; no key material leaves |
| **Baseline** | New |
| **Component** | KMIP operations — usage limits and Undo |
| **File** | `crate/server/src/core/operations/batch_undo.rs:91,116-122,355-362` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The KMIP `UsageLimits` attribute caps what a key may process. Two weaknesses let a caller exceed it. (a) With the batch option `Undo`, a failing item makes the server restore the pre-item snapshot of every object the earlier items changed, including Encrypt, Decrypt, Sign, SignatureVerify, MAC and MACVerify, and the restore writes the whole pre-state back, counter included. The earlier items' output stays in the response: `mark_undone` changes only the status to `Operation Undone` and keeps the payload (to follow the OASIS test case BL-M-2-21). The caller keeps the ciphertext or the signature, and the counter is back to its initial value. (b) The counter is decremented by a read-modify-write: the limit is checked on the copy loaded at the start of the request and the decremented copy is written back with `update_object`, whose SQL has no version predicate although a version-guarded variant exists. Two concurrent requests that read the same value consume one unit. The Undo compare-and-set is documented in the code as two separate statements.

#### Evidence

- `crate/server/src/core/operations/message.rs:521-525,703-729` (Undo mode, revert after a failed item) and `:1300-1316` (`mark_undone` keeps the payload).
- `crate/server/src/core/operations/batch_undo.rs:91,116-122` (data operations are snapshotted), `:329-333` (acknowledged race), `:355-362` (pre-state written back).
- `crate/server/src/core/operations/key_ops/crypto_op.rs:555` (check on the loaded copy), `:822-824` (unconditional update); `crate/interfaces/src/stores/object_with_metadata.rs:281`; `crate/server_database/src/stores/sql/query.sql:85` against `:87-88`.

#### Attack Scenario

1. An owner creates an AES key with a usage limit of N operations and grants Encrypt to a service account.
2. The service account sends one batch with the continuation option `Undo`: `Encrypt(K, data)` followed by an item that fails, such as a `Get` of an unknown identifier.
3. The response carries the ciphertext with the status `Operation Undone`, and the counter of K is restored.
4. Repeating step 2 gives unlimited encryptions; Decrypt, Sign and MAC behave the same way.

Preconditions: a key with `UsageLimits`, a caller with the crypto permission, and a KMIP 2.1 batch request. Static trace, not executed; the race in (b) needs a concurrent run to demonstrate.

**Proposed Fix** (review before applying)

- Do not restore usage counters on Undo (or treat keys with `UsageLimits` as non-revertible), and withhold the payload of a data operation that is undone.
- Update the counter with `UpdateObjectIfVersion` and a retry, or with an atomic SQL decrement.
- Add a regression test: `Encrypt` plus a failing item under `Undo`, then assert the remaining count.

---

### [F-032] 🟡 MEDIUM — CRL distribution-point SSRF guard checks IP literals only

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure, Elevation of Privilege |
| **CWE** | CWE-918: Server-Side Request Forgery (SSRF) |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 5.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. `PR:L`: Validate is open to every role. `VC:L`: the response is parsed as a CRL and discarded, so only a status, timing and error oracle reaches the caller (blind, GET only) |
| **Baseline** | Variant of COSMIAN-2026-021, COSMIAN-2026-028 and COSMIAN-2026-035 |
| **Component** | Certificate validation — CRL fetch |
| **File** | `crate/server/src/core/certificate/mod.rs:12-13,27,47,83,99` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

`validate_crl_url` rejects non-HTTP schemes, blocked IP literals and three internal names (`localhost`, `*.local`, `*.internal`), but a DNS name is never resolved (`Host::Domain(_) => false`). Any other name passes, including one that the attacker's DNS maps to `127.0.0.1`, a private address or the metadata address. The fetch uses a `reqwest` client with redirects disabled and a 30 s timeout but no address check at connect time. COSMIAN-2026-035 fixed exactly this class in the Google CSE path (resolve, check every address, pin the checked one); the CRL path was left with the literal-only guard. The IPv4 blocklist is also short: `100.64.0.0/10`, `168.63.129.16`, `198.18.0.0/15`, multicast and the NAT64 prefix pass, as does any port. The error text of a non-success status names the URI and the status code, and a connection failure is a soft failure, so the caller can tell open from closed.

#### Evidence

- `crate/server/src/core/certificate/mod.rs:12-13` (blocked IPv4 set), `:19-30` (`is_blocked_ip`), `:39-47` (three names), `:83` (scheme), `:96-100` (literals only), `:110` (names).
- `crate/server/src/core/operations/validate.rs:685-687` (guard, skipped for the KMS public URL), `:702-707` (client, no pinning), `:745-751` (fetch), `:758-762` (status in the error), `:895-908` (soft failure).
- Reference pattern: `crate/server/src/routes/google_cse/operations.rs:76-100` (`lookup_host`, check of every address, `builder.resolve`). Validate is open to every role: `crate/access/src/access.rs:132`.

#### Attack Scenario

1. An authenticated user submits a certificate whose CRL distribution point is `http://crl.attacker.example/x.crl`, a name that resolves to an internal or unblocked address.
2. `validate_crl_url` accepts the name; the KMS sends the GET from its own network position.
3. The body is not a CRL and is discarded, but the status code, the timing and the connect error come back to the caller.
4. The caller maps internal hosts and ports.

Preconditions: a network path from the KMS to the target and no egress policy that stops it. Static trace, not executed.

**Proposed Fix** (review before applying)

- Reuse the Google CSE helper (resolve, check every address, pin) for the CRL fetch and extend the blocklist with the special-purpose ranges of RFC 6890, `168.63.129.16` and `64:ff9b::/96`.
- Allow only ports 80 and 443, offer an optional egress allow-list, and make the status text generic. When an HTTP proxy is configured the proxy resolves the name, so the egress policy must be enforced there.

---

### [F-033] 🔵 LOW — Session-key KDF uses the public URL as the password (offline test via an anonymous cookie)

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing, Information Disclosure |
| **CWE** | CWE-331: Insufficient Entropy |
| **OWASP** | A04:2025 — Cryptographic Failures |
| **CVSS 4.0** | 9.1 † — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | † Capped to LOW. The base score is in the CRITICAL band, but the attack works only when the operator has independently chosen a guessable salt of 32 bytes or more, a failure the attacker can neither cause nor observe (`AT:P`). Read literally, the vector would make this CRITICAL; with `VC:L/VI:L` (a cookie that carries little privilege) the base is 6.3 (MEDIUM) |
| **Baseline** | New |
| **Component** | Web UI session key derivation |
| **File** | `crate/server/src/start_kms_server.rs:947,955-958,727-748` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

`derive_session_key_from_url` derives the 64-byte cookie encryption key with the **public URL as the KDF password** and a salt taken from `SHA-256(ui_session_salt ‖ "v1" ‖ public_url)`. The only secret input, `ui_session_salt`, is therefore used as a salt: it is hashed and truncated to 16 bytes, while the password is a value every client knows. The start-up check accepts any value of 32 bytes or more (`salt.len()` counts bytes, not entropy). The list of weak values that follows can never match, because each entry is shorter than 32 characters and the length check rejects it first. The documented placeholder (`change-me-and-keep-secret`, 25 bytes) is refused, and a lengthened placeholder passes.

An anonymous `GET /ui/login_flow` stores a `nonce` in the session and returns a sealed `Set-Cookie`, which gives an attacker an authenticated ciphertext to test guesses against offline. PBKDF2-SHA512 with 210,000 iterations (FIPS) or Argon2id with 19 MiB (non-FIPS) raises the cost of each guess, not the size of the search space. A hit yields the cookie key, so the attacker can seal a session that carries a chosen `user_id`, `roles` and `domain`.

#### Evidence

- `crate/server/src/start_kms_server.rs:721-752` (`salt_input` at `:727`, password at `:748`), `:945-953` (byte-length check), `:955-958` (unreachable weak-word list), `:1275-1276` (use), `:1288-1293` (random key when no salt is set).
- `crate/crypto/src/crypto/password_derivation.rs:25,45` (PBKDF2-SHA512, 210,000 iterations), `:97-100` (Argon2id: 2 passes, 19,456 KiB, one lane).
- `crate/server/src/routes/ui_auth.rs:78,135` (anonymous `GET /ui/login_flow` writes the session). `crate/server/src/middlewares/session_auth.rs:85-97` (identity, roles and domain are read from the session).
- `crate/server/src/config/command_line/ui_config.rs:59-70` (help text calls it a secret); `documentation/docs/configuration/configurations.md:369` (placeholder).

#### Attack Scenario

1. The attacker requests `GET /ui/login_flow` and keeps the `Set-Cookie` value.
2. Knowing the public URL and the KDF parameters (both public), the attacker derives a candidate key for each guess of `ui_session_salt` and tries to open the cookie.
3. With the right guess the cookie opens and the key is known.
4. The attacker seals a session for a chosen identity and presents it to the routes that accept a session.

Preconditions: UI enabled with `ui_session_salt` set to a guessable value of at least 32 bytes. The guessing is offline, so the server sees one ordinary request. Static trace, not executed.

**Proposed Fix** (review before applying)

- Use the secret as the KDF password or HKDF input and the URL as context: `derive_key_from_password(salt = H(version ‖ url), password = ui_session_salt)`. Existing session cookies stop working at the upgrade; say so in the changelog.
- Replace the byte-length check with a format check that carries entropy (hex or base64 of at least 32 random bytes, matching the `openssl rand -hex 32` hint in the message), or generate and store the secret in the wizard. Delete the unreachable weak-word list.
- Change the documentation sample so it does not invite a human-chosen phrase.

---

### [F-034] 🔵 LOW — Vault-token and login clients have no timeout or redirect policy and accept `http://`

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service, Spoofing |
| **CWE** | CWE-400: Uncontrolled Resource Consumption |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 6.3 † — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |
| **Rating basis** | † Capped to LOW. The base score is in the MEDIUM band, but the harm needs a failure the attacker cannot cause: a slow, unreachable or hostile Auth Verifier, or an operator who set `http://` or switched certificate verification off (`AT:P`). The vector scores only the availability effect. Read literally, it would make this MEDIUM |
| **Baseline** | New |
| **Component** | Outbound authentication clients |
| **File** | `crate/server/src/routes/ui_auth.rs:498-500,852-853` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The clients that call the Auth Verifier use `reqwest` defaults. The Vault-token client has neither a timeout nor `redirect::Policy::none()`, can disable certificate verification, and is shared by the Vault-token authentication (`lookup-self`) and by the unauthenticated `/v1/auth/{tail:.*}` proxy, which reads the whole upstream body. The UI login client has no timeout either; the logout client has a 10 s timeout but follows redirects. `auth_verifier_url` is parsed with `url::Url::parse` only, so `http://` is accepted, whereas JWKS URIs must be HTTPS unless certificate verification is disabled. A failed Vault-token lookup is not cached, so each request with a bogus token costs one outbound call. The liveness client in `session.rs` is the model: 10 s timeout and `Policy::none()`.

A stalled Auth Verifier leaves every such request waiting with no deadline, and the proxy forwards responses with no size cap. Over `http://` the token lookup and its answer cross the network in clear, so a network attacker can read tokens and forge an answer.

#### Evidence

- `crate/server/src/start_kms_server.rs:1300-1323` (client: no timeout, no redirect policy, `danger_accept_invalid_certs` at `:1303-1304`), `:1472,1602,1622,1640` (sharing), `:1072-1077` (HTTPS check for JWKS skipped when invalid certificates are accepted).
- `crate/server/src/middlewares/spire_token.rs:30-31` (`X-Vault-Token`), `:138-139` (`lookup-self`), `:252-256` (only a success is cached).
- `crate/server/src/routes/spire/auth_proxy.rs:80,93` (`send`, then the whole body).
- `crate/server/src/routes/ui_auth.rs:498-500` (login client), `:851-855` (logout client). `crate/server/src/config/params/server_params.rs:992-998` (URL parsed, scheme not checked). Contrast: `crate/server/src/middlewares/auth_verifier/session.rs:73-76`.

#### Attack Scenario

1. The operator enables the Vault/SPIRE API with an Auth Verifier URL.
2. The Auth Verifier stalls: an outage, a network fault, or a hostile peer after a route or DNS hijack.
3. Each request that carries an arbitrary `X-Vault-Token`, or that hits `/v1/auth/...`, opens an upstream call that is never abandoned. Tasks and sockets accumulate and the endpoint stops answering.

Preconditions: `vault_api_enabled` and `auth_verifier_url` set (off by default) and an unavailable or hostile upstream. Static trace, not executed.

**Proposed Fix** (review before applying)

- Build one hardened client for every Auth Verifier call: connect and total timeouts, `redirect::Policy::none()`, an HTTPS-or-loopback requirement on `auth_verifier_url`, and a size cap on the proxied body.
- Add a short negative cache per token hash so bogus tokens do not each cost an upstream call.
- Restrict `auth_verifier_accept_invalid_certs` to `insecure` builds; today it also skips the HTTPS check on JWKS URIs.

---

### [F-035] 🔵 LOW — The Marvin (RUSTSEC-2023-0071) ignore justification is false for the CSE migration JWT

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-1395: Dependency on Vulnerable Third-Party Component |
| **OWASP** | A03:2025 — Software Supply Chain Failures |
| **CVSS 4.0** | 2.3 — `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The exposure is a remote timing attack on a blind, noisy oracle: the signed JWT goes to the KACLS, not back to the caller (`AC:H`, `AT:P`), and signing uses a blinded call. The weight of the finding is the false statement that carries the risk acceptance. The FIPS amplifier is not applied: the algorithm is approved, but the implementation is outside the OpenSSL FIPS provider; a reviewer who reads the amplifier rule as covering non-validated implementations would rate this CRITICAL |
| **Baseline** | New (invalidates the basis of COSMIAN-2025-011) |
| **Component** | Google CSE routes and dependency policy |
| **File** | `crate/server/src/routes/google_cse/operations.rs:994-999` |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

`deny.toml`, `.cargo/audit.toml`, `sbom/openvex.json` (`not_affected`, `vulnerable_code_not_in_execute_path`) and `SECURITY.md` justify ignoring RUSTSEC-2023-0071 (Marvin, `rsa 0.9.10`, no patched release) because `rsa` only runs public-key operations. The Google CSE migration route runs a private-key operation: `create_jwt` builds an `RS256` header and calls `EncodingKey::from_rsa_der(private_key_bytes)` and `encode`. In jsonwebtoken 10.4.0 with the `rust_crypto` backend this loads the key with `RsaPrivateKey::from_pkcs1_der` and signs with `SigningKey::sign_with_rng`. The route is compiled into every build, FIPS included. The key is the KMS-held private key, fetched unwrapped as PKCS#1. The `ckms` client has a second private-key use for a service-account key (`from_rsa_pem`).

#### Evidence

- `crate/server/src/routes/google_cse/operations.rs:994-999` (header, key, `encode`), `:978` (`create_jwt`), `:1074-1079` and `:1091` (key retrieval), `:1111-1112` (call), `:1058-1065` (Migrator gate). `crate/server/src/routes/mod.rs:29` (not feature-gated).
- `Cargo.toml:294` (`jsonwebtoken` with `rust_crypto`); `Cargo.lock` (`rsa 0.9.10`); jsonwebtoken-10.4.0 `src/crypto/rust_crypto/rsa.rs:32-40`.
- The false statements: `deny.toml:73`, `.cargo/audit.toml:8`, `sbom/openvex.json:15-18`, `SECURITY.md:1284`; the acceptance: `SECURITY.md:1269` (COSMIAN-2025-011).
- `crate/clients/clap/src/actions/google/gmail_client/token.rs:60` (`EncodingKey::from_rsa_pem`).

#### Attack Scenario

1. An attacker who can call the Migrator rewrap route points it at a KACLS URL that passes the SSRF checks and that the attacker controls.
2. Each call makes the KMS sign a JWT with the private key and send it to that URL.
3. The attacker times the calls and applies a Marvin-style analysis to the signing time.

Preconditions: a valid Migrator token and a very large number of calls over a noisy network path. Static trace, not executed.

**Proposed Fix** (review before applying)

- Sign the migration JWT with OpenSSL (`crate/crypto`, the FIPS provider in FIPS builds), or use a jsonwebtoken backend that delegates to OpenSSL.
- Until then, correct the four texts, mark `RUSTSEC-2023-0071` as `affected` with a mitigation in the VEX file, and re-evaluate the COSMIAN-2025-011 acceptance. Track `rsa` 0.10 or later.

---

### [F-036] 🔵 LOW — Auth Verifier JWKS is refetched only when the cache is empty

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service, Spoofing |
| **CWE** | CWE-324: Use of a Key Past its Expiration Date |
| **OWASP** | A04:2025 — Cryptographic Failures |
| **CVSS 4.0** | 2.3 — `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. Only the availability effect is scored. Stale trust in a revoked key does not let a forged token pass, because the session-liveness check (COSMIAN-2026-043) asks the Auth Verifier whether the session is live |
| **Baseline** | New |
| **Component** | Auth Verifier token validation |
| **File** | `crate/server/src/middlewares/auth_verifier/token.rs:214-220` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

Token validation refreshes the cached JWKS only when the cache is empty. There is no periodic refresh and no refresh when a token carries an unknown `kid`. By default the Auth Verifier signs session JWTs with its TLS key pair, so a certificate renewal that generates a new key pair changes the signing key. The KMS keeps the old set until it restarts: valid sessions are refused, and a revoked old key keeps verifying signatures.

#### Evidence

- `crate/server/src/middlewares/auth_verifier/token.rs:214-220` (refresh only when `is_empty()`), `:206-211` (algorithm allow-list).
- `crate/server/src/middlewares/jwt/jwks.rs:63-68` (the whole map is replaced on a refresh).
- `authentication/pkg/auth_verifier.toml:88-89` (TLS key reused unless `[session_jwt_params]` is set); `authentication/server/src/server/parameters/server_params.rs:175-184` (key selection).

#### Attack Scenario

1. The Auth Verifier's TLS certificate is renewed with a new key pair, or its signing key is rotated after an incident.
2. New session JWTs carry the new key; the KMS cache holds only the old one.
3. Every new session fails signature verification and users get 401 until the KMS restarts. After a compromise of the old key, the old key still verifies, and only the liveness check stands between a forged token and access.

Preconditions: the Auth Verifier signing key changes while the KMS runs. Static trace, not executed.

**Proposed Fix** (review before applying)

- Refetch the JWKS when a token carries an unknown `kid` (throttled, for example once a minute) and on a timer, and keep the last good set when a fetch fails.
- Give the Auth Verifier a dedicated signing key with `kid` rotation through `[session_jwt_params]`.

---

### [F-037] 🔵 LOW — DeriveKey creates objects outside the Create permission gate

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege, Abuse |
| **CWE** | CWE-862: Missing Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 2.3 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The caller needs a `DeriveKey` right on a base key, and the effect is a policy bypass that adds objects the caller owns; no existing key is exposed. The KMS amplifiers do not apply |
| **Baseline** | New (design decision needed) |
| **Component** | Access control — role gate |
| **File** | `crate/access/src/access.rs:147,161-168` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The role gate (`Role::decide`) puts `DeriveKey` in the group that is always allowed, while every operation that creates an object (`Create`, `Import`, `CreateKeyPair`, `Register`, `ReKeyKeyPair`, `CreateSplitKey`) returns `RequireCreatePermission` for an Operator. `Certify` and `ReCertify` are in the allowed group too, but their handlers call `enforce_create_permission` themselves. `derive_key.rs` does not: it checks the `DeriveKey` right on the **base** key only, then stores a new object with the caller as owner and a caller-chosen UID, then writes a `DerivedKeyLink` onto the base key. A user who has been refused `Create` (a non-privileged user when `crypto_officer.users` is set, or an OPA identity whose role has `derive_key` but not `create`) can therefore still create keys, as long as it holds `DeriveKey` on one base key it owns or was granted. The documentation lists `DeriveKey` as a User operation and as an object-writing operation, but never says that it escapes the Create gate.

The writes to the base key are a read-modify-write of the owner's object by a grantee, so two concurrent derivations can lose a link (estimate, not executed). The derived object is stored with an empty domain, which is documented.

#### Evidence

- `crate/access/src/access.rs:112-113` (the rule), `:144-155` (`DeriveKey` in the allowed group), `:161-170` (the Create group).
- `crate/server/src/core/operations/dispatch.rs:157-161` (`RequireCreatePermission` is the only caller of the gate at dispatch).
- `crate/server/src/core/operations/derive_key.rs:194-195` (right on the base key), `:639-646` (client-chosen UID), `:669-678` (`database.create` with the caller as owner), `:684-707` (link written to the base key). No call to `enforce_create_permission` in the file; the gated handlers are `create.rs:48`, `create_key_pair.rs:60`, `import.rs:90`, `register.rs:35`, `recertify.rs:125`, `certify/resolve_subject.rs:81,314`.
- `crate/server/src/core/kms/permissions.rs:270-276` (a `Rekey` already needs the Create gate as a "creation operation").
- `documentation/docs/configuration/authorization/index.md:77,146` and `key_ceremony.md:100` (role tables).

#### Attack Scenario

1. An operator configures `crypto_officer.users` (or an OPA policy) so that only Crypto Officers may create objects.
2. A User holds `DeriveKey` on a base key (owned, or granted for a service workflow).
3. The User calls `DeriveKey` repeatedly with different UIDs and parameters. Each call stores a new key it owns, with no Create check and no quota.

Preconditions: a `DeriveKey` right on any key, and a deployment that relies on the Create gate as a quota or governance control. Static trace, not executed.

**Proposed Fix** (review before applying)

- Decide the policy first. If derived keys count as created objects (the reading of `permissions.rs:270-275`), call `enforce_create_permission` before `database.create`; otherwise document the exception in the role tables.
- Link the derived key back to its base on the derived object and skip the write to the base key, or do it in the same atomic operation.
- Stamp the domain on the derived object so the domain-scoped roles see it.

---

### [F-038] 🔵 LOW — `kmip.policy_id` is not enforced at JOSE and SPIRE transit entry points

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege, Tampering |
| **CWE** | CWE-693: Protection Mechanism Failure |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 2.3 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The control is a deployment policy, not a boundary; the routes still run their own checks (RSA of 2048 bits or more, allow-listed JOSE algorithms). The effect is that an algorithm a regulator forbade can still be created or used. The FIPS amplifier is not applied because the algorithms involved are approved, only not selected by the configured policy |
| **Baseline** | New |
| **Component** | JOSE and SPIRE transit routes |
| **File** | `crate/server/src/routes/jose/keys.rs:324-327,370` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

When `kmip.policy_id` is set, the algorithm policy is applied in one place, the KMIP dispatcher (`dispatch.rs:218-220`). The core operations do not repeat the check. The JOSE and SPIRE transit routes call the KMS methods directly (`create_key_pair`, `import`, `decrypt`), so they never reach the dispatcher. The only policy calls on those routes are an export check in `jose/encrypt.rs` (when a `cek_kid` is used), `csr.rs` and `enrollment.rs`. The documentation says that the policy is enforced "at request entry points", so an operator who selects a policy such as a restricted-algorithm profile expects it to hold for these routes. Two examples: JOSE key creation accepts any RSA size from 2048 bits, and `RSA-OAEP` maps to SHA-1 for both the hash and the MGF.

#### Evidence

- `crate/server/src/core/operations/dispatch.rs:215-220` (the only central enforcement); helpers in `core/operations/algorithm_policy.rs:54,104,202,285,415,534`.
- `crate/server/src/routes/jose/keys.rs:324-327` (size check without the policy), `:369-372` (`kms.create_key_pair`), `:666` (`kms.import`); `jose/decrypt.rs:201-212,412`; `jose/unwrap.rs:123,143,217`; `jose/algorithm.rs:416` (`RSA-OAEP` is SHA-1/SHA-1).
- `crate/server/src/routes/spire/transit.rs:409,537,560` (`kms.create_key_pair`).
- Policy calls that exist: `routes/jose/encrypt.rs:291`, `routes/csr.rs:120`, `routes/enrollment.rs:310,317`.
- `documentation/docs/certifications_and_compliance/cryptographic_algorithms/kmip_policy.md:3`.

#### Attack Scenario

1. An operator sets `kmip.policy_id` to forbid an algorithm or a key size for the whole server.
2. A user who may use the JOSE or Vault transit routes creates a key pair or decrypts with a parameter set the policy forbids, which the dispatcher would have refused on `/kmip`.
3. The server creates the key or performs the operation and returns the result, and the audit trail shows no policy denial.

Preconditions: `jose` or the Vault transit API enabled and a policy configured. Static trace, not executed.

**Proposed Fix** (review before applying)

- Enforce the policy inside the shared core primitives (`create_key_pair`, `import`, `decrypt`, wrap and unwrap) so that every entry point is covered, or call the helper from each route.
- Add a route-level test per entry point that sets a restrictive policy and expects a refusal.
- State in `kmip_policy.md` which routes the policy covers.

---

### [F-039] 🔵 LOW — Existence and state oracle on wrap and unwrap key lookup

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 2.3 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. Only existence, state and usage mask leak; no key material or attribute does. The caller needs the Create right to reach the unwrap path through `Import` |
| **Baseline** | Variant of COSMIAN-2026-037 |
| **Component** | KMIP wrapping |
| **File** | `crate/server/src/core/wrapping/unwrap.rs:188-281` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

COSMIAN-2026-037 is recorded as fixed in 5.29.0: key selection for the crypto operations checks the permission first and gives a missing key and a forbidden key the same answer. The wrap and unwrap lookups were not brought in line. In `authorized_kms_unwrapping_key` a missing key returns `NotSupported` ("does not exist or is not accessible"), a non-active key returns "is not active", a key without the unwrap usage bit returns "is not meant to unwrap keys", and only then is the permission checked (with a different text). The wrap path in `wrap.rs` already checks the permission before the state and the usage mask (the comment says why), but it still answers a missing key with `NotSupported` (HTTP 422) and a refusal with `Unauthorized` (401), so existence leaks there. Importing an object that names the wrapping key reaches the unwrap path.

#### Evidence

- `crate/server/src/core/wrapping/unwrap.rs:200-204` (missing key), `:245-249` (state), `:252-258` (usage), `:262-279` (permission, text at `:274-277`).
- `crate/server/src/core/wrapping/wrap.rs:389-393` (missing key), `:430-445` (permission first; `Unauthorized` at `:441`).
- `crate/server/src/core/operations/import.rs:90` (Create gate), `:233-234` (`unwrap_object`).
- `SECURITY.md:481-495` (COSMIAN-2026-037); `crate/server/src/core/operations/derive_key.rs:197-200` (the pattern to copy: one message for missing and refused).

#### Attack Scenario

1. A user with the Create right imports a wrapped object whose key-wrapping data names a UID the user guesses or collects.
2. The error text tells the user whether that UID exists, whether the key is active, and whether it is an unwrap key.
3. Repeating the request maps other users' key UIDs and their lifecycle state.

Preconditions: the Create right and a way to guess UIDs (for example tag names or UUIDs seen elsewhere). Static trace, not executed.

**Proposed Fix** (review before applying)

- Check the permission first on both paths and return one identical error (same type and text) for a missing key and a refused key.
- Add a test that compares the response for a foreign key and for an absent key on both paths.

---

### [F-040] 🔵 LOW — KMIP socket in-flight memory budget can be starved by a few slow mTLS clients

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-400: Uncontrolled Resource Consumption |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 2.3 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The attacker needs a client certificate that chains to the configured client CA and a socket server that is switched on (off by default). The impact is availability of the socket server only |
| **Baseline** | New |
| **Component** | KMIP socket server |
| **File** | `crate/server/src/socket_server.rs:36,313,473-476,537` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

COSMIAN-2026-032 bounded the socket server with a 1,024-connection cap and a process-wide 256 MiB budget of request bytes, reserved as `8 + length` immediately after the 8-byte header and before the body is read. The reservation is made from the length the client **declares**, and `vec![0_u8; size]` allocates lazily, so a client pays only for the bytes it actually sends. Four connections that each declare a frame of 64 MiB (three of the maximum size and a fourth of 64 MiB minus 32 bytes) hold the whole budget until each one has received its body or about 120 to 240 seconds have passed (the deadline is checked between reads). In that window every other client is refused and disconnected rather than queued. A client that reconnects keeps the budget exhausted. The budget is not per client, and the client name is read only after the request has been read, so it cannot be used to cap a single certificate. One certificate can also occupy all 1,024 connection slots. A pre-authentication variant (slots held for up to 10 s without a certificate) comes from reading only.

The HTTP listener is a separate path and is not affected by this budget; it has no global in-flight budget at all (64 MiB payload limit per request).

#### Evidence

- `crate/server/src/socket_server.rs:32,34` (timeouts), `:36` (1,024 connections), `:38,42` (64 MiB request, 256 MiB budget), `:313` (single semaphore), `:473-483` (request read, `client_username` after it, permit dropped after the response), `:528-546` (length check, reservation by declared length, fail-fast), `:549-564` (lazy buffer, deadline between reads), `:621-623` (mTLS, certificate required).
- `crate/server/src/start_kms_server.rs:1405-1410` (HTTP payload limits).
- `SECURITY.md` COSMIAN-2026-032 (the fix this finding builds on).

#### Attack Scenario

1. The attacker holds a valid client certificate, for example a compromised low-privilege service account.
2. It opens four connections and sends a header that declares a 64 MiB body, then sends nothing, or one byte at a time.
3. All other KMIP socket clients are refused until the attacker's connections time out; the attacker reconnects to repeat the cycle.

Preconditions: `socket_server_start` enabled and a certificate that the client CA accepts. Static trace, not executed.

**Proposed Fix** (review before applying)

- Reserve in small steps as bytes arrive, or allow a per-client share of the budget, and drop connections that fall below a minimum data rate.
- Read the client identity before the body and apply a per-identity connection and budget limit.
- Add an equivalent in-flight budget for the HTTP listener.

---

### [F-041] 🔵 LOW — Import marks an Active certificate Compromised on any CRL fetch error

| Field | Value |
| --- | --- |
| **STRIDE** | Tampering, Denial of Service |
| **CWE** | CWE-754: Improper Check for Unusual or Exceptional Conditions |
| **OWASP** | A10:2025 — Mishandling of Exceptional Conditions |
| **CVSS 4.0** | 2.1 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The attacker must influence what a CRL distribution point answers (or sit on the path of a plain `http://` fetch), and the importer must supply an `ActivationDate` and no `State`. The effect is a wrong, terminal lifecycle state on one imported certificate, not a loss of key material |
| **Baseline** | New |
| **Component** | KMIP Import — certificate validation |
| **File** | `crate/server/src/core/operations/import.rs:115,130,137-150` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

When a certificate is imported and its initial state is Active (the request carries an `ActivationDate` in the past and no `State`), `Import` fetches the CRLs named in the certificate and calls `verify_crls`. The result is matched in two arms. Any `KmsError::Certificate` stores the certificate as `Compromised`; every other error is described by the code comment as a "network or other transient error" and leaves it Active. The first arm is wider than a revocation. In the CRL fetch code `KmsError::Certificate` is also the error for a non-2xx HTTP answer, a response above the size cap, a body read error, a non-http(s) distribution point, a refusal by the SSRF guard (private, loopback, link-local or internal host names), and a failure to build the HTTP client. Only a connection-level failure becomes `ClientConnectionError`, which is the only error `verify_crls` skips.

A CDN or CRL server that answers `500`, `404` or `503` for a moment, a response that is too large, an on-path actor (distribution points are usually plain `http://`), or a certificate whose distribution point is an internal host name that the SSRF guard refuses therefore turns an Active import into a `Compromised` object. `Activate` refuses every state except `PreActive`, so the state cannot be repaired: the object can only be destroyed, and the certificate has to be imported again under another identifier. If the affected certificate is the CA configured as `ocsp_ca_uid`, the OCSP responder then answers `revoked` with the reason `cACompromise` for every serial it is asked about (RFC 6960 §2.7 cascade).

An expired CRL, a CRL without `nextUpdate` and a bad CRL signature are not affected: they return `ServerError`, which keeps the certificate Active.

#### Evidence

- `crate/server/src/core/operations/import.rs:52-66` (`initial_state`: Active when `ActivationDate` ≤ now), `:115-116` (a client-supplied `State` is kept and skips the check), `:120-153` (CRL check only for an Active certificate with no client `State`), `:137-143` (`Certificate` error stored as `Compromised`), `:144-150` (other errors keep Active), `:157` (state stored). Import requires the Create right (`:90`).
- `crate/server/src/core/operations/validate.rs:663-675` (non-http(s) URI returns `Certificate`), `:685-688` (SSRF guard runs before the fetch), `:743` (client build failure), `:747-751` (network errors become `ClientConnectionError`), `:758-762` (non-2xx status), `:771-787` (size caps), `:778-780` (body read error), `:895-908` (only `ClientConnectionError` is skipped; every other error propagates).
- `crate/server/src/core/certificate/mod.rs:75-119` (`validate_crl_url` returns `Certificate` for refused hosts).
- `crate/server/src/core/operations/activate.rs:117-129` (a `Compromised` object cannot be activated), `crate/server/src/core/operations/revoke.rs:397-403` (compromise transitions).
- `crate/server/src/routes/ocsp/handler.rs:303-306,343-347` (CA in `Compromised` state: every serial answered `revoked`, `cACompromise`), `crate/server/src/config/command_line/ocsp_config.rs:41` (`ocsp_ca_uid`).

#### Attack Scenario

1. An operator or an automation imports a CA or sub-CA certificate with an `ActivationDate` in the past and no `State`.
2. The CRL distribution point answers with an HTTP error or an oversized body. An attacker on the network path can inject that answer when the distribution point is a plain `http://` URL.
3. `Import` stores the certificate as `Compromised`. It cannot be activated again.
4. If this certificate is the configured OCSP CA, OCSP clients are told that every certificate it issued is revoked for key compromise.

Preconditions: the Create right (needed for Import), an `ActivationDate` and no `State` in the import request, and control over the answer of the distribution point (this is the `UI:A` of the vector: the importer takes part). Static trace, not executed.

**Proposed Fix** (review before applying)

- Mark a certificate `Compromised` only on a definitive revocation result. Return a distinct error or result type from `verify_crls` for "revoked", and treat every fetch, size, SSRF, parse or configuration error as "status unknown": keep the requested state and log a warning.
- Add tests with a distribution point that answers `500` and one that answers an oversized body; both must leave the imported certificate Active.

---

### [F-042] 🟠 HIGH — Unbounded `validity_days` aborts the whole server and lets a CRL carry a far-future `nextUpdate`

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service, Tampering, Repudiation |
| **CWE** | CWE-1284: Improper Validation of Specified Quantity in Input |
| **OWASP** | A10:2025 — Mishandling of Exceptional Conditions |
| **CVSS 4.0** | 7.1 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score; no cap and no amplifier. The vector assumes that no Crypto Officer is configured, so that every user can create the CA used for the request. With Crypto Officers configured the caller must also be one (`PR:H`), and the same vector scores 6.9 (MEDIUM). The ID comes from the first ranking pass, where the item was rated LOW; it was re-rated after the local probe showed a process abort |
| **Baseline** | New |
| **Component** | PKI — CRL generation |
| **File** | `crate/server/src/core/operations/generate_crl.rs:360-362,397` (route `crate/server/src/routes/crl.rs:23-24,48-101`) |
| **Confidence** | 9/10 |
| **Status** | Open (confirmed by local probe) |

#### Description

The authenticated endpoint `GET /certificates/{issuer_id}/crl` takes an optional `validity_days` of type `u32` (`routes/crl.rs:23-24`). `generate_crl` applies a lower bound only (`.max(1)`, `generate_crl.rs:360-362`), builds and signs the CRL with the requested validity, and only then computes the timestamp stored in the database as `generated_at + time::Duration::days(i64::from(validity))` (`:397`). OpenSSL accepted every value that was tested up to 2,900,000 days. The `time` crate limits `OffsetDateTime` to the years ±9999, and the `+` operator panics with "resulting value is out of range" beyond that. Both the release and the dev profile are built with `panic = "abort"`, so the panic ends the whole process, not just the request worker: every KMIP, REST, OCSP, CRL and cloud-provider endpoint of every tenant stops. Nothing is lost on disk, because the CRL is stored after the failing line; the service manager restarts the process, and the attacker can send the request again.

There is a second effect below the crash threshold. The CRL is signed with the chosen validity, and the cache entry is built from its `nextUpdate`. The public distribution point serves the cached CRL with `Cache-Control: public, max-age=…` derived from `nextUpdate` minus 60 seconds (`routes/crl.rs:196-204,226`), and the refresh cron regenerates a CRL only when its `nextUpdate` is inside the overlap window (`cron.rs:118-130`). A `nextUpdate` that is decades away therefore stops the periodic refresh, and relying parties that keep a CRL until its `nextUpdate` can hold an outdated revocation list. A new revocation still regenerates the CRL with the default validity, which limits the duration.

**Measured** on a local debug build (`target/debug/cosmian_kms`, OpenSSL 3.6.5, non-FIPS, SQLite, no authentication configured, scratch database; the FIPS and the release builds were not run). The CA was self-signed with `keyUsage=keyCertSign,crlSign,digitalSignature`, and the request was `ckms certificates generate-crl --certificate-id <ca> --validity-days N`:

| `validity_days` | Result |
| --- | --- |
| 7 (default) | CRL signed, `nextUpdate` one week later |
| 36500 | accepted, `nextUpdate` in October 2126 |
| 2,900,000 | accepted, `nextUpdate` in October 9966 |
| 2,950,000 | the server process terminated |

The server log shows `thread 'actix-server worker 11' panicked at crate/server/src/core/operations/generate_crl.rs:397:23: resulting value is out of range`, with the backtrace `Option::expect` ← `<OffsetDateTime as Add<SignedDuration>>::add` ← `generate_crl::sign_crl` ← `generate_crl` ← `routes::crl::get_crl`. The client saw `connection closed before message completed`, and the process was gone afterwards.

#### Evidence

- `crate/server/src/routes/crl.rs:23-24` (`validity_days: Option<u32>`), `:31-38` (any authenticated user with access to the CA; Crypto Officer required only when configured), `:48-101` (`get_crl`), `:196-204,226` (cache headers from `nextUpdate`).
- `crate/server/src/start_kms_server.rs:1909` (authenticated route in the default scope, with native authentication and `AuditMiddleware`). The public route `get_crl_public` (`:1805`) serves only the cached CRL and takes no parameter, so it is not a trigger.
- `crate/server/src/core/operations/generate_crl.rs:211-217` (Crypto Officer gate when configured), `:166-168` (issuer certificate read as the caller), `:312-328` (issuer private key read as the caller: `Get`, or `Certify` for an HSM key), `:360-362` (lower bound only), `:363-381` (build and sign before the date arithmetic), `:397` (panic site).
- `crate/server/src/cron.rs:118-130` (refresh only inside the overlap window).
- `Cargo.toml:179` (release `panic = "abort"`), `:203` (dev `panic = "abort"`).
- `pkg/cosmian_kms.service:10-11` (`Restart=on-failure`, `RestartSec=3s`), `charts/cosmian-kms/templates/deployment.yaml:141-142` (liveness probe).
- Released code: tag `cosmian-kms-5.29.0` has the same lower bound only (`.max(1)`) and the same `generated_at + time::Duration::days(i64::from(validity))` (`generate_crl.rs:327-330,363-365` in that tag) and `panic = "abort"` in its `Cargo.toml`. This was compared statically and not executed on the tag. A `SECURITY.md` entry will therefore be due when it is fixed (AGENTS.md §5.5).

#### Attack Scenario

1. The attacker is an authenticated user. When no Crypto Officer is configured every user holds the Create right, so the attacker can create a CA certificate that carries the `cRLSign` key usage (a CA without it is refused) and owns its private key.
2. The attacker calls `GET /certificates/<ca>/crl?validity_days=4294967295`.
3. The CRL is built and signed, the date addition at `generate_crl.rs:397` panics, and the whole server process aborts. All tenants lose every endpoint until the service manager restarts it (about 3 seconds with the shipped unit); the attacker repeats the call for a sustained outage.
4. Without a crash, `validity_days=36500` produces a CRL with a `nextUpdate` that is a century away, cached and served publicly with a long `max-age`.

Preconditions: an authenticated user with the `Get` right on the CA private key (an own CA is enough), plus the Crypto Officer role when Crypto Officers are configured. Measured on a local debug build as described above; the abort and the 2.9 million day boundary were observed, the effect on a relying party was not.

**Proposed Fix** (review before applying)

- Cap `validity_days` (a small multiple of `crl_default_validity_days`, for example 365 days at most) and answer `InvalidRequest` (HTTP 400) above the cap.
- Replace the addition at `generate_crl.rs:397` with `checked_add` and return an error on overflow; apply the same to every `OffsetDateTime + Duration` whose operand comes from a client (see F-051).
- Add a regression test with `validity_days = u32::MAX` that expects a client error and a live server, and one with the cap value.
- Same class: the rotation scheduler (F-051, measured) and, for HSM-backed keys only, `core/operations/attributes/set.rs` and `core/operations/rekey/symmetric/hsm.rs`, which need an HSM and were not run.

---

### [F-043] 🔵 LOW — PKCS#11 module advertises keys as non-extractable but serves `CKA_VALUE`

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-693: Protection Mechanism Failure |
| **OWASP** | A06:2025 — Insecure Design |
| **CVSS 4.0** | 2.0 — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The attribute values are a documented trade-off (a code comment cites Oracle TDE), and the bytes come from a KMS `Export` made with the KMS identity configured for the module, so the KMS permissions and its Extractable check remain the real boundary. The weakness is that a PKCS#11 consumer cannot rely on the attributes the module reports |
| **Baseline** | New (documented trade-off) |
| **Component** | Clients — PKCS#11 module |
| **File** | `crate/clients/pkcs11/module/src/core/object.rs:150-151,201-213,249-301` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The module builds the attribute table of each key in `core/object.rs`. For symmetric keys it answers `CKA_EXTRACTABLE=false`, `CKA_NEVER_EXTRACTABLE=true` and `CKA_SENSITIVE=true`, and for `CKA_VALUE` it returns the raw key bytes. For private keys it answers the same three attributes and returns the RSA private-key DER (or the PKCS#8 DER for the other algorithms) as `CKA_VALUE`. `C_GetAttributeValue` copies whatever the table returns and does not consult the attributes the module reports itself. The OASIS PKCS #11 v2.40 base specification says that when `CKA_SENSITIVE` is true or `CKA_EXTRACTABLE` is false the key value cannot be revealed in plaintext outside the token (§4.9 and §4.10), and that `C_GetAttributeValue` then reports `CK_UNAVAILABLE_INFORMATION` and `CKR_ATTRIBUTE_SENSITIVE` (§5.7). The code comment gives the reason for the symmetric keys: Oracle TDE requires `CKA_EXTRACTABLE=FALSE` and `CKA_SENSITIVE=TRUE` for master keys, so the module serves a key that it declares unreadable.

The bytes are fetched lazily from the KMS with an `Export` (`unwrap: true`, PKCS#8 or transparent symmetric key format) through the KMS client configured for the module. The KMS Get permission and its Extractable and Sensitive checks (`check_extractable_and_sensitive`) therefore still decide whether a key can be read at all. What is wrong is the contract towards the application: anything that drives the module is told the key is protected when it is not, and code running in the loading process obtains the grants of the module's KMS identity.

#### Evidence

- `crate/clients/pkcs11/module/src/core/object.rs:201-202` (symmetric `Extractable(false)`, comment on Oracle TDE), `:206` (`NeverExtractable(true)`), `:208-209` (`Sensitive(true)`), `:213` (`Value` = `sym_key.raw_bytes()`).
- `crate/clients/pkcs11/module/src/core/object.rs:249` (private `Extractable(false)`), `:276` (`NeverExtractable(true)`), `:281` (`Sensitive(true)`), `:286-302` (`Value` = RSA private DER or PKCS#8 DER), `:150-151` (`rsa_from_private_key` reads `pkcs8_der_bytes`).
- `crate/clients/pkcs11/module/src/pkcs11.rs:1059-1082` (`C_GetAttributeValue` copies the value of `object.attribute(type_)` to the caller without any `Sensitive` or `Extractable` check; `CKR_ATTRIBUTE_SENSITIVE` appears nowhere under `crate/clients/pkcs11`).
- `crate/clients/pkcs11/provider/src/pkcs11_symmetric_key.rs:67-72` and `pkcs11_private_key.rs:85-90` (lazy fetch through the backend), `backend.rs:306,437-441` (formats requested), `kms_object.rs:440-447` (`export_object` with `unwrap: true`).
- `crate/server/src/core/operations/export_get.rs:66-107` (the KMS-side check that stays in force).
- Specification text checked: OASIS PKCS #11 v2.40 base, §4.9, §4.10 and §5.7.

#### Attack Scenario

1. An application or tool (a disk-encryption agent, a database master-key wrapper, an audit tool) loads the Cosmian PKCS#11 module and concludes, from `CKA_SENSITIVE=TRUE` and `CKA_EXTRACTABLE=FALSE`, that the key bytes never leave the key store.
2. Another component in the same process, or a user who can drive the same PKCS#11 session, calls `C_GetAttributeValue` for `CKA_VALUE`.
3. The module exports the key from the KMS with its own identity and returns the bytes. The reported attributes did not prevent it, and the consumer's assumption was false.

Preconditions: code running in the process that loads the module, and a KMS identity that holds `Get` on an extractable key. Static trace, not executed.

**Proposed Fix** (review before applying)

- Serve `CKA_VALUE` only when the KMS object is extractable and not sensitive, set `CKA_EXTRACTABLE`, `CKA_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` from the KMS attributes, and otherwise return `CKR_ATTRIBUTE_SENSITIVE`.
- Where an integration such as Oracle TDE needs the value, make it an explicit, documented opt-in configuration flag that is off by default, and document the limitation in the PKCS#11 integration guide.

---

### [F-044] 🔵 LOW — Kubernetes KMS v2 plugin decrypts under a caller-supplied `key_id`

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege, Information Disclosure |
| **CWE** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 1.8 — `CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The caller needs the identity that owns the socket (normally only kube-apiserver, which already handles every secret in clear), the plugin's KMS identity bounds the effect, and taking the key from the request is a documented requirement for KEK rotation |
| **Baseline** | New (rotation requirement, documented) |
| **Component** | Clients — Kubernetes KMS provider plugin |
| **File** | `crate/clients/k8s/plugin/src/service.rs:134-140` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The KMS v2 provider plugin builds its KMIP `Decrypt` with the `key_id` from the gRPC request (`service.rs:139-140`) and not with the configured KEK. The code comment and the documentation explain why: after a KEK rotation the secrets in etcd are still wrapped under the previous KEK and must stay readable. `Encrypt` uses the configured `wrapping_key_uid` (`:88`). The plugin keeps no allow-list of accepted `key_id` values and does not check that a key belongs to Kubernetes, so any client of the Unix socket can ask it to decrypt a ciphertext under any key that the plugin's KMS identity may use. The KMS authorizes the call per key (`crypto_op.rs:392-412`), so the blast radius is the set of keys that the plugin identity can use, and the caller needs a ciphertext produced under such a key.

The socket is created with mode `0660` (`main.rs:102`; the comment at `:97-101` says that the DaemonSet should chown it to the kube-apiserver UID and that `0660` is the fallback), while the documentation requires a socket readable only by `kube-apiserver`, mode `0600` (`kms-provider-plugin.md:525`). The shipped systemd unit runs as `root` and creates the runtime directory with mode `0755`.

#### Evidence

- `crate/clients/k8s/plugin/src/service.rs:128-145` (Decrypt uses `req.key_id`), `:134-138` (rotation rationale), `:88` (Encrypt uses the configured KEK), `:61-72` (`Status` reports the current KEK UID), `:183-208` (test `test_decrypt_uses_request_key_id` asserts that a foreign `key_id` is not rejected locally).
- `crate/clients/k8s/plugin/src/main.rs:96-102` (socket bound, mode `0o660`).
- `pkg/kubernetes_kms_plugin.service:9` (`User=root`), `:22-24` (`RuntimeDirectory`, mode `0755`, preserved).
- `documentation/docs/integrations/kubernetes/kms-provider-plugin.md:392,396` (the `key_id` equals the KEK UID kept with the ciphertext and selects the KEK on Decrypt), `:525-527` (socket `0600`, KEK with restricted access).
- `crate/server/src/core/operations/key_ops/crypto_op.rs:392-412` (KMS-side permission check per key; an unauthorized key is reported as not found).

#### Attack Scenario

1. A process other than kube-apiserver obtains the right to connect to the plugin socket: through the socket group, a pod that mounts the socket directory, or a compromised sidecar.
2. It sends `Decrypt` with a `key_id` naming another KEK that the plugin's KMS identity can use, and a ciphertext produced under that KEK.
3. The plugin forwards a KMIP `Decrypt` for that key and returns the plaintext.

Preconditions: connect rights on the socket (privileges on the node), a plugin identity that holds Decrypt on more than the Kubernetes KEKs, and a ciphertext under such a key. Static trace, not executed.

**Proposed Fix** (review before applying)

- Add a configuration list of the KEK UIDs that the plugin may use (the current one and the previous ones) and reject any other `key_id` with `InvalidArgument`.
- Chown the socket to the kube-apiserver UID in the DaemonSet and make the code and the documentation describe the same permissions (`0600`, or the exact group model).
- Give the plugin's KMS identity `Encrypt` and `Decrypt` on the named KEKs only.

---

### [F-045] 🔵 LOW — `ckms login` and `logout` persist one-off overrides into `ckms.toml`

| Field | Value |
| --- | --- |
| **STRIDE** | Tampering, Information Disclosure |
| **CWE** | CWE-295: Improper Certificate Validation |
| **OWASP** | A02:2025 — Security Misconfiguration |
| **CVSS 4.0** | 2.1 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score. The user passes the flag explicitly and the library default is secure; the effect needs a `login` or `logout` run and, later, an attacker on the network path (`AT:P`) |
| **Baseline** | New |
| **Component** | Clients — ckms CLI |
| **File** | `crate/clients/ckms/src/commands.rs:185-186,208-211` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

`ckms` applies its global flags to the configuration it loaded from `ckms.toml`, in memory: `--url`, `--accept-invalid-certs`, `--header` and the proxy flags (`commands.rs:182-191`). It then builds the client from that overridden configuration (`:196`). `login` and `logout` return a copy of the client's configuration, which is the overridden one, with only the tokens replaced (`kms_actions.rs:170,204-227`), and `commands.rs:207-212` saves that whole configuration whenever the command changed it. The one-off overrides are therefore written to `ckms.toml` together with the new token. A user who runs `ckms --accept-invalid-certs login` once against a test server with a self-signed certificate leaves `accept_invalid_certs = true` in the file, and every later `ckms` command skips certificate verification for the stored `server_url`. A `--url` override changes the stored server, and `--proxy-url` replaces the stored proxy, including its basic-auth credentials. The help text of the flag and the CLI documentation do not say that the setting can be persisted; the only sign is the line `Saving configuration to: …` on standard output.

The library default is secure: `accept_invalid_certs` is `false` unless it is set. An older audit note that says the value is hard-coded to `true` in `KmsClientConfig::default()` does not match the current code, where the `true` is inside a unit test. The weakness is the silent persistence of a security-relevant flag that the user meant for one command.

#### Evidence

- `crate/clients/ckms/src/commands.rs:179` (configuration loaded), `:182-187` (`--url` and `--accept-invalid-certs` applied to it), `:190-191` (headers and proxy overrides applied in place; `update_proxy_config` replaces the stored proxy, credentials included, `:77-96`), `:196` (client built from the overridden configuration), `:207-212` (the whole configuration is saved when the command returns a different one).
- `crate/clients/clap/src/actions/kms_actions.rs:170` (`process` starts from the client's configuration, which is the overridden one), `:204-227` (`Login` and `Logout` change tokens only).
- `crate/clients/ckms/src/config.rs:57-68` (`save` writes the file and prints the path).
- `crate/clients/ckms/src/commands.rs:124-129` and `documentation/docs/kms_clients/cli/main_commands.md:21` (help and documentation of the flag, silent about persistence).
- `crate/clients/client/src/http_client/client.rs:106` (default `accept_invalid_certs: false`), `:768-772` (test: the default serializes without the key); `crate/clients/ckms/src/config.rs:116` (the `true` is inside a unit test); `documentation/docs/certifications_and_compliance/audit/owasp_security_audit.md:937` (stale note A10-1).

#### Attack Scenario

1. A user runs `ckms --accept-invalid-certs login` (or `--url`, `--header`, `--proxy-url`) once, to get past a self-signed test certificate.
2. The login succeeds with a new token, so `ckms` saves the whole configuration, including `accept_invalid_certs = true`, to `ckms.toml`.
3. Every later `ckms` command that reads this file skips server-certificate verification. An attacker on the network path presents any certificate, reads the access token and the key material of later operations, and can forge responses.

Preconditions: the user passes an override together with `login` or `logout` and later reuses the file against a server that is reached over a hostile network. Static trace, not executed.

**Proposed Fix** (review before applying)

- Save only the token changes made by `login` and `logout`: write the loaded configuration plus the token delta, never the transient `--url`, `--accept-invalid-certs`, `--header` and proxy overrides.
- Print a warning on standard error each time verification is disabled, and persist transport settings only through `ckms configure`.
- Add a test that `login --accept-invalid-certs` leaves `accept_invalid_certs` unchanged in the saved file.

---

### [F-046] ⚪ INFO — BFF OIDC callback does not require the `iss` and `aud` claims to be present in the ID token

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing |
| **CWE** | CWE-287: Improper Authentication |
| **OWASP** | A07:2025 — Authentication Failures |
| **CVSS 4.0** | n/a — no vector |
| **Rating basis** | Informational, no CVSS vector |
| **Baseline** | Known class (PR #998 review D7) |
| **Component** | Web UI backend-for-frontend |
| **File** | `crate/server/src/routes/ui_auth.rs:67-71,338-341` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

The Web UI backend-for-frontend completes the OpenID Connect login in `GET /callback` (`ui_auth.rs:144`): it exchanges the authorization code at the discovered token endpoint, validates the ID token with `jsonwebtoken` and takes the `email` claim as the session identity. The validation sets the expected audience (`:340`) and, in production builds, the expected issuer (`:69`). It never calls `set_required_spec_claims`, so the required set stays at the library default, which contains only `exp`. `jsonwebtoken` 10.4.0 checks `iss` and `aud` only when the claim is present in the token, so an ID token that carries no `iss` or no `aud` passes both checks. OpenID Connect Core §3.1.3.7 requires the client to match `iss` with the issuer identifier and to verify that `aud` contains its own `client_id`.

The PR #998 review fixed the same gap on the bearer-token path: `jwt_config.rs:335-350` adds `iss` (outside SPIFFE) and `aud` (when `jwt_audience` is set) to the required claims. The callback was not part of that fix.

This is rated informational because the token reaches the server over TLS, from the discovered token endpoint, in exchange for this client's own PKCE code (`:216-238`, redirects disabled), and because the signature, the `kid`, the nonce and the reserved identities are all checked afterwards. The exposure is limited to an IdP that signs ID tokens without `iss` or `aud`, which a conformant IdP does not do. It is a conformance gap and a defence-in-depth item.

#### Evidence

- `crate/server/src/routes/ui_auth.rs:67-71` (production `configure_oidc_token_validation`: `set_issuer` and `validate_exp = true`), `:73-76` (test and `insecure` variant: `validate_exp = false`).
- `crate/server/src/routes/ui_auth.rs:338-341` (`Validation::new(header.alg)`, the algorithm pinned to the header value, `set_audience(&[&client_id])`, then the issuer configuration). No `set_required_spec_claims` call exists in the file; `git grep set_required_spec_claims -- crate` finds only `middlewares/jwt/jwt_config.rs:350` and `middlewares/auth_verifier/token.rs:237` (`["sub", "exp"]`).
- `jsonwebtoken` 10.4.0 (`Cargo.lock:4093-4094`), `src/validation.rs:71-89` (doc comments: `aud` and `iss` are validated only when present, and adding them to `required_spec_claims` makes them required) and `:268-279` (the missing-required-claim check).
- `crate/server/src/middlewares/jwt/jwt_config.rs:335-350` (the bearer path requires `iss` and, when configured, `aud`); `SECURITY-REVIEW.md:33,85,108-112` (finding 1 and decision D7 of the PR #998 review).
- `crate/server/src/routes/ui_auth.rs:216-238` (token request to the discovered `token_endpoint`, no redirects), `:298-313` (`kid` required, JWKS lookup with one throttled refresh), `:351-355` (nonce check), `:360-375` (the `email` claim becomes the identity; reserved identities refused), `:379` (session established with no roles and no domain).

#### Attack Scenario

1. The operator configures an IdP that can sign an ID token without `iss` or without `aud`, for example a non-conformant provider, or one that signs tokens of other audiences with the keys published in the JWKS the server trusts.
2. Such a token, carrying a victim's `email` and the nonce of the session, reaches the callback in the token-endpoint response.
3. The issuer and audience checks are skipped because the claims are absent, and the server opens a session for the `email` identity.

Preconditions: an IdP that signs ID tokens lacking `iss` or `aud`, and a way to place such a token in the token-endpoint response for this client's code (the response travels over TLS from the IdP). Static trace, not executed.

**Proposed Fix** (review before applying)

- Call `validation.set_required_spec_claims(&["exp", "iss", "aud"])` in the callback, in the code shared by the production and the test or `insecure` variants.
- Add a regression test that the callback rejects an ID token without `aud`, one without `iss`, and accepts a complete one.
- Build the required-claim set in one helper used by the callback and by `jwt_config.rs`, so the two paths cannot drift apart again.

---

### [F-047] ⚪ INFO — A database file and 20 test certificate and key files are tracked in the Auth Verifier submodule

| Field | Value |
| --- | --- |
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-540: Inclusion of Sensitive Information in Source Code |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | n/a — no vector |
| **Rating basis** | Informational, no CVSS vector |
| **Baseline** | New |
| **Component** | Repository hygiene (Auth Verifier submodule) |
| **File** | `authentication/auth_verifier.db`, `authentication/server/src/tests/certificates/{ec,rsa}/` (submodule `authentication`, gitlink `012d6613`) |
| **Confidence** | 7/10 |
| **Status** | Open |

#### Description

The `authentication` submodule (`.gitmodules:10-12`, `https://github.com/Cosmian/authentication.git`, pinned at `012d6613833876ef67b01cd47c234763d04ea703`) tracks two kinds of files that should not be in a source tree. The KMS repository itself only holds the gitlink, so these files are visible through `git -C authentication ls-files`.

First, `auth_verifier.db` at the submodule root, a 98,304-byte SQLite database added in commit `04b2ae4`. The only ignore rule is `server/.gitignore`, which covers the copy under `server/` and not the one at the root. The schema is the Auth Verifier's: two realms (`_` and `test`), three `userpass` accounts whose password column holds Argon2id hashes, and two `admin` rows. The hashes were not read out for this analysis.

Second, 20 certificate, private-key and PKCS#12 files under `server/src/tests/certificates/{ec,rsa}/`, ten per directory: the CA, the private key of the test root CA, the server certificate and key, and two user certificates, keys and PKCS#12 bundles. Six helper files (the generation scripts and the extension files) sit next to them. The development configuration `server/auth_verifier.dev.toml` uses them as the CA, the TLS key pair, a JWT-signing key and a certificate-signing key. A run from the submodule root with `auth-verifier.toml:17` (`sqlite://auth_verifier.db`) opens the tracked database.

Test credentials are a known false-positive class, which is why this is informational. The packages and the Helm chart do not ship these files. The risk is that a developer or an operator deploys the development configuration or the tracked database as it is, which would make the keys public and give the committed accounts a place in that deployment.

#### Evidence

- `.gitmodules:10-12` and `git ls-tree HEAD authentication` (gitlink `012d6613833876ef67b01cd47c234763d04ea703`); `git -C authentication ls-files` lists `auth_verifier.db` and the 26 files under `server/src/tests/certificates/{ec,rsa}/` (20 `.pem` and `.p12` files, `generate_certs_p256.sh`, `generate_certs_rsa4096.sh`, `server_extensions` and `user_extensions` in each directory).
- `authentication/server/.gitignore` (ignores only the copy under `server/`); `authentication/auth-verifier.toml:17` (`connection_url = "sqlite://auth_verifier.db"`).
- `authentication/server/auth_verifier.dev.toml:32-34,41-42,52` (`auth.ca.pem`, `auth.server.cert.pem`, `auth.server.key.pem` and `auth.user1.key.pem` used as TLS, JWT-signing and certificate-signing material).
- `authentication/pkg/auth_verifier.toml:140`, `authentication/server/documentation/docs/installation.md:96` and `authentication/charts/cosmian-auth-verifier/templates/configmap.yaml:59` (the shipped paths are outside the tracked files).
- `authentication/server/README.md:63` and `authentication/admin-ui/tests/unit/fixtures/saml.ts:1` (documented and referenced as test fixtures). No file of the KMS repository refers to `auth_verifier.db`.

#### Attack Scenario

1. A developer or an operator starts the Auth Verifier from a checkout of the submodule with `auth-verifier.toml` or `server/auth_verifier.dev.toml`, or copies them into an image or a test environment that is reachable from a network.
2. The instance trusts the committed CA, serves with the committed server key and signs its tokens with committed keys, all of which are public in the repository.
3. Anyone who can reach the instance forges client certificates or tokens that it accepts, and the accounts of the committed database exist in it.

Preconditions: the development configuration or the tracked database is used outside a developer machine; no shipped package or chart does it. Static trace, not executed.

**Proposed Fix** (review before applying)

- Remove `auth_verifier.db` from the submodule index (`git rm --cached`), ignore it at the submodule root, and rotate any account that was ever used outside a test.
- Generate the test certificates and keys during test setup (the `generate_certs_*.sh` scripts exist), or mark the directory test-only.
- Make the Auth Verifier refuse to start in a production configuration when its CA, TLS key or JWT key matches one of the committed test files.

---

### [F-048] ⚪ INFO — Advisories for quinn-proto, quinn-udp and rustix in `Cargo.lock`, none reachable, none in the VEX

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service, Information Disclosure |
| **CWE** | CWE-1395: Dependency on Vulnerable Third-Party Component |
| **OWASP** | A03:2025 — Software Supply Chain Failures |
| **CVSS 4.0** | n/a — no vector |
| **Rating basis** | Informational, no CVSS vector |
| **Baseline** | New |
| **Component** | Dependencies |
| **File** | `Cargo.lock` (`quinn-proto` 0.11.16, `quinn-udp` 0.5.15, `rustix` 1.1.4), `.cargo/audit.toml`, `sbom/openvex.json` |
| **Confidence** | 8/10 |
| **Status** | Open |

#### Description

`cargo audit` 0.22.1, run for this analysis on 2026-11-14 against an advisory database of 1,509 advisories and the 790 crates of `Cargo.lock`, exits with status 1: 8 vulnerabilities and 1 warning, on top of the two advisories that `.cargo/audit.toml` already ignores (RUSTSEC-2023-0071 and RUSTSEC-2026-0387).

- `quinn-proto` 0.11.16 carries seven: RUSTSEC-2026-0524 (a long Retry token can panic or exhaust memory in a QUIC client; fixed in 0.11.19), -0339 (unbounded pending connection-ID retirements; 0.11.17), -0341 (stream reassembly guard bypass; 0.11.17), -0342 (zero-length DATAGRAM frames; 0.11.17), -0523 (`MAX_STREAM_DATA` opens streams beyond the limit; 0.11.19), -0338 (zero-length STREAM frame panic; 0.11.18) and -0340 (minimum ACK delay panic; 0.11.18). Two of them, -0341 and -0340, are rated 7.5 (high) by the advisory database.
- `quinn-udp` 0.5.15: RUSTSEC-2026-0538 (the receive loop can spin after a truncated datagram; fixed in 0.5.16, and in 0.6.3).
- `rustix` 1.1.4: RUSTSEC-2026-0486, reported as a warning (`unsound`): the extended-attribute functions mark unwritten bytes as initialized when given a zero-length buffer.

None of them is reachable. `quinn`, `quinn-proto` and `quinn-udp` are in the lock file only as optional dependencies of `reqwest` 0.12.28, behind its `http3` feature, which also needs `--cfg reqwest_unstable`. No workspace manifest enables it, and the dependency tree of the workspace has no `quinn` or `h3` entry. `rustix` is compiled in through `tempfile` 3.27.0, its only dependent, and neither `tempfile` nor the workspace sources use extended attributes.

The gap is in the process, not in the code. None of these advisories has a statement in `sbom/openvex.json`, although `.cargo/audit.toml:6` requires one for every exception. The hosted check named "Security Audit" is `cargo-deny`, and it passes on PR #998. `cargo-deny` evaluates the resolved dependency graph, so it probably does not see lock entries that no build uses, whereas `cargo audit` and SBOM scanners read every entry of `Cargo.lock` (estimate: the graph behaviour of `cargo-deny` was not tested). No workflow in `.github/` runs `cargo audit`.

#### Evidence

- `Cargo.lock:5744-5753` (`quinn` 0.11.11, which depends on `quinn-proto` and `quinn-udp`), `:5764-5765` (`quinn-proto` 0.11.16), `:5786-5787` (`quinn-udp` 0.5.15), `:6095,6117` (`reqwest` 0.12.28, the only package that lists `quinn`), `:6291-6292` (`rustix` 1.1.4).
- `Cargo.toml:329` (`reqwest` 0.12 with default features off), `crate/server/Cargo.toml:121`, `crate/clients/clap/Cargo.toml:58`, `crate/test_kms_server/Cargo.toml:48` (none enables `http3`).
- `cargo audit` 0.22.1 output of 2026-11-14 ("8 vulnerabilities found", "1 allowed warning found") and `cargo tree --offline --workspace --all-features --target all -e normal,build,dev` (no `quinn` or `h3` entry).
- `.cargo/audit.toml:6-12` (the policy comment and the two ignores), `deny.toml:67-74` (the same two ignores), `sbom/openvex.json:12,21` (the only two statements).
- `.github/workflows/main.yml:29-32` (job `cargo-deny`, displayed as "Security Audit", calling `Cosmian/reusable_workflows/.github/workflows/cargo-audit.yml` pinned at `9079c7a0`, whose step runs `cargo deny --log-level warn --all-features check`); `.mise/scripts/audit/multi_framework.sh:129-132` (`cargo audit -q`, run only through the local `mise run audit:multi`).

#### Attack Scenario

1. A customer, an auditor or a release gate runs `cargo audit`, or an SBOM scanner, on the `Cargo.lock` of the 5.29.0 sources.
2. The scan reports 8 vulnerabilities (two of them high) and an unsound warning, and the VEX document says nothing about them, so the reader cannot tell that they are unreachable.
3. No exploit path exists today. If a later change enabled the `http3` feature of `reqwest` and opted a client in to HTTP/3, `quinn-proto` would become reachable on that client's outbound path.

Preconditions: a scanner that reads the lock file, or a future change that enables `reqwest`'s `http3` feature (with `--cfg reqwest_unstable`). `cargo audit` and `cargo tree` were executed; reachability is a static reading of the dependency graph.

**Proposed Fix** (review before applying)

- Run `cargo update -p quinn-proto -p quinn-udp -p rustix` so the lock file holds fixed versions (`quinn-proto` 0.11.19 or later, `quinn-udp` 0.5.16 or later), or let the next dependency pruning remove the unused optional entries.
- If an entry has to stay, add a justified ignore to `.cargo/audit.toml` and `deny.toml` and a matching `not_affected` statement (`vulnerable_code_not_in_execute_path`) to `sbom/openvex.json`, as `.cargo/audit.toml:6` requires, and bump the VEX `version` and `timestamp`.
- Run `cargo audit` against `Cargo.lock` in CI, so the status that customers see when they scan the lock file is the status CI enforces.

---

### [F-049] ⚪ INFO — OPA roles and domain are not established on non-KMIP routes

| Field | Value |
| --- | --- |
| **STRIDE** | Elevation of Privilege |
| **CWE** | CWE-863: Incorrect Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | n/a — no vector |
| **Rating basis** | Informational, no CVSS vector |
| **Baseline** | Known class (PR #998 review D2) |
| **Component** | OPA integration |
| **File** | `crate/server/src/core/opa/context.rs:35-36` |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

OPA decisions use a per-request context, `OpaUserContext { roles, domain }`, held in a Tokio task-local, `OPA_USER_CONTEXT` (`context.rs:16-31`). A route handler has to wrap its async work in `OPA_USER_CONTEXT.scope(ctx, fut).await` (`context.rs:10-12`); outside such a scope `get_opa_user_context()` returns an empty context (`:35-36`), which the module comment calls fail-closed (`:26-29`).

The only production sites that set the scope are the three KMIP HTTP handlers (`routes/kmip/handlers.rs:275,446,486`) and the Create-permission check of `routes/access.rs:171`. The JOSE, MS DKE, Azure EKM, Google CSE, SPIRE and AWS XKS routes, and the KMIP socket server (`start_kms_server.rs:633`), call into the same core operations without setting it. When such a request reaches `opa_decision` (`retrieve_object_utils.rs:272-287`), OPA is asked to decide with empty roles and no domain.

The effect depends on how the policy is written. An allow-list policy such as the reference Rego (`test_data/opa/kms.rego:43`, `default allow := false`) fails closed on these routes, which is a functional gap and not a bypass. A policy that expresses denials in terms of a role or a domain value does not match an empty context, so the rule silently does not apply on these routes. This extends decisions D2, D5 and D6 of the PR #998 review. Rated informational because it needs a deny-style policy and a route that reaches OPA.

#### Evidence

- `crate/server/src/core/opa/context.rs:10-12` (handlers must set the scope), `:16-23` (`OpaUserContext`, derives `Default`), `:25-31` (task-local, empty default outside a scope), `:35-36` (`get_opa_user_context` returns `unwrap_or_default()`).
- `crate/server/src/core/retrieve_object_utils.rs:279-287` (`opa_decision` reads the context, builds the input and treats a transport failure as a refusal with `unwrap_or(false)`).
- Scope-setting sites: `crate/server/src/routes/kmip/handlers.rs:275,446,486` and `crate/server/src/routes/access.rs:171`; context extraction in `crate/server/src/core/kms/permissions.rs:517-530` (empty when `force_default_username` is set).
- Routes without a scope: `git grep OPA_USER_CONTEXT -- crate` finds no use in the JOSE, MS DKE, Azure EKM, Google CSE, SPIRE or AWS XKS handlers; the socket handler at `crate/server/src/start_kms_server.rs:626-635` calls `handle_ttlv_bytes` directly with the certificate name.
- `test_data/opa/kms.rego:43` (reference policy, default deny); `SECURITY-REVIEW.md` decisions D2, D5 and D6.

#### Attack Scenario

1. An operator enables OPA with a policy that grants broadly and denies by role or domain, for example a rule that denies callers whose domain is `contractors`.
2. A caller in that domain reaches an object through a route that never sets the context, such as Google CSE, MS DKE, JOSE or the KMIP socket.
3. OPA receives empty `roles` and no `domain`, the deny rule does not match, and the broad grant applies.

Preconditions: OPA authorization enabled with a policy that relies on deny rules over `roles` or `domain`, and a route that reaches `opa_decision`; an allow-list policy fails closed instead. Static trace, not executed.

**Proposed Fix** (review before applying)

- Set `OPA_USER_CONTEXT.scope(..)` once, in a middleware, for every authenticated scope, or pass the context to the core operations as an argument instead of through a task-local.
- Make a missing context an explicit error on any path that consults OPA, rather than an empty default, and document the behaviour of each route family.
- Add a test per route family that OPA receives the caller's roles and domain.

---

### [F-050] ⚪ INFO — EST first-enrolment and SCEP trust model is coarse (documented design)

| Field | Value |
| --- | --- |
| **STRIDE** | Spoofing, Elevation of Privilege |
| **CWE** | CWE-285: Improper Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | n/a — no vector |
| **Rating basis** | Informational, no CVSS vector |
| **Baseline** | Documented design |
| **Component** | PKI — EST and SCEP enrolment |
| **File** | `crate/server/src/config/command_line/est_config.rs:50-59` (also `scep_config.rs:51-80`, `routes/est/enroll.rs:259-294`, `routes/scep/pki_operation.rs:332-350`) |
| **Confidence** | 6/10 |
| **Status** | Open |

#### Description

EST (RFC 7030) and SCEP (RFC 8894) enrolment are off by default. When enabled, the first enrolment of a device is authorized by something shared, not by something that belongs to one device:

- SCEP: one static challenge password, compared in constant time (`pki_operation.rs:336-339`), authorizes every `PKCSReq` (`scep_config.rs:51-65`, at least 8 characters).
- EST, Basic bootstrap (`est_require_client_cert = false`): one shared bootstrap user name and password (`est_config.rs:50-75`).
- EST, mutual TLS: `enroll_for_peer` checks the peer certificate only when the EST CA issued it. A peer certificate that came from another CA accepted by `clients_ca_cert_file`, or no certificate on the Basic path, falls through to `issue_and_respond` (`enroll.rs:264-293`).

What the shared secret does not do is bind the request to a device. The issuance template limits the key type, key size, extended key usage and validity, and applies default-deny to SAN names and a Common Name pattern (`template.rs:372-376,474-545`), so a caller can obtain a certificate for any name that matches the template. The project documents this: the EST page warns that anyone who knows the bootstrap credentials can enrol a device that matches the template (`pki-enrollment-est.md:142-144`), and the SCEP option text says that the secret authenticates a class of devices, not the name a device asks for (`scep_config.rs:79-80`).

The residual points a deployer should weigh:

- A leaked shared secret lets its holder enrol any name that matches the template; there is no per-device uniqueness, so withdrawing one device's right to enrol means rotating the shared secret (a configuration change and a restart).
- In EST mutual-TLS mode every certificate accepted by `clients_ca_cert_file` can enrol, and the TLS layer does not check the revocation of those certificates (`pki-enrollment-est.md:246-247`).
- Subject attributes other than serialNumber, userId, emailAddress and the Common Name (for example `O`, `OU`, `C`, `ST`, `L`) are not constrained by the template and are copied into the certificate (`build_certificate.rs:82`).
- SCEP renewal needs no challenge by default (`scep_config.rs:67-73`), so a stolen enrolled certificate and its key can obtain a fresh certificate for the same identity for as long as the presented certificate is valid and `Active`.

Mitigations in place: enrolled certificates carry a marker policy that a CSR cannot request, and the TLS layer refuses them as KMS user credentials (`tls_auth.rs:181-190`); a CSR cannot ask for `keyCertSign` or `cRLSign`; a per-client lockout, replay cache and concurrency cap (`enrollment_guard.rs:24-48`); TLS is mandatory for Basic bootstrap; EST-CA-issued peers can re-enrol only the same Subject and SAN and must be `Active`.

#### Evidence

- `crate/server/src/routes/est/enroll.rs:264-287` (the peer certificate is examined only when `is_issued_by` the EST CA), `:288-291` (a marked certificate issued elsewhere is refused with 403), `:293` (every other peer reaches `issue_and_respond`).
- `crate/server/src/routes/scep/pki_operation.rs:332-345` (one challenge, `secrets_equal`, failures counted, principal `scep-challenge`), `:346-350` (renewal for the identity already carried).
- `crate/server/src/config/command_line/scep_config.rs:51-65` (challenge of at least 8 characters), `:67-73` (`scep_allow_renewal_without_challenge`, default `true`), `:75-80` (class-of-devices wording).
- `crate/server/src/config/command_line/est_config.rs:50-59` (`est_require_client_cert`, default `true`; `false` enables the Basic fallback), `:61-75` (one shared user name and password).
- `crate/server/src/config/params/server_params.rs:753-792` (startup checks: Basic bootstrap needs TLS, a user name without a colon and a long enough password; mutual-TLS mode needs `clients_ca_cert_file`; SCEP needs a CA, a challenge and a template).
- `crate/server/src/core/operations/certify/template.rs:372-376` (a template needs `subject_cn_regex` or `allow_any_identity`), `:474-508` (`check_subject`), `:513-545` (`check_sans`, default-deny); `crate/server/src/core/operations/certify/build_certificate.rs:82` (the CSR subject is copied).
- `crate/server/src/routes/enrollment.rs:378-420` (`issue_from_csr` issues as the reserved `[enrollment-service]` identity and applies the template); `crate/server/src/routes/enrollment_guard.rs:24-48`; `crate/server/src/middlewares/tls_auth.rs:181-190`.
- `documentation/docs/use_cases/pki-enrollment-est.md:142-144,246-247,252`; `documentation/docs/use_cases/pki-enrollment-scep.md:113-123`.

#### Attack Scenario

1. An insider, or the owner of a compromised device, learns the SCEP challenge password (or the EST bootstrap credentials), which many devices of one class share.
2. They send a `PKCSReq` with a key and a Common Name that match the template's pattern but name a device they do not own.
3. The KMS issues a certificate for that name. Its marker policy stops it from becoming a KMS user, but a relying party that trusts the enrolment CA, such as a VPN gateway, a Wi-Fi controller or an MDM service, accepts it as that device.

Preconditions: EST or SCEP enabled, a shared secret that leaked or is held by a party who should not enrol that name (or a corporate client CA in `clients_ca_cert_file` for EST mutual TLS), and a relying party that trusts the enrolment CA. Static trace, not executed.

**Proposed Fix** (review before applying)

- Give EST first enrolment its own trust store, or bind the first-enrolment CSR to the identity in the peer certificate, instead of reusing `clients_ca_cert_file`.
- Offer per-device, single-use SCEP challenges, and default `scep_allow_renewal_without_challenge` to `false`.
- Rebuild the certificate subject from the allowed attributes of the template instead of copying the CSR subject, and document that revoking a device means rotating the shared secret.

---

### [F-051] 🟡 MEDIUM — Unbounded `RotateInterval` or `RotateOffset` crash-loops the server once auto-rotation is enabled

| Field | Value |
| --- | --- |
| **STRIDE** | Denial of Service |
| **CWE** | CWE-1284: Improper Validation of Specified Quantity in Input |
| **OWASP** | A10:2025 — Mishandling of Exceptional Conditions |
| **CVSS 4.0** | 6.0 — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **Rating basis** | Band of the base score; no cap and no amplifier. The AT:P value reflects that the scheduler is an operator opt-in (off by default); with AT:N the same vector scores 7.1 (HIGH). The vector assumes that no Crypto Officer is configured; with Crypto Officers configured the attacker must hold that role (`PR:H`), which scores 5.9 (still MEDIUM). |
| **Baseline** | New |
| **Component** | Auto-rotation scheduler and SQL object store |
| **File** | `crate/server_database/src/stores/sql/locate_query.rs:710-728` (also `crate/server/src/core/operations/auto_rotate.rs:347-363`, `crate/server/src/core/operations/attributes/set.rs:113-114,235-240`) |
| **Confidence** | 9/10 |
| **Status** | Open (confirmed by local probe) |

#### Description

`RotateInterval` and `RotateOffset` are signed 64-bit counts of seconds (`kmip_attributes.rs:400,417`). `SetAttribute` stores whatever it receives: the only test on `RotateInterval` is `n > 0`, which switches `rotate_automatic` on implicitly (`set.rs:113-114,235-240`), and nothing under `crate/server/src`, `crate/server_database` or `crate/kmip` bounds either value. Any user who may create a key can set them, and the `ckms` rotation options do exactly that right after `Create` (`rotation_policy_args.rs:34-39,57-70`).

The auto-rotation scheduler runs on a dedicated thread, ticks immediately at start-up, then every `auto_rotation_check_interval_secs` (`cron.rs:16-43`). Each tick calls `run_auto_rotation` (`auto_rotate.rs:53`), which asks the database for the Active objects with `RotateAutomatic` set and `RotateInterval > 0` (`locate_query.rs:683-700`) and then calls `is_due_for_rotation` on each of them (`:710-728`). That function adds the interval, or `initial + offset + interval`, to an `OffsetDateTime` (`:715-721`). The addition panics when the result leaves the date range of the `time` crate (year 9999 at most in this build), and both the release and the dev profile use `panic = "abort"` (`Cargo.toml:179,203`), so the panic ends the whole process. The same tick reaches a second unchecked addition in `days_until_next_rotation` (`auto_rotate.rs:347-363`) through `dispatch_renewal_warnings` (`:284,303`). `database_objects.rs:618-626` swallows database errors with `unwrap_or_default()`, which cannot catch a panic. The root cause is the missing bound (CWE-1284); the immediate failure is an uncaught exception turned into a process abort (CWE-248).

Because the poisoned object stays in the database and the first tick runs at start-up, the crash repeats on every restart: the server cannot come back until the scheduler is disabled and the value is repaired. A service manager that restarts on failure (`Restart=on-failure`, `pkg/cosmian_kms.service:10-11`) only repeats the abort. The panic message names the source line but not the object, so finding the key means scanning the stored rotation policies. The impact is availability only; no key material is exposed.

The scheduler is off by default: `auto_rotation_check_interval_secs` defaults to 0 (`clap_config.rs:292-296`), `resources/kms.toml:45` has it commented out, values between 1 and 59 are refused (`server_params.rs:974-985`), and the key-rotation documentation uses 300 seconds in its examples (`auto_rotation_policy.md:96,101,121,191`, `server_cli.md:698`). The finding therefore applies to deployments that follow that documentation, which is why the vector carries AT:P.

Release exposure: `is_due_for_rotation` has the same unchecked additions in tag `cosmian-kms-5.29.0` (`locate_query.rs:681-692` in that tag) and has had this shape since tag `5.25.0` (`:600-611`); the `SetAttribute` path and the scheduler have the same shape in tag 5.29.0 (`set.rs:107-108,198`, `cron.rs:18,38-41`). This was compared statically and not executed on the tag. A `SECURITY.md` entry will therefore be due when it is fixed (AGENTS.md §5.5).

Not a trigger: ReKey and ReCertify take their `offset` as a KMIP `Interval`, an unsigned 32-bit count of seconds (`ttlv/interval.rs:36`), so `now + offset` stays within about 136 years (`kmip_attributes.rs:2041-2042`). Measured: 4294967295 was accepted (HTTP 200), while 4294967296 and 9000000000000 were refused with HTTP 422 and the server stayed up.

The same class exists for HSM-backed keys, not executed because it needs an HSM: `set.rs:255-291` rejects intervals below one day and otherwise computes `today + Duration::days(days)` at `:283` for any larger value (the ceiling division at `:282` can overflow too), and `rekey/symmetric/hsm.rs:187-189,243-244` repeats the date addition on re-key. No HSM amplifier is applied, because the faulting arithmetic runs in the KMS outside the HSM communication path. A hugely positive or negative `RotateOffset` combined with a small interval reaches the same panic at `locate_query.rs:721` and `auto_rotate.rs:359` (static inference; only `RotateInterval` was executed).

**Measured** on a local debug build (`target/debug/cosmian_kms`, OpenSSL 3.6.5, non-FIPS, SQLite, no authentication configured, scratch database; the FIPS and release builds and the PostgreSQL, MySQL, Redis and HSM variants were not run):

| Step | Result |
| --- | --- |
| `Create` a key, then `SetAttribute` with `RotateInterval` 9000000000000 (scheduler set to 60 s) | accepted and stored, no error |
| next scheduler tick, about 46 s after the key was created | the process terminated: `panicked at crate/server_database/src/stores/sql/locate_query.rs:721:9: resulting value is out of range` |
| restart on the same database, twice, scheduler enabled | each run aborted again, exit status 134, within about 35 ms and before the HTTP listener was bound |
| restart on the same database with the scheduler disabled (the default) | started normally; an empty `POST /kmip/2_1` answered 422; the key and its interval were still there |
| `ckms sym keys set-rotation-policy --interval 0` on that key, then restart with the scheduler enabled | started; the first tick logged "No keys due for rotation" and the server answered requests |

The backtrace of the first abort ends in `Option::expect` ← `<OffsetDateTime as Add<SignedDuration>>::add` ← `is_due_for_rotation` ← `filter_due_for_rotation` ← `SqlitePool::find_due_for_rotation` ← `Database::find_due_for_rotation` ← `auto_rotate::run_auto_rotation` ← `cron::spawn_auto_rotation_cron`.

#### Evidence

- `crate/kmip/src/kmip_2_1/kmip_attributes.rs:400,417` (`rotate_interval` and `rotate_offset` are `Option<i64>`).
- `crate/server/src/core/operations/attributes/set.rs:113-114` (the only test is `n > 0`), `:235-240` (`rotate_automatic` implicitly true).
- `crate/clients/clap/src/actions/shared/rotation_policy_args.rs:34-39,57-70` (the CLI sends `SetAttribute` for the interval and the offset).
- `crate/server_database/src/stores/sql/locate_query.rs:683-700` (selection: Active, `RotateAutomatic`, `RotateInterval > 0`), `:710-728` (`is_due_for_rotation`: `Duration::seconds` at `:715`, additions at `:718` and `:721`; the measured panic is at `:721:9`).
- `crate/server_database/src/stores/sql/sqlite.rs:1010-1036`, `pgsql.rs:1195-1207`, `mysql.rs:901-915` and `crate/server_database/src/stores/redis/objects_db.rs:757` (all four backends reach `is_due_for_rotation`; only SQLite was executed).
- `crate/server/src/core/operations/auto_rotate.rs:53-55` (`run_auto_rotation`), `:284,303` (`dispatch_renewal_warnings`), `:347-363` (`days_until_next_rotation`, additions at `:355` and `:359`).
- `crate/server/src/cron.rs:16-43` (dedicated thread, immediate first tick, `run_auto_rotation` then `dispatch_renewal_warnings`); `crate/server_database/src/core/database_objects.rs:618-626`.
- `Cargo.toml:179` (release `panic = "abort"`), `:203` (dev `panic = "abort"`); `pkg/cosmian_kms.service:10-11`.
- Gate: `crate/server/src/config/command_line/clap_config.rs:292-296`, `crate/server/src/config/params/server_params.rs:974-985`, `resources/kms.toml:45`, `documentation/docs/kmip_support/key_rotation/auto_rotation_policy.md:96,101,121,191`, `documentation/docs/configuration/server_cli.md:698`, `documentation/adr/2026-06-30-key-auto-rotation-keyset-chain-design.md:156`.
- HSM variant (static): `set.rs:255-291`, `crate/server/src/core/operations/rekey/symmetric/hsm.rs:187-189,243-250`.
- Bounded counter-example: `crate/kmip/src/ttlv/interval.rs:36,87-100`.

#### Attack Scenario

1. The attacker is an authenticated user. When no Crypto Officer is configured every user holds the Create right, so the attacker creates a symmetric key and sets `RotateInterval` to a very large value (`ckms sym keys create --algorithm aes --number-of-bits 256 --rotation-interval 9000000000000`, or a direct `SetAttribute`). The server accepts and stores it; nothing happens yet.
2. On a deployment where the operator enabled auto-rotation, the next scheduler tick selects the key (Active, `RotateAutomatic` implied, interval above 0) and `is_due_for_rotation` adds the interval to the key's initial date. The addition panics and `panic = "abort"` ends the whole process: every tenant and every endpoint is down.
3. The first tick of a restarted server runs immediately and selects the same key, so the process aborts again before it listens. The restart policy of the service manager only repeats the abort until an operator disables the scheduler, finds the key and repairs its interval.
4. The attacker can set the value again as soon as the scheduler is switched back on, until the right to create or modify keys is withdrawn from that user.

Preconditions: auto-rotation enabled by the operator (`auto_rotation_check_interval_secs` of 60 or more) and an authenticated user who may create a key (every user when no Crypto Officer is configured). Measured on a local debug build as described above (non-FIPS, SQLite, no authentication); the abort, the persistence across restarts and the recovery were observed, the other backends and the HSM variant were not run.

**Proposed Fix** (review before applying)

- Validate `RotateInterval` and `RotateOffset` where they are set (`SetAttribute`, and the Create, Register and Import attribute paths that accept them): positive and no larger than a documented ceiling (for example 100 years in seconds), `RotateOffset` within the same bound, and answer `InvalidRequest` (HTTP 400) otherwise.
- Use `checked_add` in `is_due_for_rotation` (`locate_query.rs:715-721`) and `days_until_next_rotation` (`auto_rotate.rs:355-359`), and the same for the HSM `Date + Duration` sites; treat an overflow as "not due" and log the object identifier, so that a row already stored by an earlier version cannot stop the scheduler. `catch_unwind` is not a fix under `panic = "abort"`; only checked arithmetic is.
- Add regression tests with `RotateInterval = i64::MAX` and `RotateOffset = i64::MIN` and `i64::MAX` that expect a client error, plus a unit test of `is_due_for_rotation` on stored out-of-range values.
- Audit every `OffsetDateTime + Duration` and `Date + Duration` whose operand comes from a client (`git grep` for `Duration::seconds(` and `Duration::days(`), as proposed for F-042.
- Document the recovery for operators already affected: start with `auto_rotation_check_interval_secs = 0`, locate the key, run `ckms sym keys set-rotation-policy --key-id <id> --interval 0`, then re-enable the scheduler.

---

## Appendix — Unverified Hardening Notes

The analysis agents also reported the 24 items below. They were **not independently re-verified** by the verification pass, so they carry no CVSS score, no severity, and no place in the ranked index; each one is a note to triage, not a finding. The last column keeps the analysis agent's own wording: "CONFIRMED" there means the agent read the code, not that the verification pass repeated the check. Several rows are bundles of small items that share a file or a theme.

| ID | Area | Note | Files | Agent confidence |
| --- | --- | --- | --- | --- |
| R-01 | Observability | OTLP over https is probably not compiled in (tonic without a TLS feature) while the documentation claims TLS | `crate/server/src/core/kms/mod.rs:374`; `documentation/docs/configuration/otlp-telemetry.md:27` | PROBABLE |
| R-02 | Server hardening | Bundle: unbounded rate-limiter map (off by default), unkeyed audit hash chain with `try_send` drops, socket reads the request before identity, public `/version`, no HSTS or Referrer-Policy, secret CLI flags visible in `ps`, localhost prefix match in a secret backend, `test_kms_server` enables `insecure` by feature unification | `crate/server/src/middlewares/rate_limiter.rs:58`; `crate/access/src/audit/hash.rs:111`; `crate/server/src/socket_server.rs:473-476`; `crate/server/src/config/command_line/secret_backends/cosmian_kms.rs:32-45`; `crate/test_kms_server/Cargo.toml:32` | CONFIRMED (each, in code) |
| R-03 | KMIP attributes | Server-internal `x-cosmian-*` vendor attributes are client-writable and trusted by JoinSplitKey | `crate/server/src/core/operations/attributes/policy.rs:41-58`; `crate/server/src/core/operations/join_split_key.rs:193-196`; `crate/server/src/core/operations/create_split_key.rs:384` | Mechanics CONFIRMED; exploit value HYPOTHESIS |
| R-04 | Key ceremony | Global-ceremony CreateSplitKey does not require the caller to be a crypto-officer candidate (the comment says it does), leaving orphan shares when the source Revoke or Destroy then fails | `crate/server/src/core/operations/create_split_key.rs:133-154` | CONFIRMED (mechanics) |
| R-05 | KMIP parsing | Debug-dump of transient memory before the 512 B truncation amplifies per-request memory | `crate/kmip/src/ttlv/kmip_ttlv_deserializer/deserializer.rs:343,447,797` | PROBABLE |
| R-06 | KMIP parsing | Locate `OffsetItems` uncapped; JSON decoded before the batch cap; `trace!` of full requests | `crate/server/src/core/operations/locate.rs:24,88`; `crate/server_database/src/stores/sql/locate_query.rs:571` | CONFIRMED (each) |
| R-07 | Algorithm policy | No Get arm for a KeyWrappingSpecification in the algorithm policy (only Export is validated) | `crate/server/src/core/operations/algorithm_policy.rs:131,137` | CONFIRMED (code) |
| R-08 | Cryptography | SHA1withRSA accepted on the CSE `private_key_sign` path with no Rust-side FIPS gate; no PSS salt floor; verify failures log signature and data at error level; non-zeroised temporaries; revocation soft-fails | `crate/crypto/src/crypto/rsa/sign.rs:51`; `crate/crypto/src/crypto/rsa/verify.rs:142-143`; `crate/server/src/core/operations/validate.rs:899-902` | Mixed; FIPS-provider refusal of SHA-1 unverified |
| R-09 | HSM and database | `hsm_admin` wildcard; `HsmInstanceParams` Debug prints slot passwords; no timeout on the HSM session-permit wait; PKCS#11 path from an environment variable; dead MySQL upsert without owner guard; fixed Redis KDF salt; SQLite file mode | `crate/interfaces/src/hsm/hsm_store.rs:146`; `crate/hsm/base_hsm/src/slots.rs:405-406`; `crate/server/src/config/command_line/hsm_config.rs:6` | CONFIRMED (each) |
| R-10 | Cloud routes | SSRF blocklist gaps (CGNAT, 0.0.0.0/8, 198.18/15), XKS auto-grant of `aws-xks` tagged objects, Tokenize hash with caller salt, reserved-identity guard not applied on CSE, DKE, Azure and JOSE, `unsafe` transmute in the SigV4 middleware, CSE PKCS1 padding and md5 or sha1 not gated | `crate/server/src/core/certificate/mod.rs:13`; `crate/server/src/routes/aws_xks/sigv4_middleware.rs:386-388`; `crate/server/src/routes/google_cse/operations.rs:608-609,902-903` | CONFIRMED (lines); exploit hypotheses |
| R-11 | Kubernetes clients | Unsalted SHA-256 of the secret used as the CSI object version and the operator `status.lastSecretHash` | `crate/clients/k8s/csi_provider/src/service.rs:242-245`; `crate/clients/k8s/operator/src/controller.rs:103` | PROBABLE |
| R-12 | Clients | Base64 key export is lower-cased, so the exported backup is corrupt (functional defect, no adversary; confirmed by reading both call sites) | `crate/clients/wasm/src/wasm.rs:1765-1766`; `crate/clients/clap/src/actions/shared/export_key.rs:169-170` | CONFIRMED (functional) |
| R-13 | Clients | Auth Verifier login honours `accept_invalid_certs` and does not require https for Basic credentials | `crate/clients/client/src/http_client/login.rs:526-529` | PROBABLE |
| R-14 | PKCS#11 module | `parse_mechanism` builds a slice from a raw pointer with no null check and no `SAFETY` note | `crate/clients/pkcs11/module/src/core/mechanism.rs:132-135` | CONFIRMED (hardening) |
| R-15 | Clients | Bundle: `/ui` CSP, nosniff, HSTS and Referrer-Policy missing; logout CSRF; fail-open admission webhook; root CSI image; `ps`-visible flags; a `static mut`; a CNG layout mismatch | `crate/server/src/start_kms_server.rs:1386-1389`; `crate/clients/k8s/operator/src/webhook.rs:111`; `crate/clients/cng/src/provider.rs:473-490` | CONFIRMED (each) |
| R-16 | Web UI session | Residue H3-H10: `GET /ui/logout` changes state; `Secure` flag derived only from the URL scheme; API-token shared identity with lower-cased compare and a database read before the header parse; rate-limiter map never collected; `/jwks.json` unauthenticated database cost (off by default); permissive CORS; `/ms_dke` omits SessionAuth | `crate/server/src/routes/ui_auth.rs:752`; `crate/server/src/middlewares/api_token/api_token_auth.rs:23,79`; `crate/server/src/start_kms_server.rs:1267` | CONFIRMED (each in code) |
| R-17 | Monitoring stack | The monitoring script copies `.env.example` with a published Grafana password, labelled production; port 8428 published; `--tls-p12-password` on argv; `latest` image tags | `monitoring/start-monitoring.sh:9`; `monitoring/.env.example:8,12`; `monitoring/docker-compose.yml:21,71` | PROBABLE |
| R-18 | CI/CD | Windows installers are signed with a test signing account and the trust check accepts `UnknownError`; publication path unverified | `.github/workflows/build_windows.yml:148,192` | PROBABLE (publication unverified) |
| R-19 | CI/CD | Secrets are passed to the compile step of the test group (read-only contents, same-repo guard in place) | `.github/workflows/test-group.yml:100,113,121` | CONFIRMED (hardening) |
| R-20 | CI/CD | 17 workflows declare no `permissions` block; dead job in `main.yml` | `.github/workflows/packaging-kubernetes.yml:28-29`; `.github/workflows/cla.yml:7-10`; `.github/workflows/main.yml:22-25` | CONFIRMED (hardening) |
| R-21 | CI/CD | GPG signing key available in the package build job | `.github/workflows/packaging.yml:48-50`; `.github/workflows/packaging-apk.yml:34-36` | CONFIRMED (hardening) |
| R-22 | Supply chain policy | `deny.toml` source policy is warn-only and `supply-chain/config.toml` carries 362 cargo-vet exemptions (the lock file is crates.io-only today) | `deny.toml:251,254`; `supply-chain/config.toml` | CONFIRMED (hardening) |
| R-23 | CI/CD | Expression injection in `run:` steps (`workflow_dispatch` inputs only) | `.github/workflows/release.yml:84,130`; `.github/workflows/nix-update-hashes.yml:114`; `.github/workflows/flamegraph.yml:89` | CONFIRMED |
| R-24 | Configuration templates | Placeholder secrets in the unpackaged `resources/kms.toml` template (commented ceremony secret, Redis master password) | `resources/kms.toml:143,158` | CONFIRMED (hardening) |

**Incidental defect for the development team (R-12).** `export_key.rs:169-170` and `wasm.rs:1765-1766` call `.to_lowercase()` on standard Base64 output. Base64 is case-sensitive, so a key exported in that format cannot be decoded back to the original bytes: the `ckms` Base64 export and the Web UI Base64 export would give an unusable backup. This is a functional bug rather than a security issue. It was found by reading both call sites and was not executed, and it deserves its own ticket.

**Conditional upgrade (R-08).** If a runtime test shows that the FIPS provider accepts SHA1withRSA signing on the CSE `private_key_sign` path, the KMS amplifier for non-approved algorithms in FIPS mode would apply (CRITICAL) and the note would become a rated finding. This was not tested: the FIPS provider's refusal of SHA-1 signatures was neither confirmed nor ruled out.

---

_Generated by AI Threat Model Analyst. All findings require human review before remediation._
