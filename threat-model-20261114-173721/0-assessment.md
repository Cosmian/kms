# Threat Model Assessment — Eviden KMS

**Date**: 2026-11-14
**Scope**: Full repository, branch `rbac_rego` at commit `17926f40b` (PR #998, workspace version 5.29.0), including the `authentication/` submodule (Auth Verifier) pinned at `012d6613`
**Overall Risk Posture**: HIGH

The posture is HIGH for the product as shipped. It is CRITICAL for deployments that run one of the two optional components that carry a CRITICAL finding: the Auth Verifier session API (F-001) and the Google CSE routes (F-002). The core KMIP request path held up under analysis: client authentication, token comparison, the role gate and the Create gate on every batched item, the TTLV parser limits, the OPA client and the cryptographic provider initialisation behave as designed. 29 such controls were verified (T-052 to T-080 in `2-stride-analysis.md`).

The analysis produced 51 findings: 🔴 2 CRITICAL, 🟠 10 HIGH, 🟡 22 MEDIUM, 🔵 12 LOW and ⚪ 5 INFO, ranked in `3-findings.md`, plus an appendix of 24 unverified hardening notes that are neither counted nor scored. F-042 and F-051 were reproduced against a local server. Every other finding is a static trace of the code and was not executed. Nothing was fixed, committed or pushed by this analysis; every fix is a proposal for human review.

## Key Findings

- **Two CRITICAL authorisation gaps sit in optional components, and both are in released code.** F-001: the Auth Verifier `/sessions` scope is protected only by cookie authentication, and no handler compares the caller with the session it reads, writes or deletes, so any holder of a valid session cookie in any realm can read another user's signed session JWT. The KMS bearer path accepts that token, so the weakness becomes full impersonation on the KMS (CVSS 4.0 base 9.3). F-002: Google CSE `privilegedunwrap` decrypts a wrapped data encryption key as the default user for any caller that holds a token from the configured identity provider (base 8.2, rated CRITICAL by the key-escrow amplifier). Both are present in tag 5.29.0.
- **The shipped defaults are open.** F-003: the packaged configuration binds `0.0.0.0:9998`, serves plain HTTP unless a TLS section is added, and treats every request as the full-privilege default user `admin` when no authentication method is configured (base 9.2, capped to HIGH because it is a documented insecure default that logs a startup warning). F-004: the Auth Verifier creates the administrator `admin` with the fixed password `change_me`, and the KMS bearer path accepts the resulting token as the KMS default user.
- **One process with `panic = "abort"` means that one bad value stops the whole server.** F-042 (CRL `validity_days`) and F-051 (`RotateInterval` and `RotateOffset`) are out-of-range time arithmetic on client-supplied values, and both were reproduced. F-051 is stored, so once automatic rotation is enabled the server aborts again on every restart until the value is removed. F-005 and F-006 are reachable without credentials, and F-009 and F-010 need only a low-privilege account (static traces).
- **Protections that operators or the documentation describe are weaker in the code.** F-008: CreateSplitKey copies a non-extractable or sensitive key into shares without the checks that `Get` applies, and JoinSplitKey rebuilds the key without the flags, so a caller that holds only a `Get` grant obtains the plaintext. F-011: an HSM key is created extractable and non-sensitive unless the caller passes `--sensitive`, which the HSM documentation contradicts. F-007: the MySQL `ssl-ca` setting adds a CA to the system trust store instead of pinning it. F-017 and F-043 show the same pattern in the Windows CNG provider and the PKCS#11 module.
- **The core held, and the baseline is credited.** 33 of the 51 findings are new. 12 are variants, incomplete fixes or a regression of an advisory already in `SECURITY.md`, 5 are items that the PR #998 security review already records, and 1 is documented design. Three earlier decisions need another look: F-002 (the fix of COSMIAN-2025-008 is incomplete), F-029 (a regression of COSMIAN-2026-013) and F-035 (the risk acceptance of COSMIAN-2025-011 rests on a statement that is false for one code path).

## Risk Summary

| Category | Risk Level | Notes |
| --- | --- | --- |
| Authentication & Authorization | 🔴 CRITICAL | F-001 (Auth Verifier sessions, CRITICAL). F-003 and F-004 (open shipped defaults, HIGH). F-013, F-014, F-015, F-020, F-022 and F-024 (MEDIUM), F-036 (LOW), F-046 and F-049 (INFO). Verified controls: constant-time API token and XKS key comparison, PKCE and nonce on the UI login, wildcard and reserved identities rejected, TLS session resumption off for client-certificate listeners (T-052 to T-059). |
| KMIP Protocol Security | 🟠 HIGH | F-008 (split keys expose non-extractable keys, HIGH). F-031 (UsageLimits bypass through batch Undo, MEDIUM). F-037, F-038 and F-039 (LOW). Verified controls: bounded TTLV parser, role and Create gates on every batched item, JOSE decrypt authorises before the CEK cache, CreateSplitKey refuses HSM sources (T-060, T-067, T-068, T-073). |
| Cryptographic Implementation | 🔵 LOW | F-033 (the session-key KDF takes the public URL as password), F-035 (a Marvin advisory ignore whose justification is false for the CSE migration JWT) and F-036 (JWKS refetched only when empty), all LOW, and the unverified notes R-08 and R-12. Verified controls: FIPS-only provider loading, minimum GCM tag length, PKCS#1 v1.5 encryption compiled only in non-FIPS builds, OpenSSL tarball checked against a pinned SHA-256 (T-063 to T-066). The unbounded-work finding F-009 is counted under Availability. |
| HSM Trust Boundary | 🟠 HIGH | F-011 (HSM keys are created extractable and non-sensitive unless `--sensitive` is passed; HIGH after the HSM-boundary amplifier). F-017 (Windows CNG provider) and F-043 (PKCS#11 module) repeat the pattern on the client side. Verified controls: HSM object creation is reserved to the HSM administrator, and CreateSplitKey refuses HSM-backed sources (T-068, T-069). HSM backends were not executed. |
| Dependency Supply Chain | 🟡 MEDIUM | F-012 and F-016 (long-lived tokens and a runner host SSH key exposed to jobs that run third-party code; both capped to MEDIUM). F-035 and F-048 (advisory handling), F-047 (a database file and test key material tracked in the Auth Verifier submodule). Verified controls: 143 of 143 external action references pinned to commit SHAs, keyless cosign signatures on container images, pnpm build scripts disabled (T-077 to T-079). |
| Availability and Resource Exhaustion | 🟠 HIGH | F-042 and F-051 (reproduced aborts of the whole server). F-005 and F-006 (unauthenticated, in features that must be enabled). F-009 and F-010 (unbounded work by a low-privilege caller). F-025 (MEDIUM) and F-040 (LOW). Verified controls: SigV4 verification gated by a CPU semaphore and a 5-minute freshness window, TTLV and batch limits (T-060, T-061). |
| Cloud Provider Routes | 🔴 CRITICAL | F-002 (Google CSE, CRITICAL). F-005 (AWS XKS, HIGH). F-013 (CSE and Azure EKM opt-out switches) and F-026 (MS DKE permissive CORS with credentials), both MEDIUM. F-035 (LOW). Verified controls: Azure EKM refuses to start without client authentication unless explicitly opted out, and the CSE rewrap SSRF guard (T-071, T-072). |
| PKI and Certificate Services | 🟠 HIGH | F-042 and F-006 (HIGH). F-019, F-025 and F-032 (MEDIUM). F-041 (LOW). F-050 (EST and SCEP trust model, documented design, INFO). Verified controls: CRL signing refuses a CA without `cRLSign`, and the CRL fetch applies the SSRF controls added for COSMIAN-2026-021 (T-062, T-070). |
| Database Layer | 🟠 HIGH | F-007 (the MySQL `ssl-ca` does not pin the CA, HIGH). F-019, F-027 and F-051 (MEDIUM). Verified control: the PostgreSQL backend pins the configured CA (T-074). Only SQLite was exercised. |
| Web UI and Clients | 🟡 MEDIUM | F-017, F-021, F-023, F-024 and F-028 (MEDIUM). F-033, F-034, F-043, F-044 and F-045 (LOW). Verified controls: PKCE and a per-login `state` on the UI login, anti-clickjacking headers on the UI responses (T-054, T-075). |
| Logging, Audit and Error Handling | 🟡 MEDIUM | F-018 (secrets in info-level startup logs), F-029 (raw internal error text in 5xx bodies; regression of COSMIAN-2026-013) and F-030 (audit is off by default and attached to two Actix scopes only), all MEDIUM, with F-019 (backend errors collapse to empty results). |

## Recommended Actions (Priority Order)

The order follows the rated severity, then the exploitability against the shipped configuration. Each finding card in `3-findings.md` has its own `Proposed Fix`; the list below groups the fixes that belong together. Nothing was applied.

1. **Close the Auth Verifier session API (F-001, CRITICAL).** Require `AdminAuth` plus a realm-administrator check for cross-user and cross-realm operations, and an ownership check (stored username and realm equal to the caller's claims) for self-service operations. Never return `cookie_string` from `GET`. Make the session upsert internal, restrict `DELETE /expired` and `DELETE /realms/{id}` to administrators and stop logging session ids. Keep the KMS self-delete call working (`crate/server/src/routes/ui_auth.rs:836-861`) and add negative tests. Until the fix ships, limit network access to the Auth Verifier to the hosts that need it.
2. **Restrict the three privileged Google CSE operations (F-002, CRITICAL).** Accept `privileged_unwrap`, `privileged_wrap` and `privileged_private_key_decrypt` only from a whitelisted KACLS verifier whose `aud` is `kacls-migration` for every resource type, or from an explicit administrator allow-list. Fail closed when no audience is configured, bind the `resource_name` and `kacls_url` claims, and never map an arbitrary identity-provider token to `default_username`. Add a negative test, flip the existing test that encodes the current behaviour and fix the documentation sample. The code is in tag 5.29.0, so a `SECURITY.md` entry is due when the fix ships (`AGENTS.md` §5.5). The existing entry COSMIAN-2025-008 (`SECURITY.md:1364-1380`) states that access is restricted to administrators, which the code does not do.
3. **Make the shipped defaults safe (F-003 and F-004, HIGH).** Bind `127.0.0.1` by default, or refuse a non-loopback bind without authentication and TLS unless an explicit opt-in is set. Run the container as a non-root user, make the Helm chart fail when no authentication is configured, enable its network policy by default and state the risk in `pkg/kms.toml`. In the Auth Verifier, print a random initial password once or enforce `change_password` at first login, reject admin-realm tokens on the KMS bearer path, and apply to every identity source the `default_username` guard that the SPIRE path already has (F-022).
4. **Bound client-controlled arithmetic and work (F-042, F-051, F-009 and F-010).** Validate and cap `validity_days` (for example at 365 days), `RotateInterval` and `RotateOffset` (positive, below a ceiling such as 100 years), and use `checked_add` at `crate/server/src/core/operations/generate_crl.rs:397`, `crate/server_database/src/stores/sql/locate_query.rs:715-721` and `crate/server/src/core/operations/auto_rotate.rs:355-359`. Treat an overflow as "not due" and log the object id. `catch_unwind` is no fix, because the release and dev profiles set `panic = "abort"` (`Cargo.toml:179` and `:203`). Cap the derived key length and the PBKDF2 work before deriving (F-009) and the split-key source size and total share bytes (F-010). Add regression tests with `u32::MAX`, `i64::MAX` and `i64::MIN`. To recover a server that aborts at every start because of a stored `RotateInterval` (F-051): start it with the scheduler disabled (`auto_rotation_check_interval_secs = 0`, the default), then run `ckms sym keys set-rotation-policy --key-id <id> --interval 0`. Both steps were run in the local probe.
5. **Bound the unauthenticated paths (F-005 and F-006, HIGH).** Read the XKS body with a byte limit (plaintext up to 4,300 bytes, AAD up to 8,192 bytes plus JSON overhead), reject an oversized `Content-Length` and a bad access key id or date before reading the body, add a body-read timeout and take the CPU permit before buffering. Answer all serials of an OCSP request with one lookup, cache negative results, rate-limit the nonce path and warn when OCSP is enabled without a limiter.
6. **Make the key-protection flags mean what they say (F-008, F-011, F-007 and F-017).** Refuse split-key sources that are `Extractable=false`, `NeverExtractable=true` or `Sensitive=true`, and let the shares and the reconstructed key inherit the flags. Create HSM keys with `sensitive=true` and `extractable=false` by default and correct `hsm_operations.md`. Call `.with_disable_built_in_roots(true)` whenever the MySQL `ssl-ca` is set and add a live TLS test that mirrors the PostgreSQL one. Create Windows CNG keys `Sensitive=true` and `Extractable=false` unless export is requested.
7. **Take long-lived secrets out of CI (F-012 and F-016, MEDIUM).** Compile in a job that holds no credential, publish from a final job bound to a protected environment with a short-lived GitHub App or fine-grained token, and set `persist-credentials: false`. Pin the `cosmian/docker_doc_ci` image by digest, and replace the bind-mounted runner SSH key with ephemeral runners, OIDC or a restricted upload-only key.
8. **Fail closed on the opt-out switches and on identity mapping (F-013, F-014, F-015 and F-022, MEDIUM).** Gate `--google-cse-disable-tokens-validation` and `--azure-ekm-disable-client-auth` behind the `insecure` feature or refuse them in release builds, and make `get_user` fail closed. Reject `email_verified=false`, or build the identity from `(iss, sub)`. Check client certificates against a CRL or OCSP (`X509_V_FLAG_CRL_CHECK`). Bind `default_username` to a single authentication method.
9. **Logs, errors and audit (F-018, F-029, F-030 and F-019, MEDIUM).** Redact every credential in the two configuration dumps (a `Secret<T>` type and a log allow-list), return a fixed body with a correlation id for 5xx responses, attach the audit hook to the socket server and the provider scopes, and return the error from the five lookup wrappers instead of an empty result (keep the previous CRL on failure and answer `tryLater` to OCSP).
10. **Tenancy in the Kubernetes clients (F-021 and F-023, MEDIUM).** Add a namespace-to-key allow-list to the operator and drop the server-side apply `.force()`. Use per-workload credentials or an allow-list in the CSI provider.
11. **Sessions and rate limits (F-024, F-033 and F-020).** Use server-side sessions, or `iat` plus a deny-list, for the UI cookie. Use the secret as the KDF password and the URL as context. Pass the end-user address from the KMS to the Auth Verifier in a header that only the KMS may set, and key the login bucket on username plus address.
12. **CRL fetch (F-025 and F-032, MEDIUM).** Stream the CRL body with a byte counter and bound the cache. Reuse the resolve-and-pin helper of the CSE rewrap guard and extend its blocklist.
13. **Remaining MEDIUM, LOW and INFO findings (F-027, F-028, F-031, F-034 to F-041 and F-043 to F-050).** Each card carries its own fix. The INFO items call for a decision or a hygiene change rather than a code fix: F-046 (make the BFF OIDC callback require `iss` and `aud`), F-047 (untrack the database file and test key material in the Auth Verifier submodule), F-048 (see item 14), F-049 and F-050 (known design choices).
14. **Process.** Add `cargo audit` to CI and record a justified `not_affected` VEX statement for each advisory that stays in `Cargo.lock`, or run `cargo update -p quinn-proto -p quinn-udp -p rustix` (F-048). Write the `SECURITY.md` entries that `AGENTS.md` §5.5 requires for the findings listed under Release Exposure once they are fixed. Confirm that the `test_data` commit pinned by the branch is merged in `test_data` before PR #998 merges (see Dependency Analysis). Re-run this threat model in incremental mode with `threat-inventory.json` as the baseline after the fixes.

## Scope Limitations

- **Static analysis, two executed probes.** Apart from F-042 and F-051, every finding is a static trace of the code that was not executed. The two probes ran against a local debug build (`target/debug/cosmian_kms`) in non-FIPS mode with OpenSSL 3.6.5, SQLite, no authentication and scratch databases. Figures that were not measured are labelled "estimate, not executed".
- **No FIPS-mode run and no release build.** The abort behaviour of F-042 and F-051 was observed on a debug build. The release and dev profiles both set `panic = "abort"` (`Cargo.toml:179` and `:203`), which is the basis for the same behaviour in a release build.
- **Backends not exercised.** HSM (PKCS#11), PostgreSQL, MySQL and Redis-Findex were read as source only.
- **The Auth Verifier was read as source only.** It is a git submodule (`authentication/`, pinned at `012d6613`) that was never built or run. F-001 and F-004 rest on a reading of its session scope and its bootstrap code.
- **Not analysed or not verified.** Runtime FIPS behaviour, including whether the FIPS provider refuses SHA-1 on the CSE `private_key_sign` path (R-08); SAML validation; races that need concurrent execution; `HTTPS_PROXY` against the DNS pin; invalid-curve handling in JOSE ECDH; deployed Rego policies; the AWS XKS documentation; the browser behaviour of the cloud routes (CORS and Private Network Access); the real DKE authentication behaviour of the Office client.
- **Dependencies.** Only the Rust dependency graph (`Cargo.lock`) was scanned, with `cargo audit` and `cargo tree`. The pnpm, Python, Go and container-image dependencies were not scanned.
- **Not findings by design.** The native Crypto Officer bypass of OPA is decision D2 of the PR #998 review (F-049 records the related gap on non-KMIP routes). `JoinSplitKey` stays open to every user by design (`SECURITY.md:302`).
- **Release exposure is partial.** The cited code was compared with tag `cosmian-kms-5.29.0` for a subset of the findings only. A finding that is not in the Release Exposure table is "unknown, not absent".
- **Scores are triage estimates.** The CVSS 4.0 vectors describe the least-privileged realistic attacker against the shipped or documented configuration. They are not a substitute for a maintainer's own scoring.
- **The 24 unverified notes in the appendix of `3-findings.md` are not counted and not scored.** Each one names the evidence that is missing.

## Context — PR #998 and the Baseline

PR #998 "feat: OPA server + Authentication server" (head `17926f40b`, 143 files, +9912/−1287) was open, mergeable and approved when this analysis ran. Its own security review (`SECURITY-REVIEW.md`, a local untracked working note) recorded 24 findings, fixed 18 of them in the commits `318349eb1` to `f8774ea79`, and left the decisions D1 to D11 open. This threat model is a separate analysis of the whole repository. It credits the following baseline and does not report it again:

- The `SECURITY.md` advisories COSMIAN-2026-017 to COSMIAN-2026-056, GHSA-8mmx-f92q-2gq8 (`SECURITY.md:633`), GHSA-c75c-3cmm-48h7 (`SECURITY.md:671`), COSMIAN-2025-008 (`SECURITY.md:1364-1380`) and COSMIAN-2025-011 (`SECURITY.md:1269`).
- Findings 1 to 24 and decisions D1 to D11 of `SECURITY-REVIEW.md`.
- The dependency exceptions in `.cargo/audit.toml:9,11` and `deny.toml:67-74`.

Relative to that baseline, the 51 findings fall into four classes:

| Class | Count | Findings |
| --- | --- | --- |
| New | 33 | F-001, F-006, F-010, F-011, F-012, F-013, F-015, F-016, F-017, F-019, F-020, F-021, F-022, F-023, F-027, F-028, F-030, F-031, F-033, F-034, F-035, F-036, F-037, F-038, F-040, F-041, F-042, F-043, F-044, F-045, F-047, F-048, F-051 |
| Variant, incomplete fix or regression of an earlier advisory | 12 | F-002, F-005, F-007, F-008, F-009, F-018, F-024, F-025, F-026, F-029, F-032, F-039 |
| Already recorded by the PR #998 review | 5 | F-003, F-004 and F-014 (each with a new angle), F-046 and F-049 |
| Documented design | 1 | F-050 |

Three earlier decisions did not hold up:

- **F-002** is an incomplete fix and a regression of COSMIAN-2025-008. The advisory says access was restricted to administrators; the code has only a `/drive/`-scoped audience check that compares the audience with its own configuration.
- **F-029** is a regression of COSMIAN-2026-013, introduced by commit `c45074fcd` (first in tag 5.29.0).
- **F-035** removes the basis of the risk acceptance COSMIAN-2025-011 (`SECURITY.md:1269`): the justification that the `rsa` crate is used for public-key operations only is false for the CSE migration JWT, which signs RS256 with a private key.

The OPA integration, which is new in PR #998 (`crate/server/src/core/opa/`, absent from tag 5.29.0), produced one INFO finding, F-049, which is a known class (decision D2), and one verified control, T-080: the OPA client fails closed and has a 5-second timeout. No other finding concerns the OPA integration, and none is claimed to be introduced by the PR. The Release Exposure table lists the findings that were confirmed in tag 5.29.0.

## Themes

**Identity and sessions (F-001, F-003, F-004, F-014, F-020, F-022, F-024, F-033, F-036 and F-046).** Identities from all trusted JWT issuers share one flat namespace (the `email` claim, else `sub`), and `default_username` is not reserved on the JWT paths. That is decision D1 of the PR #998 review, and it is what turns a weakness in one issuer into a KMS identity. A stolen Auth Verifier session token (F-001) or the fixed bootstrap password (F-004) is accepted by the KMS bearer path, which checks the signature, the expiry and the session liveness but not the realm, and which maps the subject `admin` to the KMS default user. The KMS documentation says that admin-realm sessions must never authenticate to the KMS. F-003 covers deployments without any authentication method: the default user is injected and holds full privileges. F-014 and F-022 are the same namespace problem on the JWT and mTLS paths; F-022 is a hypothesis that was not confirmed.

**Availability (F-042, F-051, F-005, F-006, F-009, F-010, F-025 and F-040).** The KMS is one process with `panic = "abort"` and overflow checks on (`Cargo.toml:179`, `:182` and `:203`), so out-of-range arithmetic on a value that a client supplies stops every tenant at once. Two of the findings were reproduced against a local debug build:

| Finding | Input | Result |
| --- | --- | --- |
| F-042 | CRL `validity_days` of 7, 36,500 and 2,900,000 | Accepted |
| F-042 | CRL `validity_days` of 2,950,000 | The server aborted at `generate_crl.rs:397:23` with "resulting value is out of range" |
| F-051 | `RotateInterval` of 9,000,000,000,000 on a key | The next scheduler tick aborted the server at `locate_query.rs:721:9` with "resulting value is out of range" |
| F-051 | Two restarts on the same database | Both aborted with exit status 134 within about 35 ms, before the listener bound |
| F-051 | Restart with the scheduler disabled | The server started and `POST /kmip/2_1` with `{}` returned 422; the key and its interval were intact |
| F-051 | `ckms sym keys set-rotation-policy --key-id <id> --interval 0`, then a restart with the scheduler on | The key was repaired and the server logged "No keys due for rotation" |
| F-051 | ReKey and ReCertify `offset` of 4,294,967,295 | Accepted (HTTP 200) |
| F-051 | ReKey and ReCertify `offset` of 4,294,967,296 and 9e12 | Refused with HTTP 422; the server stayed up (`offset` is a KMIP `Interval`, a `u32`) |

A far-future `nextUpdate` from F-042 is cached, and the CRL refresh cron then stops refreshing that CRL. Interval values above about 2.5 × 10^11 seconds are expected to overflow the signed 64-bit arithmetic (estimate, not executed). The scheduler is off by default (`crate/server/src/config/command_line/clap_config.rs:292-296`), values below 60 seconds are refused (`crate/server/src/config/params/server_params.rs:974-985`) and the documentation uses 300 seconds, so F-051 needs an operator who enabled it; that is why it is MEDIUM and not HIGH. F-005 (the XKS SigV4 middleware buffers the request body without a size limit before it verifies the signature) and F-006 (one database lookup per serial of an OCSP request) are reachable without credentials, but only where the XKS routes or the OCSP responder are enabled. F-009 and F-010 need only a low-privilege account. Those four are static traces.

**Cloud provider routes (F-002, F-005, F-013, F-026 and F-035).** The four provider scopes (`/google_cse`, `/aws`, `/azure_ekm` and `/ms_dke`) are separate trust domains with their own authentication, and the KMS-wide controls do not reach them uniformly: audit is attached to two scopes only (F-030), CORS on `/ms_dke` is permissive (F-026), and the `--google-cse-disable-tokens-validation` and `--azure-ekm-disable-client-auth` switches remove authentication and act as the default user (F-013). F-002 is the only finding of the group that exposes key material, and the key-escrow amplifier rates it CRITICAL. Two controls held: Azure EKM refuses to start without client authentication unless the explicit opt-out is set (T-072), and the CSE rewrap SSRF guard resolves, pins and does not follow redirects (T-071).

**Key-protection flags (F-008, F-011, F-017, F-043 and F-007).** The same pattern recurs: a flag or a setting says that material is protected, and one code path does not honour it. `Get` refuses a non-extractable key and CreateSplitKey does not (F-008). The HSM documentation says that keys are always created with `CKA_SENSITIVE=true`, and they are created non-sensitive by default (F-011). The Windows CNG provider sets `allow_export` and `allow_plaintext_export` (F-017), and the PKCS#11 module reports keys as non-extractable while it serves `CKA_VALUE` (F-043). The MySQL `ssl-ca` option does not pin the CA, where the PostgreSQL backend does (F-007 and T-074).

**Secrets and files (F-018, F-028, F-047 and F-012).** Two info-level configuration dumps print the proxy password, a custom proxy header, the CSE migration key PEM and, in non-FIPS builds, the Redis URL (F-018, an incomplete fix of COSMIAN-2026-014 and COSMIAN-2026-038). `ckms.toml`, exported keys and decrypt outputs are written with `fs::write` and `File::create`, which give mode `0666` minus the umask, while `ckms.toml` holds tokens and passwords in clear text (F-028). A 98,304-byte `auth_verifier.db` and 20 test certificate and key files are tracked in the Auth Verifier submodule (F-047).

**Supply chain and CI (F-012, F-016, F-035, F-047 and F-048).** The pinned parts held: the OpenSSL tarball is checked against a pinned SHA-256 (T-063), all 143 action references are pinned to commit SHAs (T-077), container images are signed with keyless cosign (T-078) and pnpm build scripts are disabled (T-079). What is exposed is the secrets that jobs hold. A personal access token with the `repo` and `workflow` scopes is left in the git configuration of release jobs that run `cargo build --workspace`, next to the crates.io token in the publish step (F-012). Eight self-hosted-runner jobs bind-mount the runner host's `/home/cosmian/.ssh/id_rsa` into the mutable, untagged `cosmian/docker_doc_ci` image as root (F-016). Both are capped to MEDIUM because exploitation needs a prior compromise.

## Dependency Analysis

`cargo audit` 0.22.1, run on 2026-11-14 against 1,509 advisories and the 790 crates of `Cargo.lock`, exits with status 1: 8 vulnerabilities and 1 warning, on top of the two advisories that `.cargo/audit.toml` ignores. None is reachable, and none has a statement in `sbom/openvex.json` (F-048, INFO). The full output is not part of the artifacts.

| Crate | Version | Advisories | Reachable |
| --- | --- | --- | --- |
| `quinn-proto` | 0.11.16 | RUSTSEC-2026-0524, RUSTSEC-2026-0339, RUSTSEC-2026-0341, RUSTSEC-2026-0342, RUSTSEC-2026-0523, RUSTSEC-2026-0338 and RUSTSEC-2026-0340 | No |
| `quinn-udp` | 0.5.15 | RUSTSEC-2026-0538 | No |
| `rustix` | 1.1.4 | RUSTSEC-2026-0486 (`unsound`, reported as a warning) | No |

`quinn`, `quinn-proto` and `quinn-udp` are in the lock file only as optional dependencies of `reqwest` 0.12.28, behind its `http3` feature, which also needs `--cfg reqwest_unstable`. No workspace manifest enables it, and `cargo tree` has no `quinn` or `h3` entry. `rustix` is compiled in through `tempfile` 3.27.0, its only dependent, and neither `tempfile` nor the workspace sources use extended attributes. The gap is in the process: `.cargo/audit.toml:6` requires a VEX statement for every exception, and no workflow in `.github/` runs `cargo audit`. The hosted "Security Audit" check is `cargo-deny`, which passes. `cargo-deny` evaluates the resolved dependency graph, so it probably does not see lock entries that no build uses (estimate: its graph behaviour was not tested). The only `cargo audit` call is the local script `.mise/scripts/audit/multi_framework.sh:129-132`. `Cargo.lock` last changed on 2026-11-12 (#1404).

The two ignored advisories are `RUSTSEC-2023-0071` (`rsa` 0.9, the Marvin attack; `.cargo/audit.toml:9`) and `RUSTSEC-2026-0387` (`crypto-bigint` 0.5.5; `:11`), mirrored in `deny.toml:67-74`. `sbom/openvex.json` marks `rsa@0.9.10` `not_affected` (line 12) and `crypto-bigint@0.5.5` `under_investigation` (line 21, set on 2026-11-12T16:48:49Z). `rsa` 0.9.10 is reached through `jsonwebtoken` 10.4.0 and `pgp` 0.21.0, and `crypto-bigint` 0.5.5 through `elliptic-curve` 0.13.8 (through `pgp`). F-035 shows that the justification of the Marvin exception ("public-key operations only") is false for the CSE migration JWT, which signs RS256 with a private key.

The lock holds two `reqwest` versions: 0.12.28 for the workspace and 0.13.4 for the `authentication` submodule. The gitlinks at HEAD are `.github/reusable_scripts` `b33a969b`, `authentication` `012d6613`, `documentation/theme` `b268a8e5` and `kmip` `a771328a`, and `test_data` is pinned at `cc30ab4f0ae22427a40d66497aa10e1973079ea2`. This clone contains that `test_data` commit only through `origin/feat/rbac-keycloak-opa-stack`, so confirm that it is merged in `test_data` before PR #998 merges. The four workflow references to `Cosmian/reusable_workflows` use the pin `9079c7a0`.

## Release Exposure

Fifteen findings were compared with the release tag `5.29.0` (commit `1d6783669`, 2026-10-30) by reading the cited code at the tag with `git show`. The method is a static comparison of the cited code, not a run of the released binary.

| Finding | Present in tag 5.29.0 | Basis |
| --- | --- | --- |
| F-001 | Yes | At the tag the Auth Verifier is pinned at `904a068d`, and `auth_verifier.rs:539` wraps the `/sessions` scope with `CookieAuthSameServer` only. `sessions_endpoints.rs`, `auth_verifier.rs` and `trait.rs` are byte-identical at that pin and at the current pin `012d6613`. The KMS bearer path `token.rs` came with `e4f27a1ab` and is in every tag from 5.26.0 on |
| F-002 | Yes | `google_cse/jwt.rs:288-316` has the audience check on `/drive/` resource names only and maps a privileged token to `kms_default_username`; `operations.rs:777` has `privileged_unwrap` |
| F-003 | Yes | `pkg/kms.toml` has `hostname = "0.0.0.0"` and `default_username = "admin"`, `http_config.rs:9-13` defaults to `0.0.0.0`, and the Helm chart has `networkPolicy.enabled: false` and `defaultUsername: admin`. All of it is identical at HEAD |
| F-004 | Yes | `trait.rs:73` has `APP_REALM_ADMIN_INITIAL_PASSWORD = "change_me"` and `:92` has `allow_expired_passwords: true`; the file is byte-identical at the two submodule pins |
| F-005 | Yes | `sigv4_middleware.rs` has the same `fold(BytesMut::new()` body buffering |
| F-006 | Yes | `ocsp/handler.rs` has `for query in &queries`, and `core/certificate/find.rs` is unchanged |
| F-007 | Yes | `mysql.rs` has `with_root_certs` and has no `with_disable_built_in_roots` |
| F-008 | Yes | `create_split_key.rs` has no Extractable or Sensitive check on the source key; only the shares get `sensitive: Some(true)` (`:313` and `:333`) |
| F-009 | Yes | `derive_key.rs` reads `cryptographic_length` at `:181-184`, has only `MAX_PBKDF2_ITERATIONS` (`:59`) and checks the length after the derivation (`:255`) |
| F-010 | Yes | The only bound is `split_key_parts > 255` (`:92`) |
| F-011 | Partly | `crate/hsm/base_hsm/src/session/aes.rs` is unchanged since the tag and keeps the `unwrap_or(false)` default for `sensitive`. `hsm_store.rs` changed by +902 and −133 lines since the tag and was not compared line by line |
| F-020 | Partly | Only the UI relay route was seen at the tag (`login_as`, six occurrences in `ui_auth.rs`); the Auth Verifier rate limiter was not compared |
| F-029 | Yes, new in 5.29.0 | Introduced by `c45074fcd` (2026-10-09, #1240); tags 5.22.0 to 5.28.0 return a fixed text |
| F-042 | Yes, since 5.27.0 | `generate_crl.rs:365` computes `generated_at + time::Duration::days(i64::from(validity))` without `checked_add` and without a cap. The line is absent in tag 5.26.0 and present in 5.27.0, 5.27.1, 5.28.0 and 5.29.0 |
| F-051 | Yes, since 5.25.0 | `locate_query.rs` has `is_due_for_rotation` (`:681`), `Duration::seconds(interval_secs)` (`:686`) and `Duration::seconds(attrs.rotate_offset.unwrap_or(0))` (`:691`) without `checked_add`. The code is absent in tag 5.24.0 and present from 5.25.0 to 5.29.0 (`7fdc944a1`, #968) |

All other findings were not compared with the tag: unknown, not absent. `crate/server/src/core/opa/client.rs` is absent at the tag, so the OPA integration is new in PR #998; its only finding is F-049 (INFO). AGENTS.md §5.5 asks for a `SECURITY.md` entry when a fix addresses a vulnerability that shipped in a tagged release, so the fix of each row marked "Yes" will need a `COSMIAN-YYYY-NNN` entry. This analysis did not edit `SECURITY.md`.

## Incidental Defect and Conditional Upgrade

**R-12: a functional defect without an adversary (confirmed by reading both call sites, not executed).** Both Base64 key exports lower-case the encoder output: `crate/clients/wasm/src/wasm.rs:1764-1766` and `crate/clients/clap/src/actions/shared/export_key.rs:168-170` call `.to_lowercase()` on the result of the standard Base64 encoder. Base64 is case-sensitive, so a decoder reads different bytes, and the exported backup of a key whose encoding contains an upper-case letter is corrupt. This is not a vulnerability. It is listed here because it would otherwise stay hidden in the appendix, and it affects the backups of the keys that the KMS protects. A fix removes `.to_lowercase()` at both sites and adds a round-trip test.

**R-08: a conditional upgrade, not verified.** SHA1withRSA is accepted on the CSE `private_key_sign` path with no Rust-side FIPS gate (`crate/crypto/src/crypto/rsa/sign.rs:51`). The same appendix row lists four smaller points: no PSS salt-length floor, signature and data logged at error level when a verification fails (`crate/crypto/src/crypto/rsa/verify.rs:142-143`), non-zeroised temporaries, and revocation checking that soft-fails when a CRL distribution point is unreachable (`crate/server/src/core/operations/validate.rs:899-902`). If the OpenSSL FIPS provider accepts SHA-1 for this operation, the FIPS amplifier of the method (a non-approved algorithm in FIPS mode is rated CRITICAL) would apply. Whether the provider refuses it was not verified, so R-08 stays an unscored note and no standard section is cited for it.

**Documentation drift and build-script reuse (static reading, not findings).** `SECURITY.md:1557` says that the KMS links against OpenSSL 3.6.2, whereas `crate/crypto/build.rs:7` pins 3.6.5. In the same script, line 85 skips the build whenever `lib/libcrypto.a` already exists in the prefix, without checking its version, and lines 53-57 take `OPENSSL_DIR` as it is when `openssl.cnf` and the `ossl-modules` directory exist. The pinned SHA-256 therefore covers the download path only. Using a stale or substituted prefix needs write access to the build tree or to the build environment, which is why this is a note and not a finding.

## Scoring and Mapping Conventions

**Evidence basis.** Every finding is a static trace of the code at the cited lines, except F-042 and F-051, which were also reproduced on a local debug build (non-FIPS, SQLite, no authentication, scratch databases under `/tmp`). No FIPS build or release build was run, the HSM, PostgreSQL, MySQL and Redis variants were not exercised, and no test was added to the repository. "Confidence" in the cards is the analyst's estimate, out of 10, that the described condition exists and is reachable as stated.

**CVSS 4.0.** The base score of every finding is computed from an evidence-based vector with the `cvss` Python package (`CVSS4`); no score was typed by hand. The vector describes the least-privileged realistic attacker against the shipped or documented configuration, and it prefers an honest `AC:H` or `AT:P` to a cap. The subsequent-system metrics (`SC`, `SI` and `SA`) are set only for a downstream effect that the code shows. The rated severity is the band of the base score (CRITICAL from 9.0, HIGH from 7.0 to 8.9, MEDIUM from 4.0 to 6.9, LOW from 0.1 to 3.9), except for the rows marked † (capped) and ‡ (raised). INFO rows have no vector and no score. Findings are ordered by rated severity, then by base score, then by exploitability, then by business impact. IDs are stable from the first ranking pass, so F-042 (re-rated from LOW to HIGH after its probe) and F-051 (added after its probe) are out of ID order in the index. The 24 unverified notes of the appendix are not scored.

**Adjustments register.** A MEDIUM cap applies when the attack needs a prior compromise of a credential, a third party or a developer account, an explicit operator opt-out switch, or an identity provider or secret configured against a documented operator requirement. A HIGH cap applies to a documented insecure default. A LOW cap applies when the trigger is an independent failure that the attacker cannot cause. The base score stays visible so that a reviewer can disagree with the cap. A KMS amplifier raises the rating only where the finding itself demonstrates the condition.

| ID | Base and band | Rated | Reason |
| --- | --- | --- | --- |
| F-002 ‡ | 8.2 HIGH | CRITICAL | Key-escrow amplifier: key material leaves the KMS without the owner's consent. The independent verifier suggested HIGH |
| F-011 ‡ | 6.0 MEDIUM | HIGH | HSM-boundary amplifier, one tier up. With `AT:N` the base would be 7.1 |
| F-003 † | 9.2 CRITICAL | HIGH | A documented insecure default that logs a startup warning; the operator must deploy it without any authentication |
| F-012 † | 9.1 CRITICAL | MEDIUM | Needs a prior compromise of a third party; a reviewer who counts that as in scope would keep CRITICAL |
| F-013 † | 8.3 HIGH | MEDIUM | Explicit operator opt-out switches whose help text says they are for tests; the cloud-route amplifier is declined |
| F-014 † | 7.6 HIGH | MEDIUM | Needs an identity provider that lets a user choose a verified-looking `email`, which the documentation tells operators not to allow |
| F-015 † | 7.6 HIGH | MEDIUM | Needs a client certificate that was compromised and then revoked; a documented limitation for EST. The vector uses `PR:L`; with `PR:N` it would score 9.1 |
| F-016 † | 7.0 HIGH | MEDIUM | The jobs run only for tags, pushes to `develop` or `main`, the schedule and manual dispatch; exploitation needs a prior compromise |
| F-033 † | 9.1 CRITICAL | LOW | Works only if the operator independently chose a guessable salt of at least 32 bytes (`AT:P`). With `VC:L` and `VI:L` the base would be 6.3 |
| F-034 † | 6.3 MEDIUM | LOW | Needs a failure that the attacker cannot cause (a slow, unreachable or hostile Auth Verifier, `http://`, or verification turned off); the vector scores only the availability effect |

**Declined amplifiers.** The rating that would apply if a reviewer disagrees is stated on the card.

- F-005 would be CRITICAL under the cloud-route amplifier. It stays HIGH because only availability is affected and no key material is exposed.
- F-008 would be CRITICAL under the key-escrow amplifier. It stays HIGH because the caller already holds the `Get` grant.
- F-021 and F-023: the multi-tenant amplifier is declined, because the effect depends on the grants of the shared KMS identity, which the repository does not define.
- F-030: the cloud-route amplifier is not applied to the unaudited provider scopes.
- F-035 and F-038: the FIPS amplifier is not applied. For F-035 the algorithm is approved and only the implementation lies outside the FIPS provider; for F-038 the algorithms are approved and are only not the ones that the configured policy selects.

**Other vector choices.**

- F-051: base 6.0, no cap and no amplifier. `AT:P`, because the scheduler is an operator opt-in (`AT:N` would score 7.1). With Crypto Officers configured the attacker needs `PR:H`, which scores 5.9, still MEDIUM.
- F-042: `PR:L`. `PR:H` would score 6.9.
- F-009 and F-010: `PR:L`. `PR:N` would score 8.7.
- F-004: `AV:A`, because the packages bind to localhost (`AV:N` would score 9.5 and `AV:L` 8.8).
- F-007: `AV:A`, `AC:H` and `AT:P` (`AV:N` would score 9.1).

**OWASP Top 10:2025.** Every finding carries exactly one category, with the numbers and names that OWASP published for 2025 (downloaded on 2026-11-14): A01 Broken Access Control (which includes SSRF, CWE-918), A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures and A10 Mishandling of Exceptional Conditions. The table in the reference file of the method (`threat-model-analysis-principles.md`, lines 114-127) mixes 2021 and 2025 numbering and does not match the published list, so the published list was used. 37 of the 51 findings use a CWE that is listed on the page of their category. The other 14 were mapped by the definition of the category, because their CWE is not listed there:

- F-003 and F-011 (CWE-1188) to A02.
- F-045 (CWE-295) to A02.
- F-005, F-009, F-010 and F-025 (CWE-770) to A06.
- F-006, F-034 and F-040 (CWE-400) to A06.
- F-012 and F-016 (CWE-522) to A03.
- F-042 and F-051 (CWE-1284) to A10.

The distribution over the 51 findings is A01 13, A06 11, A07 9, A10 5, A03 4, A02 4, A09 2, A04 2, A08 1 and A05 0.

## Companion Artifacts

All artifacts are in `threat-model-20261114-173721/`, which the repository ignores through `/threat-model*`. Nothing was committed and no remediation was applied.

| File | Content |
| --- | --- |
| `0-architecture.md` | System description, component and asset inventories, trust boundaries TB1 to TB13, the authorization layers as shipped, and the runtime properties that shape the model |
| `1-dfd.md` | Nine data-flow diagrams (Mermaid) |
| `2-stride-analysis.md` | STRIDE-A matrix per component: T-001 to T-051 map one-to-one onto F-001 to F-051, T-052 to T-080 are the 29 verified controls, and 12 threat narratives |
| `3-findings.md` | Ranked index, 51 finding cards with CVSS 4.0 vector, CWE, OWASP mapping, evidence, attack scenario and proposed fix, and the appendix of 24 unverified notes |
| `threat-inventory.json` | Machine-readable inventory of the 51 findings and the 24 notes |
| `threat-model-20261114-173721.pdf` | The five documents in one file |

*Generated by AI Threat Model Analyst. All findings require human review before remediation.*
