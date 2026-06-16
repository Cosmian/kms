---
name: security-review
description: 'AI-powered security scanner — OWASP Top 10, CWE Top 25, KMIP authorization, FIPS gating, memory safety, side-channel, supply chain, and 20 vulnerability families. Use when asked to review code security, audit KMIP access control, or scan for vulnerabilities.'
---

# Security Review

An AI-powered security scanner that reasons about code the way a security researcher would — tracing data flows, understanding component interactions, and catching vulnerabilities that pattern-matching tools miss. Covers all major software vulnerability families relevant to a Rust + TypeScript KMS with FFI to OpenSSL and PKCS#11 HSMs.

## When to use

- Scan a codebase or file for security vulnerabilities
- Check for SQL injection, command injection, secrets exposure, auth bypass
- Review KMIP operation authorization (missing `is_allowed()` calls, unauthorized key material access)
- Audit FIPS feature flag gating consistency
- Audit memory safety (FFI, `unsafe` blocks), side-channel resistance, supply chain integrity
- Any request like "is my code secure?", "audit this codebase", "review for vulnerabilities"

## Execution

Follow these steps **in order**:

### Step 0 — Load Anti-Hallucination Discipline

Read `.github/skills/shared/anti-hallucination.md` **before any analysis**. All rules in
that file are mandatory for this skill. Do not proceed to Step 1 until you have read it.

### Step 1 — Scope Resolution

If a path was provided (e.g. `/security-review crate/server/src/core/`), scan only that scope.
If no path given, scan the **entire project** starting from the root.

Identify the primary language(s): Rust (main), TypeScript (UI), Bash (scripts).

### Step 2 — Dependency Audit

- **Rust**: Check `Cargo.toml` and `Cargo.lock` for known vulnerable crates (CVEs in `cargo audit` watchlist).
    - Flag crates with known CVEs, deprecated crypto libs, or unpinned versions.
    - Special attention: `openssl`, `ring`, `rustls`, `hyper`, `actix-web`, `serde`.
- **Node/pnpm**: Check `ui/pnpm-lock.yaml` for vulnerable npm packages.
- **Python** (test scripts): Check `.github/scripts/` for insecure subprocess calls.

### Step 3 — Secrets & Exposure Scan

Scan ALL files (config, CI, Dockerfiles, shell scripts, Rust source) for:

- Hardcoded API keys, tokens, passwords, private keys in source code or comments
- `.env` files accidentally committed
- Secrets in log statements (`debug!`, `trace!`, `info!` with sensitive variable names)
- Database connection strings with embedded credentials
- Hardcoded test credentials that may reach production paths

Flag any `// TODO: debug — remove before shipping` markers left in the codebase.

### Step 4 — Vulnerability Deep Scan

#### Injection Flaws

- SQL / NoSQL injection in `crate/server_database/src/` — raw query construction with user input
- Command injection in shell scripts under `.github/scripts/` — `$variable` without quoting
- LDAP / XPath injection (N/A for this stack)
- Log injection — user-controlled content passed to log macros without sanitization

#### Authentication & Access Control

- Missing authentication on sensitive Actix-web endpoints in `crate/server/src/routes/`
- Broken object-level authorization: KMIP operations in `crate/server/src/core/operations/` that return or modify key material **without** calling the access-control check (typically `db.is_allowed(...)` or equivalent in `crate/access/`)
    - Every operation that reads a `KmipObject` (Get, Export, Decrypt, Sign, MAC, Derive) must verify the caller owns or has been granted access to the key UID
    - `Locate` operations must filter results to objects the caller can access — not return global object lists
    - Wrap/Unwrap operations must verify access to both the wrapping key and the wrapped key
- JWT weaknesses in `crate/server/src/middlewares/` — `alg:none`, weak secrets, missing expiry validation
- Session or API token bypass: `insecure` feature flag code that disables auth must be strictly gated with `#[cfg(feature = "insecure")]`
- Privilege escalation via the `crate/access/` module — check that grant/revoke operations require owner or admin privilege

#### KMIP Protocol Authorization (this repo-specific)

Review each file in `crate/server/src/core/operations/`:

- Does the operation check access before returning key material?
- Does the operation check access before performing a destructive action (Destroy, Revoke)?
- Does `Locate` scope results to the authenticated user's owned + granted objects?
- Are `Create`, `Register`, `Import` operations linking the new object to the authenticated user as owner?
- Are there any code paths that can be reached without the `EnsureAuth` middleware being enforced?

#### FIPS Feature Flag Consistency

- Scan for `#[cfg(feature = "non-fips")]` usage — verify it is at function/module level, never inline inside function bodies
- Scan for non-FIPS algorithms (MD5, SHA1, DES, RC4, Blowfish) used outside `#[cfg(feature = "non-fips")]` gates
- Verify `crate/server/src/start_kms_server.rs` scope registrations for non-FIPS routes are wrapped in `#[cfg(feature = "non-fips")] { ... }`
- Check that `insecure` feature does not bypass FIPS algorithm enforcement

#### Data Handling

- Sensitive data (private key bytes, plaintext, passwords) in error messages or `Display` impls
- Missing zeroization of sensitive buffers (look for `zeroize` crate usage on key material)
- Path traversal in file-based operations (SQLite path, cert file paths from config)
- SSRF: outbound HTTP calls in cloud provider routes (`crate/server/src/routes/aws_xks/`, etc.) — verify URL validation

#### Cryptography

- Use of deprecated algorithms: MD5, SHA1 for security-sensitive purposes
- Hardcoded IVs or salts in `crate/crypto/src/`
- Weak RNG: `rand::thread_rng()` used for key generation instead of `rand::rngs::OsRng`
- OpenSSL provider init: verify `apply_openssl_dir_env_if_needed()` is called before any `Provider::try_load()`

#### UI / TypeScript

- XSS: `dangerouslySetInnerHTML`, unescaped user content in React components
- Insecure WASM call error handling — errors containing sensitive server info surfaced to UI
- Hard-coded CSE/EKM keys in `ui/src/`

#### Memory & Type Safety (CWE-119, CWE-125, CWE-416, CWE-843)

Critical for Rust `unsafe` blocks and FFI to OpenSSL / PKCS#11 / HSM libraries:

- Buffer overflow / underflow in FFI call sites (`crate/hsm/*/src/`, `crate/crypto/src/`)
- Integer overflow / underflow / truncation in key-size arithmetic, TTLV length fields (`crate/kmip/src/`)
- Use-after-free, double-free in `unsafe` blocks — require `// SAFETY:` comment; flag every `unsafe` without one
- Type confusion in TTLV deserialization — mismatched tag/type casting
- Uninitialized memory reads that could leak secrets via FFI return buffers

#### Deserialization & Protocol Parsing (CWE-502, CWE-400)

- TTLV parsing: unbounded length fields that trigger OOM, malformed tag handling, integer overflow in length math
- JSON deserialization (serde): missing field validation, type coercion attacks, missing `#[serde(deny_unknown_fields)]` on security-critical structs
- HTTP request smuggling (Actix-web) — Transfer-Encoding / Content-Length conflict handling
- Prototype pollution in TypeScript (`ui/src/`) — `Object.assign` or spread with user-controlled keys

#### Race Conditions & TOCTOU (CWE-362, CWE-367)

- TOCTOU in key lifecycle state transitions — gap between `is_allowed()` check and state mutation
- Database access patterns without serializable isolation for key ownership changes or grant/revoke operations
- Shared state in `OnceLock` / `Mutex` / `RwLock` — deadlock potential or poisoned lock propagation in error paths
- Concurrent `Create` + `Destroy` on the same UID — race to key existence

#### Denial of Service (CWE-400, CWE-1333, CWE-770)

- **ReDoS**: scan all regex patterns in Rust (`regex::Regex::new(...)`) and TypeScript for catastrophic backtracking
- Algorithmic complexity attacks — unbounded loops or quadratic operations triggered by user-controlled input size
- Resource exhaustion: unbounded memory allocation from KMIP request fields, unlimited DB query result sets, no cap on concurrent HSM sessions
- Amplification: single KMIP request triggering many sub-operations (e.g., `ReKey` across large object sets)

#### Side-Channel Attacks (CWE-208, CWE-385)

- **Timing attacks**: non-constant-time comparisons of secrets, MACs, or password hashes — search for `==` on `&[u8]` secrets instead of `constant_time_eq`
- **Marvin Attack / ROBOT Attack**: RSA PKCS#1 v1.5 decryption with observable error differences (see `RUSTSEC-2023-0071` in `SECURITY.md`)
- **Lucky13 / CBC padding oracle**: any CBC-mode decryption path where error messages distinguish "bad padding" from "bad MAC"
- **Cache-timing**: AES table-lookup implementations (should use OpenSSL/AES-NI, not pure-Rust table-based AES)
- **Speculative execution**: sensitive operations in FFI-boundary code without speculation barriers

#### OAuth / OIDC & Token-Based Auth Attacks (CWE-287, CWE-346)

- JWT `alg:none` / algorithm substitution — `alg` header not validated against server-side expected algorithm list
- JWT `kid` injection — path traversal or SQL injection via the `kid` header field
- JWT `jku` / `x5u` injection — SSRF via header-specified key URL (server fetches attacker-controlled URL)
- Missing JWT expiry (`exp`) validation — check `insecure` feature gate does not disable it in production builds
- OAuth redirect URI manipulation — wildcard or open redirector patterns in callback validation
- PKCE bypass — if PKCE flow is used, verify `code_verifier` is actually validated server-side
- mTLS certificate validation bypass — missing hostname verification or incomplete CA chain validation

#### HTTP-Level & Web Security (CWE-352, CWE-1021, CWE-601)

- **CSRF**: missing `SameSite` cookie attribute, absent CSRF tokens on state-changing endpoints
- **Clickjacking**: missing `X-Frame-Options` or `frame-ancestors` CSP directive
- **Open redirect**: unvalidated `return_url`, `redirect`, `next` parameters in auth flows
- **HTTP parameter pollution**: duplicate parameter handling in Actix-web query/form parsing
- **Rate limiting**: no throttling on authentication endpoints, no per-IP or per-user limits
- **Security response headers**: missing `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- **CORS misconfiguration**: wildcard `Access-Control-Allow-Origin` combined with `Access-Control-Allow-Credentials: true`

#### Supply Chain & Dependency Integrity (CWE-1104, CWE-829)

- Dependencies with known CVEs — extend current `Cargo.toml` audit with `cargo deny check advisories`
- Dependency confusion / typosquatting — private crate names (e.g., `cosmian_*`) potentially claimable on crates.io
- Unpinned / wildcard version ranges (`*`, `>=`) that could admit malicious patch releases
- Git submodule integrity — verify `test_data` submodule points to the expected Cosmian repo and branch
- Lockfile tampering — `Cargo.lock` and `ui/pnpm-lock.yaml` integrity (unexpected changes without corresponding `Cargo.toml` / `package.json` changes)

#### Security Logging, Monitoring & Forensics (CWE-778, CWE-532)

- **Missing audit events**: failed authentication, key destruction (`Destroy`), privilege grants/revokes, key export — all must be logged
- **Insufficient log detail**: security events missing principal identity, source IP, object UID, or operation result
- **Sensitive data in logs**: key material, plaintext, tokens, or passwords in `debug!` / `trace!` / `info!` calls
- **Log injection**: user-controlled content passed to log macros without sanitization (newline injection to forge log entries)
- **No audit trail for irrecoverable operations**: `Destroy` operations are irrecoverable — must produce a durable audit log entry

#### Business Logic & KMIP-Specific (CWE-840, CWE-863)

- **Key lifecycle state machine bypass**: can `Destroy` be called on an `Active` key without first calling `Revoke`/`Deactivate`?
- **Wrap/Unwrap dual authorization**: both the wrapping key UID and the wrapped key UID must be access-checked independently — missing either is a privilege escalation
- **Attribute manipulation without ownership**: can a non-owner set `Activation Date`, `Deactivation Date`, `Sensitive`, or `Extractable` attributes?
- **Non-exportable key export**: keys with the `Non-Exportable` attribute must be blocked in `Export` / `Get` operations
- **`Locate` information disclosure**: `Locate` returning objects owned by other principals (even metadata without key material is information leakage)
- **Re-registration attacks**: can a `Register` / `Import` overwrite an existing object UID owned by a different user?

### Step 5 — Cross-File Data Flow Analysis

Trace user-controlled input from entry points (HTTP params, KMIP request fields, TTLV-deserialized bytes) to sinks (DB queries, exec calls, key material output, file writes).

Check for vulnerabilities that only appear when examining multiple files together:

- Insecure trust boundaries between Actix middleware layers
- Auth middleware applied at scope level but bypassed via direct handler registration
- KMIP operation implementations that call sub-operations without re-checking access

### Step 6 — Self-Verification Pass

For each finding:

1. Re-read the relevant code with fresh eyes
2. Ask: "Is this actually exploitable, or is there sanitization I missed?"
3. Check if a framework or middleware already handles this upstream
4. Downgrade or discard findings that aren't genuine vulnerabilities
5. Assign final severity: 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🔵 LOW / ⚪ INFO

### Step 7 — Generate Security Report

Output the report in this format:

```markdown
## Security Review: [scope]

### Summary
| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | N |
| 🟠 HIGH     | N |
| 🟡 MEDIUM   | N |
| 🔵 LOW      | N |
| ⚪ INFO      | N |

### Findings

#### [SEVERITY] [Category]: [Title]
- **File**: `path/to/file.rs:line`
- **Vulnerable code**: `<snippet>`
- **Risk**: What can an attacker do with this?
- **Confidence**: High / Medium / Low
- **Fix**: See patch below

### Dependency Audit
[CVEs or clean]

### Secrets Scan
[Findings or clean]

### KMIP Authorization Audit
[Missing access checks or clean]

### FIPS Gating Audit
[Inconsistent gating or clean]
```

### Step 8 — Propose Patches

For every 🔴 CRITICAL and 🟠 HIGH finding, generate a concrete patch:

- Show the vulnerable code (before)
- Show the fixed code (after)
- Explain what changed and why
- Preserve code style and variable names

> State explicitly: "Review each patch before applying. Nothing has been changed yet."

### Step 9 — Update SECURITY.md for confirmed fixed vulnerabilities

For every 🔴 CRITICAL and 🟠 HIGH finding where the fix is already present in the codebase
(i.e., the vulnerability existed before and is now resolved), add a new entry to
`SECURITY.md` under the current year using this format:

```markdown
#### COSMIAN-<YYYY>-<NNN> — <Short title matching the finding title>

| Field      | Value |
| ---------- | ----- |
| Severity   | <Critical / High / Moderate / Low> |
| Published  | <DD Month YYYY> |
| Affected   | from <first affected version> before <fix version> |
| Fixed in   | <version or "next release"> |
| Found by   | <source, e.g. "Copilot security-review"> |
| References | <PR or issue link if available, else —> |

**Summary:** <Two-to-four sentences: what the vulnerability was, how it could be triggered.>

**Impact:** <What an attacker could do.>

**Mitigation:** <What operators must do: upgrade, config change, workaround.>
```

Numbering: read the highest existing `COSMIAN-<YYYY>-NNN` in `SECURITY.md` for the current
year and increment by 1. If no entry exists for the current year, start at `001`.

Also add the entry to the table of contents and the summary table at the bottom of `SECURITY.md`.

If the finding is **not yet fixed** (i.e., it is a new finding requiring a patch), do **not**
add it to `SECURITY.md` yet — it will be added after the fix is merged and verified.

### Architectural findings — when to recommend `/threat-model`

If any finding involves a **trust boundary change** — a new authentication method,
a new unauthenticated endpoint, a new outbound call, a new inter-service trust,
or a new HSM/cloud integration — append this note to the report:

> ⚠️ **Architectural review recommended**: this finding affects a trust boundary.
> Run `/threat-model` (incremental mode) to update the STRIDE-A threat inventory
> before merging. `/security-review` covers tactical code vulnerabilities;
> `/threat-model` covers system-level threats that may not be visible at the code level.

## Severity Guide

| Severity | Meaning | Example |
|----------|---------|---------|
| 🔴 CRITICAL | Immediate exploitation risk, data breach likely | Key material returned without auth check, RCE |
| 🟠 HIGH | Serious vulnerability, exploit path exists | BOLA/IDOR on KMIP objects, hardcoded secrets |
| 🟡 MEDIUM | Exploitable with conditions or chaining | Missing rate limit, SSRF with partial control |
| 🔵 LOW | Best practice violation, low direct risk | Verbose errors, missing security header |
| ⚪ INFO | Observation worth noting, not a vulnerability | `insecure` feature left enabled in a config file |

## Output rules

- **Always** produce a findings summary table first
- **Never** auto-apply any patch — present for human review only
- **Always** include confidence rating (High / Medium / Low) per finding
- **Group findings** by category, not by file
- **Be specific** — include file path, line number, and exact vulnerable snippet
- If the codebase is clean, say so clearly with what was scanned
