# Cosmian KMS — OWASP Security Audit Plan

**Document type**: Security Audit Plan & Report Template
**Standard**: OWASP Top 10 (2021) + OWASP ASVS v4.0 (selective)
**Repository**: `Cosmian/kms` — branch `develop`
**Workspace root**: `crate/` (Rust workspace) + `ui/` (React/TypeScript)
**Audit date**: ___________
**Auditor(s)**: ___________
**Status**: ☐ In Progress  ☐ Complete

---

## Table of Contents

1. [Tool Installation](#1-tool-installation)
2. [A01 – Broken Access Control](#2-a01--broken-access-control)
3. [A02 – Cryptographic Failures](#3-a02--cryptographic-failures)
4. [A03 – Injection](#4-a03--injection)
5. [A04 – Insecure Design](#5-a04--insecure-design)
6. [A05 – Security Misconfiguration](#6-a05--security-misconfiguration)
7. [A06 – Vulnerable and Outdated Components](#7-a06--vulnerable-and-outdated-components)
8. [A07 – Identification and Authentication Failures](#8-a07--identification-and-authentication-failures)
9. [A08 – Software and Data Integrity Failures](#9-a08--software-and-data-integrity-failures)
10. [A09 – Security Logging and Monitoring Failures](#10-a09--security-logging-and-monitoring-failures)
11. [A10 – Server-Side Request Forgery (SSRF)](#11-a10--server-side-request-forgery-ssrf)
12. [EXT-0 – KMS Own Authorization System](#12-ext-0--kms-own-authorization-system)
13. [EXT-1 – Cryptographic Key Lifecycle & Zeroization](#13-ext-1--cryptographic-key-lifecycle--zeroization)
14. [EXT-2 – Denial of Service / Resource Exhaustion](#14-ext-2--denial-of-service--resource-exhaustion)
15. [Remediation Priority Matrix](#15-remediation-priority-matrix)
16. [Report Sign-off](#16-report-sign-off)

---

## 1. Tool Installation

Install every tool before starting the audit. All commands assume the workspace root.

### 1.1 Rust security toolchain

```bash
# Audit Rust dependencies for known CVEs (RustSec Advisory DB)
cargo install cargo-audit

# Policy-based dependency checking (licenses, bans, advisories)
# cargo-deny is already configured — deny.toml exists at workspace root
cargo install cargo-deny

# Count and locate `unsafe` blocks across the workspace
cargo install cargo-geiger

# Find outdated dependencies
cargo install cargo-outdated

# Verify tool versions
cargo audit --version
cargo deny --version
cargo geiger --version
cargo outdated --version
```

### 1.2 Secrets scanning

```bash
# Scan git history for accidentally committed secrets
cargo install gitleaks 2>/dev/null || pip install gitleaks || \
  (curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz | tar xz && sudo mv gitleaks /usr/local/bin/)

# Alternative: trufflehog
pip install truffleHog3 || pip3 install truffleHog3
```

### 1.3 SAST — Semgrep

```bash
# Install semgrep with Rust rules
pip install semgrep || pip3 install semgrep

# Pull the official Rust security ruleset (requires internet)
semgrep --config p/rust --dry-run --quiet 2>/dev/null || true
# Also pull OWASP ruleset
semgrep --config p/owasp-top-ten --dry-run --quiet 2>/dev/null || true
```

### 1.4 Verify installation

```bash
echo "=== Tool readiness check ===" && \
  cargo audit --version && \
  cargo deny --version && \
  cargo geiger --version && \
  cargo outdated --version && \
  semgrep --version && \
  (gitleaks version 2>/dev/null || trufflehog3 --version 2>/dev/null || echo "secrets scanner: check manually")
```

---

## 2. A01 – Broken Access Control

> **OWASP description**: Restrictions on what authenticated users are allowed to do are
> not properly enforced. Attackers can exploit these flaws to access unauthorized
> functionality and/or data.

### 2.1 Scope

| Area | Key files |
|------|-----------|
| Auth middleware stack | `crate/server/src/middlewares/ensure_auth.rs` |
| KMIP route handler | `crate/server/src/routes/kmip.rs` |
| Access grant/revoke | `crate/server/src/routes/access.rs` |
| Unauthenticated endpoints | `crate/server/src/routes/health.rs`, `root_redirect.rs` |
| Enterprise route auth | `crate/server/src/routes/aws_xks/`, `azure_ekm/`, `google_cse/`, `ms_dke/` |

### 2.2 Investigation Steps

```bash
# Step 1 — Enumerate all HTTP routes; look for any route registered WITHOUT
# going through the standard auth middleware chain
grep -rn "web::resource\|web::route\|web::scope\|#\[get\]\|#\[post\]\|#\[put\]\|#\[delete\]" \
  crate/server/src/routes/ --include="*.rs"

# Step 2 — Check how the server assembles its middleware chain
# (order matters: auth must wrap ALL routes except explicit public ones)
grep -n "App::new\|wrap\|configure\|service" crate/server/src/start_kms_server.rs

# Step 3 — Confirm which endpoints bypass authentication
# (expected public: /health, /, /version, /server-info)
grep -rn "EnsureAuth\|JwtMiddleware\|ApiTokenMiddleware\|TlsAuthMiddleware" \
  crate/server/src/ --include="*.rs"

# Step 4 — Look for any condition that skips the auth check entirely
grep -rn "skip\|bypass\|no_auth\|insecure\|#\[cfg(feature.*insecure" \
  crate/server/src/middlewares/ --include="*.rs"

# Step 5 — Horizontally: can a user access another user's objects without explicit grant?
# Inspect retrieve_object_for_operation — trace the owner check
grep -n "owner\|user_has_permission\|is_object_owned_by" \
  crate/server/src/core/retrieve_object_utils.rs

# Step 6 — Semgrep rule: forbidden path traversal patterns in file-serving routes
semgrep --config p/owasp-top-ten \
  crate/server/src/routes/ --lang rust 2>/dev/null | grep -i "access\|path\|traversal" || true
```

### 2.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 3. A02 – Cryptographic Failures

> **OWASP description**: Failures related to cryptography that often lead to exposure of
> sensitive data. Focus: data at rest, data in transit, key management, algorithm choices.

### 3.1 Scope

| Area | Key files |
|------|-----------|
| Crypto primitives | `crate/crypto/src/` (all subdirectories) |
| Key export enforcement | `crate/server/src/core/operations/export_get.rs` |
| Key wrapping | `crate/server/src/core/wrapping/wrap.rs`, `unwrap.rs` |
| Key storage format | `crate/kmip/src/` — `EncryptedKeyBlock`, `KeyMaterial` types |
| OpenSSL build | `crate/crypto/build.rs` |
| TLS config | `crate/server/src/config/command_line/tls_config.rs` |

### 3.2 Investigation Steps

```bash
# Step 1 — Search for hardcoded keys, IVs, or seeds
grep -rn "0x00\{16\}\|\\[0u8; 16\]\|\\[0u8; 32\]\|nonce.*=.*\[0\|iv.*=.*\[0" \
  crate/crypto/src/ --include="*.rs"

# Step 2 — Look for weak or deprecated algorithms (ECB, DES, RC4, MD5, SHA1)
grep -rni "ecb\|des\b\|rc4\|md5\|sha1\b\|sha-1" crate/ --include="*.rs"

# Step 3 — Verify sensitive=true exports are blocked unless wrapped
grep -n "sensitive\|key_wrapping_specification\|Sensitive" \
  crate/server/src/core/operations/export_get.rs

# Step 4 — Check that non-FIPS algorithms are gated behind the feature flag
grep -rn "non.fips\|legacy\|Covercrypt\|AES.XTS\|chacha\|xchacha" \
  crate/crypto/src/ --include="*.rs" | head -30

# Step 5 — Inspect memory cache for unwrapped key material
grep -n "cache\|HashMap\|DashMap\|insert\|zeroize\|Zeroizing" \
  crate/server/src/core/wrapping/wrap.rs

# Step 6 — Verify OpenSSL download hash verification (supply chain)
grep -n "sha256\|checksum\|hash\|verify" crate/crypto/build.rs

# Step 7 — Semgrep crypto checks
semgrep --config p/rust crate/crypto/src/ --lang rust 2>/dev/null | \
  grep -i "crypto\|cipher\|hash\|random\|seed" || true
```

### 3.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 4. A03 – Injection

> **OWASP description**: Injection flaws occur when untrusted data is sent to an interpreter
> as part of a command or query. SQL, TTLV, command, and LDAP injections are in scope.

### 4.1 Scope

| Area | Key files |
|------|-----------|
| Dynamic SQL builder | `crate/server_database/src/stores/sql/locate_query.rs` |
| All SQL backends | `crate/server_database/src/stores/sql/sqlite.rs`, `pgsql.rs`, `mysql.rs` |
| TTLV binary parser | `crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs` |
| TTLV XML parser | `crate/kmip/src/ttlv/xml/parser.rs`, `deserializer.rs` |
| JSON entry point | `crate/server/src/routes/kmip.rs` — `from_ttlv()` call |
| CLI file path inputs | `crate/clients/clap/src/actions/` |

### 4.2 Investigation Steps

```bash
# Step 1 — Find any raw SQL string building (format!, concat!, +)
# Safe pattern: bind_values filled, sql only has ? or $N placeholders
grep -rn "format!.*SELECT\|format!.*INSERT\|format!.*UPDATE\|format!.*DELETE\|\
\"SELECT.*{}\|\"INSERT.*{}\|\"UPDATE.*{}\|\"DELETE.*{}" \
  crate/server_database/src/ --include="*.rs"

# Step 2 — Verify parameterized query usage (should see bind or execute with params)
grep -n "bind\|execute\|query_as\|fetch" \
  crate/server_database/src/stores/sql/locate_query.rs | head -30

# Step 3 — TTLV parser: look for missing length checks before allocation
grep -n "len\|size\|capacity\|Vec::with_capacity\|allocate\|read_exact" \
  crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs

# Step 4 — Check for recursion depth guard in TTLV struct parser
grep -rn "depth\|recursion\|stack\|recursive\|Box::new\|fn from_ttlv" \
  crate/kmip/src/ttlv/ --include="*.rs"

# Step 5 — CLI: look for shell command execution with user-supplied values
grep -rn "Command::new\|std::process\|exec\|popen\|shell" \
  crate/clients/ --include="*.rs"

# Step 6 — Tag injection: tags are stored as strings — check they go through bind
grep -n "tag\|Tag\|object_group" \
  crate/server_database/src/stores/sql/locate_query.rs | head -20

# Step 7 — Semgrep injection patterns
semgrep --config p/owasp-top-ten crate/ --lang rust 2>/dev/null | \
  grep -i "inject\|sql\|command\|exec" || true
```

### 4.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 5. A04 – Insecure Design

> **OWASP description**: Missing or ineffective control design. Unlike misconfiguration
> this is a structural flaw, not a configuration gap.

### 5.1 Scope

| Area | Key files |
|------|-----------|
| KMIP operation dispatcher | `crate/server/src/core/operations/dispatch.rs` |
| Actix-web app builder | `crate/server/src/start_kms_server.rs` |
| Server config | `crate/server/src/config/` |
| KMIP lifecycle state machine | `crate/kmip/src/` — object state types |
| Rate limiting | `crate/server/src/middlewares/` |

### 5.2 Investigation Steps

```bash
# Step 1 — Max request body size: Actix default is 256 KB; look for override
grep -n "LimitPayloadSize\|max_payload_size\|payload_size\|content_length" \
  crate/server/src/start_kms_server.rs crate/server/src/routes/kmip.rs

# Step 2 — Rate limiting middleware
grep -rn "RateLimiter\|rate_limit\|throttle\|governor\|leaky_bucket" \
  crate/server/src/ --include="*.rs"

# Step 3 — KMIP state machine: transitions must follow the spec
# (PreActive → Active → Deactivated → Destroyed, no skipping)
grep -rn "Deactivated\|PreActive\|Compromised\|Destroyed\|state.*transition\|update_state" \
  crate/server/src/core/operations/ --include="*.rs"

# Step 4 — Bulk operations: can a single request affect thousands of objects?
grep -rn "Locate\|for.*objects\|batch\|BulkRequest\|RequestBatchItem" \
  crate/server/src/core/operations/ --include="*.rs" | head -20

# Step 5 — Pagination: are Locate results bounded?
grep -rn "limit\|offset\|pagination\|page_size\|LIMIT\|OFFSET" \
  crate/server_database/src/ --include="*.rs"

# Step 6 — Secret data type: are there constraints on what can be stored?
grep -rn "SecretData\|Opaque\|OpaqueData\|CertificateRequest" \
  crate/server/src/core/operations/ --include="*.rs"
```

### 5.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 6. A05 – Security Misconfiguration

> **OWASP description**: Security misconfiguration is the most commonly seen issue, often
> resulting from insecure default configurations, incomplete configurations, open cloud
> storage, verbose error messages, or missing security hardening.

### 6.1 Scope

| Area | Key files |
|------|-----------|
| All config CLI flags | `crate/server/src/config/command_line/` (all files) |
| UI auth & CORS | `crate/server/src/routes/ui_auth.rs` |
| OpenSSL provider init | `crate/server/src/openssl_providers.rs` |
| Error response format | `crate/server/src/routes/kmip.rs` — error handling |
| Default values | `crate/server/src/config/command_line/clap_config.rs` |

### 6.2 Investigation Steps

```bash
# Step 1 — Find default values for security-sensitive flags
grep -n "default_value\|default.*=\|fn default()" \
  crate/server/src/config/command_line/clap_config.rs | head -40

# Step 2 — TLS minimum version and cipher suite defaults
grep -rn "TLSv1\|tls_cipher\|cipher_suite\|TlsVersion\|min_protocol" \
  crate/server/src/config/ --include="*.rs"
grep -n "tls_p12\|tls_cert\|tls_key\|tls_chain\|clients_ca" \
  crate/server/src/config/command_line/tls_config.rs

# Step 3 — CORS configuration: look for wildcard origins
grep -rn "Cors\|allow_origin\|AllowedOrigin\|allow_any_origin\|\".\"" \
  crate/server/src/ --include="*.rs"

# Step 4 — Error messages: do they leak stack traces or internal state?
grep -rn "backtrace\|debug_info\|internal_err\|format.*err\|KmsError\|error.*details" \
  crate/server/src/routes/ --include="*.rs" | head -20

# Step 5 — Feature flags that weaken security
grep -rn "insecure\|debug\|allow_self_signed\|skip.*expir\|no.verify" \
  crate/server/src/ --include="*.rs"

# Step 6 — Env var names for secrets (check they are documented + not logged)
grep -rn "KMS_.*PASSWORD\|KMS_.*SECRET\|KMS_.*KEY\|KMS_.*TOKEN" \
  crate/server/src/ --include="*.rs"

# Step 7 — Look for hardcoded dev credentials
semgrep --config p/secrets crate/ --lang rust 2>/dev/null | head -30 || true
gitleaks detect --source . --no-git 2>/dev/null | head -30 || true
```

### 6.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 7. A06 – Vulnerable and Outdated Components

> **OWASP description**: Components such as libraries, frameworks, and other software
> modules run with the same privileges as the application. If a vulnerable component is
> exploited, it can facilitate serious data loss or server takeover.

### 7.1 Scope

| Area | Files |
|------|-------|
| Workspace dependencies | `Cargo.toml` (root) + all `crate/*/Cargo.toml` |
| Deny policy | `deny.toml` |
| OpenSSL build + hash | `crate/crypto/build.rs` |
| UI dependencies | `ui/package.json`, `ui/pnpm-lock.yaml` |
| Git history for removed vulns | `.git/` |

### 7.2 Investigation Steps

```bash
# Step 1 — Scan Rust deps for known CVEs (RustSec Advisory DB)
cargo audit

# Step 2 — Policy-based check (licenses, banned crates, advisories)
cargo deny check

# Step 3 — List outdated crates (compare to latest on crates.io)
cargo outdated --workspace

# Step 4 — Count unsafe usage per crate (baseline for risk triage)
cargo geiger --workspace 2>/dev/null | tail -50

# Step 5 — Verify OpenSSL source is pinned and hash-checked
grep -n "openssl.*version\|OPENSSL_VERSION\|sha256\|expected_hash\|verify" \
  crate/crypto/build.rs | head -20

# Step 6 — UI dependencies
cd ui && pnpm audit 2>/dev/null || npm audit 2>/dev/null; cd ..

# Step 7 — Scan git history for credentials or vulnerable versions accidentally committed
gitleaks detect --source . 2>/dev/null | head -30 || \
  trufflehog3 --no-entropy . 2>/dev/null | head -30 || \
  echo "Run secrets scanner manually"

# Step 8 — Check for git-sourced Rust deps (unaudited source)
grep -rn "git = \|branch = \|rev = " Cargo.toml crate/*/Cargo.toml
```

### 7.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

cargo audit output summary:
-

cargo deny check output summary:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 8. A07 – Identification and Authentication Failures

> **OWASP description**: Incorrectly implemented authentication and session management
> functions allow attackers to compromise passwords, keys, or session tokens, or to
> exploit other implementation flaws to assume other users' identities.

### 8.1 Scope

| Area | Key files |
|------|-----------|
| JWT middleware | `crate/server/src/middlewares/jwt/jwt_middleware.rs`, `jwt_token_auth.rs`, `jwt_config.rs` |
| JWKS manager | `crate/server/src/middlewares/jwt/jwks.rs` |
| API token auth | `crate/server/src/middlewares/api_token/api_token_auth.rs`, `api_token_middleware.rs` |
| TLS client cert auth | `crate/server/src/middlewares/tls_auth.rs` |
| AWS SigV4 auth | `crate/server/src/routes/aws_xks/sigv4_middleware.rs` |
| Auth fallback | `crate/server/src/middlewares/ensure_auth.rs` |
| `insecure` feature | Everywhere gated by `#[cfg(feature = "insecure")]` |

### 8.2 Investigation Steps

```bash
# Step 1 — JWT algorithm restriction: RS256/ES256 only; reject HS256, "none"
grep -rn "Algorithm\|alg\|Validation\|decode\|jsonwebtoken" \
  crate/server/src/middlewares/jwt/ --include="*.rs"

# Step 2 — Token expiration check: is it enforced? (insecure feature skips it)
grep -rn "exp\|expir\|validate_exp\|insecure" \
  crate/server/src/middlewares/jwt/ --include="*.rs"

# Step 3 — JWKS fetch: must be HTTPS; look for plain HTTP fallback
grep -n "http://\|reqwest\|fetch_jwks\|jwks_uri\|url" \
  crate/server/src/middlewares/jwt/jwks.rs

# Step 4 — API token comparison: must be constant-time to prevent timing attacks
grep -n "==\|compare\|ConstantTimeEq\|constant_time\|subtle" \
  crate/server/src/middlewares/api_token/api_token_auth.rs

# Step 5 — TLS cert auth: CN alone is not unique; check if full DN or SAN used
grep -n "CommonName\|CN\|SubjectAltName\|SAN\|subject\|peer_cert" \
  crate/server/src/middlewares/tls_auth.rs

# Step 6 — Session fixation in UI auth (Actix session)
grep -rn "actix.session\|Session\|cookie\|HttpOnly\|Secure\|SameSite" \
  crate/server/src/routes/ui_auth.rs crate/server/src/middlewares/ --include="*.rs"

# Step 7 — Brute-force protection on API token endpoint
grep -rn "rate_limit\|lockout\|backoff\|attempt" \
  crate/server/src/middlewares/ --include="*.rs"

# Step 8 — Semgrep auth patterns
semgrep --config p/owasp-top-ten crate/server/src/middlewares/ --lang rust 2>/dev/null || true
```

### 8.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 9. A08 – Software and Data Integrity Failures

> **OWASP description**: Software and data integrity failures relate to code and
> infrastructure that does not protect against integrity violations. Includes insecure
> deserialization, CI/CD pipeline attacks, and unsigned updates.

### 9.1 Scope

| Area | Key files |
|------|-----------|
| OpenSSL download + verify | `crate/crypto/build.rs` |
| Imported object validation | `crate/server/src/core/operations/import.rs` |
| KMIP deserializer | `crate/kmip/src/ttlv/` |
| Cargo lock and git deps | `Cargo.lock`, `Cargo.toml` |
| CI pipeline scripts | `.github/workflows/`, `.github/scripts/` |

### 9.2 Investigation Steps

```bash
# Step 1 — OpenSSL build: verify hash check is present and non-bypassable
grep -A5 -B5 "sha256\|checksum\|expected\|download" crate/crypto/build.rs

# Step 2 — Imported keys: are cryptographic properties validated on import?
# (e.g., RSA modulus size, EC curve OID, key material length)
grep -n "validate\|check\|verify\|length\|CryptographicLength\|algorithm" \
  crate/server/src/core/operations/import.rs | head -30

# Step 3 — KMIP deserialization: does serde_json reject unknown fields?
grep -rn "deny_unknown_fields\|flatten\|tag\|untagged\|#\[serde" \
  crate/kmip/src/ --include="*.rs" | head -20

# Step 4 — Git-sourced or path-sourced deps (integrity not guaranteed by crates.io)
grep -rn "git =\|path =\|branch =\|rev =" Cargo.toml crate/*/Cargo.toml

# Step 5 — CI scripts: look for unauthenticated downloads or pip/curl | sh patterns
grep -rn "curl.*sh\|wget.*sh\|pip install\|npm install" \
  .github/scripts/ .github/workflows/ 2>/dev/null | grep -v "#" | head -20

# Step 6 — Nix vendor hash files (CI supply chain)
ls -la nix/expected-hashes/
cat nix/expected-hashes/*.sha256 2>/dev/null | head -20
```

### 9.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 10. A09 – Security Logging and Monitoring Failures

> **OWASP description**: Insufficient logging and monitoring, coupled with missing
> or ineffective integration with incident response, allows attackers to further attack
> systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy
> data.

### 10.1 Scope

| Area | Key files |
|------|-----------|
| KMIP request tracing | `crate/server/src/routes/kmip.rs`, `routes/access.rs` |
| Config secret logging | `crate/server/src/config/command_line/` (all) |
| Auth failure logging | `crate/server/src/middlewares/` |
| Privileged operation audit | `crate/server/src/core/operations/export_get.rs`, `destroy.rs`, `revoke.rs` |
| Error response content | `crate/server/src/routes/` |

### 10.2 Investigation Steps

```bash
# Step 1 — Secrets in logs: DB URLs, TLS passwords, API tokens, JWT secrets
grep -rn "tracing::\|log::\|info!\|warn!\|error!\|debug!\|trace!" \
  crate/server/src/config/ --include="*.rs" | \
  grep -i "password\|secret\|token\|key\|credential\|url\|connection"

# Step 2 — Same check in middleware (auth failure messages must NOT include token value)
grep -rn "info!\|warn!\|error!\|debug!" \
  crate/server/src/middlewares/ --include="*.rs" | \
  grep -i "token\|bearer\|api.key\|password\|secret"

# Step 3 — Privileged operations: are export, destroy, revoke logged with user identity?
grep -n "tracing\|info!\|warn!\|error!" \
  crate/server/src/core/operations/export_get.rs \
  crate/server/src/core/operations/destroy.rs \
  crate/server/src/core/operations/revoke.rs 2>/dev/null | head -40

# Step 4 — Failed auth: are 401/403 events logged?
grep -rn "401\|403\|Unauthorized\|Forbidden\|warn!\|error!" \
  crate/server/src/middlewares/ --include="*.rs" | grep -i "auth\|denied\|failed"

# Step 5 — Log injection: user-controlled strings in tracing macros without sanitization
# (a user could inject newlines or log-forging sequences)
grep -rn 'info!.*user\|debug!.*uid\|trace!.*tag\|warn!.*{.*}' \
  crate/server/src/core/operations/ --include="*.rs" | head -20

# Step 6 — Check that OTEL / tracing spans cover ALL KMIP operations (not just errors)
grep -rn "span!\|instrument\|#\[tracing::instrument\]" \
  crate/server/src/core/operations/ --include="*.rs" | wc -l
```

### 10.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 11. A10 – Server-Side Request Forgery (SSRF)

> **OWASP description**: SSRF flaws occur whenever a web application fetches a remote
> resource without validating the user-supplied URL. This allows attackers to coerce the
> application to send a crafted request to an unexpected destination.

### 11.1 Scope

| Area | Key files |
|------|-----------|
| JWKS URL fetch | `crate/server/src/middlewares/jwt/jwks.rs` |
| Google CSE callbacks | `crate/server/src/routes/google_cse/` |
| AWS XKS outbound | `crate/server/src/routes/aws_xks/` |
| Azure EKM connections | `crate/server/src/routes/azure_ekm/` |
| HTTP client construction | `crate/clients/client/src/` |

### 11.2 Investigation Steps

```bash
# Step 1 — All outbound HTTP calls: find reqwest/hyper/ureq client creation
grep -rn "reqwest::Client\|reqwest::get\|Client::new\|ClientBuilder" \
  crate/ --include="*.rs" | grep -v "test\|#\[cfg(test"

# Step 2 — JWKS URL: is it validated/allowlisted or taken directly from config?
grep -n "jwks_uri\|jwks_url\|fetch\|get\|url\|https\|http" \
  crate/server/src/middlewares/jwt/jwks.rs

# Step 3 — Check if any URL is constructed from user-supplied KMIP fields
# (e.g., CertificateRequestType, Extensions with URLs)
grep -rn "url\|http\|endpoint\|callback\|webhook" \
  crate/server/src/core/operations/ --include="*.rs" | grep -i "user\|request\|input"

# Step 4 — Google CSE: look for user-controlled redirect or callback URLs
grep -rn "redirect\|callback\|url\|uri" \
  crate/server/src/routes/google_cse/ --include="*.rs"

# Step 5 — HTTP client: are redirects followed? (can enable SSRF via 301)
grep -rn "redirect\|follow_redirect\|redirect_policy\|max_redirect" \
  crate/ --include="*.rs"

# Step 6 — Allowlist check: are outbound URLs restricted to expected domains?
grep -rn "allowlist\|whitelist\|allowed_url\|valid_host\|parse.*url" \
  crate/ --include="*.rs" | grep -v test | head -15
```

### 11.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 12. EXT-0 – KMS Own Authorization System

> **OWASP ASVS V4 (Access Control)** — The KMS implements a custom, multi-layer
> authorization model on top of KMIP. This section audits the entire call chain from
> HTTP request to permission decision and covers privilege escalation, bypass mechanisms,
> and delegation controls.

### 12.1 Architecture Summary

The full authorization call chain for every KMIP operation:

```text
HTTP request
  └─ TlsAuthMiddleware | JwtMiddleware | ApiTokenMiddleware
       └─ EnsureAuthMiddleware (fallback: default_username)
            └─ routes/kmip.rs → kms.get_user(&req)
                 │  ↑ force_default_username=true → ALL identities discarded
                 └─ dispatch(kms, ttlv, user) → operation handler
                      └─ retrieve_object_for_operation(uid, op, kms, user)
                           └─ user_has_permission(user, owm, op, kms)
                                ├─ SHORTCUT: user == owm.owner() → true (owner bypass)
                                ├─ IMPLICIT: ops.contains(Get) → all ops allowed
                                └─ DB: list_user_operations_on_object(uid, user, false)
                                        ├─ SQL: SELECT … WHERE object_id=uid AND user_id=user
                                        └─     UNION … WHERE object_id="*" AND user_id=user
```

### 12.2 Scope

| Area | Key files |
|------|-----------|
| Core permission gate | `crate/server/src/core/retrieve_object_utils.rs` |
| KMS identity + delegation | `crate/server/src/core/kms/permissions.rs` |
| Permission data types | `crate/access/src/access.rs` |
| SQL permission queries | `crate/server_database/src/stores/sql/` — permissions table |
| Redis permission store | `crate/server_database/src/stores/redis/permissions.rs` |
| Privilege config | `crate/server/src/config/command_line/clap_config.rs` — `privileged_users`, `force_default_username` |
| Create authorization | `crate/server/src/core/operations/create.rs`, `import.rs`, `register.rs` |
| Delegation controls | `crate/server/src/core/kms/permissions.rs` — `grant_access()`, `revoke_access()` |

### 12.3 Investigation Steps

```bash
# Step 1 — Map every bypass mechanism
grep -n "force_default_username\|privileged_users\|default_username" \
  crate/server/src/config/command_line/clap_config.rs \
  crate/server/src/core/kms/permissions.rs

# Step 2 — Owner bypass: trace user_has_permission() — verify owner check is safe
grep -n "owner\|is_object_owned_by\|user.*==.*owner\|owner.*==" \
  crate/server/src/core/retrieve_object_utils.rs \
  crate/server/src/core/kms/permissions.rs

# Step 3 — "Get implies everything" — find the implicit grant logic
grep -n "KmipOperation::Get\|contains.*Get\|Get.*implies\|get.*all" \
  crate/server/src/core/retrieve_object_utils.rs

# Step 4 — Wildcard "*" permission for Create: verify only privileged_users can grant it
grep -n '"\\*"\|wildcard\|Create\|privileged\|grant_access\|is_create' \
  crate/server/src/core/kms/permissions.rs \
  crate/server/src/core/operations/create.rs \
  crate/server/src/core/operations/import.rs

# Step 5 — Non-owner grant: verify is_object_owned_by() enforced before grant_access()
grep -n "is_object_owned_by\|owned_by\|owner.*check\|grant_access" \
  crate/server/src/core/kms/permissions.rs | head -20

# Step 6 — Self-grant: verify a user cannot grant themselves more permissions
grep -n "user_id.*owner\|self.*grant\|grant.*self\|access.user_id.*==.*owner" \
  crate/server/src/core/kms/permissions.rs

# Step 7 — KMIP state filter: Destroyed/Compromised must block operations
grep -n "Destroyed\|PreActive\|Deactivated\|Compromised\|state.*check\|filter.*state" \
  crate/server/src/core/retrieve_object_utils.rs

# Step 8 — Publicly accessible endpoints without auth middleware
grep -rn "health\|version\|server.info\|configure\|service\|wrap" \
  crate/server/src/start_kms_server.rs | head -30

# Step 9 — Enterprise routes: can AWS/Azure/Google routes reach standard KMIP ops?
grep -rn "dispatch\|kms\.\|KMS\b" \
  crate/server/src/routes/aws_xks/ \
  crate/server/src/routes/azure_ekm/ \
  crate/server/src/routes/google_cse/ \
  crate/server/src/routes/ms_dke/ --include="*.rs" | head -30

# Step 10 — Redis PermTriple: check atomicity of grant + concurrent revoke
grep -n "PermTriple\|insert\|delete\|transaction\|atomic\|pipeline" \
  crate/server_database/src/stores/redis/permissions.rs | head -20

# Step 11 — EnsureAuth fallback: verify it enforces single-user mode only when
# no other auth is configured (not a blanket bypass)
cat crate/server/src/middlewares/ensure_auth.rs
```

### 12.4 Specific Risk Checklist

- [ ] `force_default_username=true` cannot be set via un-authenticated endpoint or env injection
- [ ] `privileged_users` list is logged at startup so administrators can detect unauthorized changes
- [ ] `Get` → all-operations implicit grant is documented as intentional AND is scope-limited (not cross-user)
- [ ] A non-owner cannot call `grant_access()` even if they hold `Get` permission
- [ ] A user cannot grant `Create` permission unless they are in `privileged_users`
- [ ] `/health`, `/version`, `/server-info` return no object metadata, user data, or internal state
- [ ] Enterprise routes (XKS, EKM, CSE, DKE) authenticate independently and do not bypass standard KMIP auth for unwrapping
- [ ] KMIP lifecycle transitions from Compromised/Destroyed are one-way and enforced at DB level
- [ ] Redis PermTriple updates are atomic (no TOCTOU between grant and revoke)

### 12.5 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 13. EXT-1 – Cryptographic Key Lifecycle & Zeroization

> **OWASP ASVS V6 (Stored Cryptography)** — Sensitive cryptographic material (private
> keys, AES keys, shared secrets) must be zeroized from memory as soon as they are no
> longer needed. Residual key material in heap memory enables cold-boot and process-dump
> attacks.

### 13.1 Scope

| Area | Key files |
|------|-----------|
| Key wrapping cache | `crate/server/src/core/wrapping/wrap.rs` |
| Key unwrap paths | `crate/server/src/core/wrapping/unwrap.rs` |
| PKCS#11 provider key handling | `crate/clients/pkcs11/provider/src/kms_object.rs` |
| All crypto operations | `crate/crypto/src/` |
| Zeroize usage | Workspace-wide |

### 13.2 Investigation Steps

```bash
# Step 1 — Find all uses of zeroize / Zeroizing in the codebase (baseline)
grep -rn "zeroize\|Zeroizing\|ZeroizeOnDrop\|SecretBox" crate/ --include="*.rs" | wc -l

# Step 2 — Find Vec<u8> or Box<[u8]> that likely hold key material but NOT wrapped
# in Zeroizing<> — search operations that touch raw key bytes
grep -rn "Vec<u8>\|Box<\[u8\]>\|key_bytes\|key_material\|private_key\|secret" \
  crate/server/src/core/operations/ --include="*.rs" | \
  grep -v "Zeroizing\|zeroize\|#\[derive.*Zeroize" | head -30

# Step 3 — Wrapping cache: what is evicted and is it zeroized on drop?
grep -n "cache\|remove\|evict\|drop\|DashMap\|HashMap\|clear\|Zeroizing" \
  crate/server/src/core/wrapping/wrap.rs

# Step 4 — Check that KeyMaterial and EncryptedKeyBlock implement Zeroize
grep -rn "impl Zeroize\|impl Drop\|#\[derive.*Zeroize" \
  crate/kmip/src/ --include="*.rs"

# Step 5 — Look for key bytes in error messages (could appear in logs)
grep -rn 'format!.*key\|error!.*key\|warn!.*key\|info!.*\bkey\b' \
  crate/server/src/core/operations/ --include="*.rs" | head -15

# Step 6 — PKCS#11: key material in kms_object.rs before zeroize on drop
grep -n "Zeroizing\|zeroize\|drop\|CK_BYTE\|key_value\|private" \
  crate/clients/pkcs11/provider/src/kms_object.rs | head -30

# Step 7 — Cargo geiger: identify crates with the most unsafe blocks
cargo geiger --workspace --output-format Ratio 2>/dev/null | head -30
```

### 13.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 14. EXT-2 – Denial of Service / Resource Exhaustion

> **OWASP ASVS V12 / CWE-400** — The server must bound all user-controlled resource
> consumption: request body size, TTLV nesting depth, database result set size, and
> concurrent connection count.

### 14.1 Scope

| Area | Key files |
|------|-----------|
| Actix-web payload limit | `crate/server/src/start_kms_server.rs` |
| TTLV binary parser depth | `crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs` |
| TTLV XML parser depth | `crate/kmip/src/ttlv/xml/parser.rs` |
| Locate result pagination | `crate/server_database/src/` |
| Bulk request handling | `crate/server/src/core/operations/dispatch.rs` |
| Rate limiting | `crate/server/src/middlewares/` |

### 14.2 Investigation Steps

```bash
# Step 1 — Max HTTP body size enforced by Actix-web?
grep -n "limit\|max_payload\|PayloadConfig\|max_body" \
  crate/server/src/start_kms_server.rs

# Step 2 — TTLV recursion: is there a max depth check before recursive call?
grep -n "depth\|recursion\|max_depth\|stack\|recursive\|fn parse\|fn decode\|fn from_ttlv" \
  crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs

# Step 3 — XML TTLV: libxml parser settings (entity expansion = billion laughs)
grep -n "expand_entities\|entity\|xml_parse\|XmlParser\|depth\|recursive" \
  crate/kmip/src/ttlv/xml/parser.rs

# Step 4 — Locate operation: result set bounded?
grep -n "Locate\|limit\|max_results\|LIMIT\|pagination\|fetch_all\|count" \
  crate/server/src/core/operations/locate.rs 2>/dev/null
grep -n "SELECT\|LIMIT\|offset\|page" \
  crate/server_database/src/stores/sql/locate_query.rs | head -20

# Step 5 — KMIP batch requests: unbounded RequestBatchItem count?
grep -n "RequestBatchItem\|batch_items\|iter\|for.*batch\|len()" \
  crate/server/src/core/operations/dispatch.rs | head -20

# Step 6 — Rate limiting middleware
grep -rn "RateLimiter\|Governor\|leaky\|throttle\|rate" \
  crate/server/src/middlewares/ --include="*.rs"

# Step 7 — Semgrep: allocation without bound check
semgrep --config p/rust crate/kmip/src/ttlv/ --lang rust 2>/dev/null | \
  grep -i "alloc\|capacity\|len\|size\|vec" || true
```

### 14.3 Findings Template

```text
Status: ☐ ✅ No issues  ☐ ⚠️ Review needed  ☐ ❌ Vulnerability found

Files inspected:
-

Findings:
| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
|    |           |          |             |

Recommended fix:
```

---

## 15. Remediation Priority Matrix

Fill in after completing all sections above.

| ID | Section | File:Line | Severity | CVSS (est.) | Status | Assigned to | Due |
|----|---------|-----------|----------|-------------|--------|-------------|-----|
|    |         |           | Critical |             | Open   |             |     |
|    |         |           | High     |             | Open   |             |     |
|    |         |           | Medium   |             | Open   |             |     |
|    |         |           | Low      |             | Open   |             |     |
|    |         |           | Info     |             | Open   |             |     |

### Severity definitions (aligned with CVSS 3.1)

| Severity | CVSS base score | Response SLA |
|----------|-----------------|--------------|
| Critical | 9.0 – 10.0 | Fix before next release |
| High | 7.0 – 8.9 | Fix within 1 sprint |
| Medium | 4.0 – 6.9 | Fix within 3 sprints |
| Low | 0.1 – 3.9 | Fix in backlog |
| Info | N/A | Document / accept |

---

## 16. Report Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Lead auditor | | | |
| Security reviewer | | | |
| Engineering lead | | | |

**Next audit scheduled**: ___________

**Review frequency**: Quarterly or on every major dependency update / KMIP spec change.
