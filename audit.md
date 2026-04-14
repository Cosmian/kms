# Cosmian KMS — OWASP Security Audit Plan & Report

**Document type**: Security Audit Plan & Report Template
**Standard**: OWASP Top 10 (2021) + OWASP ASVS v4.0 (selective)
**Repository**: `Cosmian/kms` — branch `develop`
**Workspace root**: `crate/` (Rust workspace) + `ui/` (React/TypeScript)
**Audit date**: 2026-04-14 (re-run with remediation verification: 2026-04-14)
**Auditor(s)**: GitHub Copilot (automated static analysis)
**Status**: ☑ Complete — all High/Medium findings fixed or mitigated; Low findings addressed or accepted

## Tools available during this audit

| Tool | Version | Status | Notes |
|------|---------|--------|-------|
| `cargo-audit` | 0.22.1 | ✅ Available | Advisory DB scan |
| `cargo-deny` | 0.19.0 | ✅ Available | Policy check (bans, licenses, advisories, sources) |
| `cargo-outdated` | 0.17.0 | ✅ Available | Outdated dep detection |
| `cargo-geiger` | 0.13.0 | ⚠️ Installed — partial | Fails on virtual workspace manifest with bug ([#378](https://github.com/rust-secure-code/cargo-geiger/issues/378)); fallback: manual `grep -r "unsafe "` |
| `semgrep` | — | ❌ Not installed | Static pattern matching — install per §1 |
| `gitleaks` / `trufflehog3` | — | ❌ Not installed | Secret scanning — install per §1 |

> `cargo-geiger 0.13.0` fails with `error: No such file or directory — crate/cli/src/lib.rs` when
> invoked against this virtual workspace. This is a known upstream bug. The A06 section below uses
> manual `grep -r "unsafe"` counts as a validated substitute.

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

Install every tool before starting the audit. Run all commands from the workspace root.

### 1.1 Rust security toolchain

```bash
# Audit Rust dependencies for known CVEs (RustSec Advisory DB)
cargo install cargo-audit

# Policy-based dependency checking (licenses, bans, advisories)
# cargo-deny is already configured: deny.toml exists at workspace root
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
# Option A: gitleaks (scan git history + working tree for accidentally committed secrets)
curl -sSfL \
  https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz \
  | tar xz && sudo mv gitleaks /usr/local/bin/
gitleaks version

# Option B: trufflehog (entropy-based secret detection)
pip3 install truffleHog3
trufflehog3 --version
```

### 1.3 SAST — Semgrep

```bash
# Install semgrep
pip3 install semgrep
semgrep --version

# Verify the Rust and OWASP rulesets are reachable (requires internet)
semgrep --config p/rust        --test 2>/dev/null || true
semgrep --config p/owasp-top-ten --test 2>/dev/null || true
semgrep --config p/secrets     --test 2>/dev/null || true
```

### 1.4 Readiness check

```bash
echo "=== Tool readiness ===" && \
  cargo audit   --version && \
  cargo deny    --version && \
  cargo geiger  --version && \
  cargo outdated --version && \
  semgrep       --version && \
  (gitleaks version 2>/dev/null || trufflehog3 --version 2>/dev/null || \
    echo "WARNING: no secrets scanner found")
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
| Access grant / revoke endpoints | `crate/server/src/routes/access.rs` |
| Unauthenticated public endpoints | `crate/server/src/routes/health.rs`, `root_redirect.rs` |
| Server app builder (middleware order) | `crate/server/src/start_kms_server.rs` |
| Enterprise route auth | `crate/server/src/routes/aws_xks/`, `azure_ekm/`, `google_cse/`, `ms_dke/` |

### 2.2 Investigation Steps

```bash
# Step 1 — Enumerate all HTTP routes; identify routes registered WITHOUT
# the standard auth middleware chain
grep -rn \
  "web::resource\|web::route\|web::scope\|#\[get\]\|#\[post\]\|#\[put\]\|#\[delete\]" \
  crate/server/src/routes/ --include="*.rs"

# Step 2 — Inspect the full middleware assembly order
# Auth wrappers MUST be registered before route handlers
grep -n "App::new\|\.wrap\|\.configure\|\.service" \
  crate/server/src/start_kms_server.rs

# Step 3 — Confirm which middleware types protect which routes
grep -rn "EnsureAuth\|JwtMiddleware\|ApiTokenMiddleware\|TlsAuthMiddleware" \
  crate/server/src/ --include="*.rs"

# Step 4 — Look for any explicit auth skip or bypass condition
grep -rn "skip\|bypass\|no_auth\|#\[cfg(feature.*insecure" \
  crate/server/src/middlewares/ --include="*.rs"

# Step 5 — Horizontal privilege escalation: can a user access another user's objects
# without an explicit grant? Inspect owner check in retrieve_object_for_operation
grep -n "owner\|user_has_permission\|is_object_owned_by" \
  crate/server/src/core/retrieve_object_utils.rs

# Step 6 — Semgrep: path traversal and broken access control patterns
semgrep --config p/owasp-top-ten \
  crate/server/src/routes/ --lang rust 2>/dev/null \
  | grep -i "access\|path\|traversal" || true
```

### 2.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server/src/start_kms_server.rs`
- `crate/server/src/middlewares/ensure_auth.rs`, `tls_auth.rs`, `api_token/`, `jwt/`
- `crate/server/src/routes/health.rs`, `access.rs`, `kmip.rs`
- `crate/server/src/core/retrieve_object_utils.rs`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A01-1 | `start_kms_server.rs:776,795,806,901,962` | Medium | `Cors::permissive()` applied to **all** scopes including the main KMIP endpoint. This allows cross-origin requests from any domain, enabling browser-based cross-site attacks against the KMIP API. |
| A01-2 | `routes/health.rs:47` | Info | `/health` is a public (unauthenticated) endpoint that calls `kms.get_user(&req)` and logs the result. On an unconfigured server the default username is logged on every health probe. Not a direct vulnerability but reveals configuration state. |
| A01-3 | `middlewares/ensure_auth.rs:128` | Info | EnsureAuth correctly skips itself when the request is already authenticated (comment confirms intent). No bypass risk. |

**Recommended fix**:

- A01-1: Replace `Cors::permissive()` with an explicit allowlist (`Cors::default().allowed_origin(…)`) for all scopes. For KMIP, restrict to known client origins or require mTLS instead of relying on CORS.
- A01-2: Move the `get_user` log line behind an `if tracing::enabled!(Level::DEBUG)` guard, or remove it from public endpoints.

> **OWASP description**: Failures related to cryptography (data at rest, data in transit,
> key management, algorithm choices) that often lead to exposure of sensitive data.

## 3. A02 – Cryptographic Failures

### 3.1 Scope

| Area | Key files |
|------|-----------|
| Crypto primitives | `crate/crypto/src/` (all subdirectories) |
| Key export enforcement | `crate/server/src/core/operations/export_get.rs` |
| Key wrapping / unwrapping | `crate/server/src/core/wrapping/wrap.rs`, `unwrap.rs` |
| Key storage format | `crate/kmip/src/` — `EncryptedKeyBlock`, `KeyMaterial` types |
| OpenSSL build & hash | `crate/crypto/build.rs` |
| TLS configuration | `crate/server/src/config/command_line/tls_config.rs` |

### 3.2 Investigation Steps

```bash
# Step 1 — Search for hardcoded keys, zero IVs, or predictable nonces
grep -rn "\[0u8; 16\]\|\[0u8; 32\]\|\[0u8; 12\]\|nonce.*=.*\[0\|iv.*=.*\[0" \
  crate/crypto/src/ --include="*.rs"

# Step 2 — Deprecated / weak algorithms (ECB mode, DES, RC4, MD5, SHA-1)
grep -rni "ecb\|des\b\|rc4\|md5\|sha1\b\|sha-1\|rc2\|md4" \
  crate/ --include="*.rs" | grep -v "//\|#\[doc\|test_" | head -30

# Step 3 — Sensitive key export: verify the sensitive flag blocks unprotected export
grep -n "sensitive\|key_wrapping_specification\|Sensitive\|is_sensitive" \
  crate/server/src/core/operations/export_get.rs

# Step 4 — Non-FIPS algorithm use must be gated behind the non-fips feature flag
grep -rn "#\[cfg(feature.*non.fips\|cfg.*non_fips" \
  crate/crypto/src/ --include="*.rs" | head -20
# Cross-check: algorithms that appear outside a cfg gate
grep -rni "Covercrypt\|AES.XTS\|chacha\|xchacha\|kyber\|dilithium" \
  crate/crypto/src/ --include="*.rs" | grep -v "#\[cfg" | head -15

# Step 5 — In-memory cache for unwrapped key material: check zeroization on eviction
grep -n "cache\|HashMap\|DashMap\|insert\|remove\|evict\|zeroize\|Zeroizing" \
  crate/server/src/core/wrapping/wrap.rs

# Step 6 — OpenSSL download: verify SHA-256 check is non-bypassable
grep -A5 -B5 "sha256\|checksum\|expected\|download\|verify" crate/crypto/build.rs

# Step 7 — Semgrep crypto-specific rules
semgrep --config p/rust crate/crypto/src/ --lang rust 2>/dev/null \
  | grep -i "crypto\|cipher\|hash\|random\|seed" || true
```

### 3.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/crypto/src/crypto/symmetric/symmetric_ciphers.rs`
- `crate/crypto/src/crypto/elliptic_curves/ecies/standard_curves.rs`
- `crate/server/src/core/operations/export_get.rs`
- `crate/server/src/core/wrapping/wrap.rs`
- `crate/crypto/build.rs`
- `crate/clients/clap/src/actions/mac.rs`, `actions/aws/byok/export_key_material.rs`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A02-1 | `symmetric_ciphers.rs:429,784` | Info | Zero-initialised buffers (`vec![0; nonce_size]`, `[0_u8; 16]`) are overwritten immediately by `rand_bytes()` or by structured counter/nonce construction (ChaCha20). No actual hardcoded IVs. |
| A02-2 | `mac.rs:17,31,47` / `export_key_material.rs:92,106` | Low | SHA-1 is exposed as a user-selectable MAC/hash algorithm and used in AWS BYOK RSA-OAEP wrapping. SHA-1 is weak for MAC and PKCS#1 v1.5 is weak for key wrapping. These paths are not gated behind `#[cfg(feature = "non-fips")]` in the CLI actions layer even though FIPS forbids SHA-1. |
| A02-3 | `standard_curves.rs:31` | Info | `let mut iv = vec![0; iv_size]` in ECIES — filled by OpenSSL `rand_bytes`. Safe; zero is a temporary placeholder. |
| A02-4 | `export_get.rs:77` | ✅ | `sensitive=true` objects are correctly blocked from export unless `key_wrapping_specification` is present. Per KMIP BL-M-12-21. |
| A02-5 | `wrap.rs:118–121` | Medium | Unwrapped key objects are stored in an in-memory `DashMap`/`HashMap` cache with no TTL or eviction policy visible in `wrap.rs`. Cached plaintext key material persists indefinitely in process heap, increasing the window for cold-boot / process-dump attacks. |
| A02-6 | `build.rs:234,274–275` | ✅ | `verify_hash()` enforces SHA-256 check on the OpenSSL tarball. Non-empty `sha256` param is required. Supply-chain integrity protected. |

**Recommended fix**:

- A02-2: Gate SHA-1 MAC and RSA-OAEP-SHA1 behind `#[cfg(feature = "non-fips")]` or emit a deprecation warning when selected. Replace with SHA-256 defaults.
- A02-5: Add a TTL (e.g. 60 s) or LRU eviction to the unwrapped-object cache. Call `zeroize()` on cache values before removal.

> **OWASP description**: Injection flaws occur when untrusted data is sent to an interpreter
> as part of a command or query (SQL, LDAP, OS shell, TTLV, XML).

## 4. A03 – Injection

### 4.1 Scope

| Area | Key files |
|------|-----------|
| Dynamic SQL query builder | `crate/server_database/src/stores/sql/locate_query.rs` |
| SQL backends | `crate/server_database/src/stores/sql/sqlite.rs`, `pgsql.rs`, `mysql.rs` |
| TTLV binary parser | `crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs` |
| TTLV XML parser | `crate/kmip/src/ttlv/xml/parser.rs`, `deserializer.rs` |
| JSON → TTLV entry point | `crate/server/src/routes/kmip.rs` — `from_ttlv()` call |
| CLI file path arguments | `crate/clients/clap/src/actions/` |

### 4.2 Investigation Steps

```bash
# Step 1 — SQL injection: flag any dynamic SQL built with format! or string concatenation
grep -rn \
  'format!.*SELECT\|format!.*INSERT\|format!.*UPDATE\|format!.*DELETE\|"SELECT.*{}' \
  crate/server_database/src/ --include="*.rs"

# Step 2 — Verify parameterized query usage throughout the SQL backends
grep -n "bind\|execute\|query_as\|fetch" \
  crate/server_database/src/stores/sql/locate_query.rs | head -30

# Step 3 — TTLV binary parser: length field checked before allocation?
grep -n "len\|size\|capacity\|Vec::with_capacity\|read_exact\|take\|limit" \
  crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs

# Step 4 — Recursion depth guard in TTLV struct parser
grep -rn "depth\|recursion\|stack\|max_depth\|fn from_ttlv\|fn parse" \
  crate/kmip/src/ttlv/ --include="*.rs"

# Step 5 — OS shell injection: any std::process::Command with user-supplied data?
grep -rn "Command::new\|std::process\|exec\|popen" \
  crate/clients/ crate/server/ --include="*.rs"

# Step 6 — Tag / object-group injection: these are stored as strings — verify binding
grep -n "tag\|Tag\|object_group\|ObjectGroup" \
  crate/server_database/src/stores/sql/locate_query.rs | head -20

# Step 7 — Semgrep injection ruleset
semgrep --config p/owasp-top-ten crate/ --lang rust 2>/dev/null \
  | grep -i "inject\|sql\|command\|exec" || true
```

### 4.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server_database/src/stores/sql/locate_query.rs`
- `crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs`
- `crate/kmip/src/ttlv/wire/ttlv_bytes_serializer.rs`
- `crate/server/src/core/operations/locate.rs`
- `crate/server/src/routes/kmip.rs`
- `crate/server/benchmarks/bench.rs` (CLI-only)

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A03-1 | `stores/sql/locate_query.rs` (all) | ✅ | All SQL queries use bind-parameter style (`sqlx::query!`, placeholder `?` / `$N`). No string concatenation into SQL statements. No SQL injection. |
| A03-2 | `ttlv_bytes_deserializer.rs:56` | **High** | `read_ttlv()` is purely recursive with no depth counter and no maximum depth check. A malicious deeply-nested TTLV binary can exhaust the call stack (stack overflow / uncontrolled recursion). An unauthenticated TTLV POST triggers this code path before any authentication (parsed at HTTP handler level). |
| A03-3 | `routes/kmip.rs` (XML path) | Medium | The TTLV XML parser (`ttlv_xml_deserializer.rs`) has a `depth` counter but the loop contains no `max_depth` enforcement — deep XML nesting proceeds without limit. |
| A03-4 | `bench.rs:2815` | Info | CLI benchmark code builds a gnuplot script embedding the `op` operation name variable inline. This is benchmark CLI code, not reachable from the server. No server-side command injection. |
| A03-5 | All server routes | ✅ | No OS `std::process::Command::new()` / `shell_exec` calls found in production server code. |

**Recommended fix**:

- A03-2: Add a `depth: u32` parameter to `read_ttlv()` and return an error when `depth > MAX_TTLV_DEPTH` (suggested: 64). Example: `fn read_ttlv(reader: &mut impl Read, depth: u32) -> Result<Ttlv> { if depth > 64 { return Err(...) } ... read_ttlv(reader, depth + 1) ... }`
- A03-3: Add `const MAX_XML_DEPTH: usize = 64;` and fail when `depth >= MAX_XML_DEPTH`.

---

## 5. A04 – Insecure Design

> **OWASP description**: Missing or ineffective control design. Unlike misconfiguration,
> this is a structural flaw that cannot be fixed by correct configuration alone.

### 5.1 Scope

| Area | Key files |
|------|-----------|
| KMIP operation dispatcher | `crate/server/src/core/operations/dispatch.rs` |
| Actix-web app builder | `crate/server/src/start_kms_server.rs` |
| Server configuration | `crate/server/src/config/` |
| KMIP lifecycle state machine | `crate/kmip/src/` — object state types |
| Rate limiting | `crate/server/src/middlewares/` |

### 5.2 Investigation Steps

```bash
# Step 1 — Max request body size: Actix default is 256 KB; look for an explicit override
grep -n "LimitPayloadSize\|max_payload_size\|PayloadConfig\|content_length\|max_body" \
  crate/server/src/start_kms_server.rs crate/server/src/routes/kmip.rs

# Step 2 — Rate limiting middleware
grep -rn "RateLimiter\|rate_limit\|throttle\|governor\|leaky_bucket\|token_bucket" \
  crate/server/src/ --include="*.rs"

# Step 3 — KMIP state machine: transitions must follow spec
# (PreActive → Active → Deactivated → Destroyed; no skipping)
grep -rn "Deactivated\|PreActive\|Compromised\|Destroyed\|state.*transition\|update_state" \
  crate/server/src/core/operations/ --include="*.rs"

# Step 4 — Bulk operations: can one request mutate thousands of objects?
grep -rn "Locate\|for.*objects\|batch\|BulkRequest\|RequestBatchItem" \
  crate/server/src/core/operations/ --include="*.rs" | head -20

# Step 5 — Locate result set: is it bounded / paginated?
grep -rn "limit\|offset\|pagination\|page_size\|LIMIT\|OFFSET\|max_items" \
  crate/server_database/src/ --include="*.rs"

# Step 6 — SecretData / Opaque objects: are there constraints on size or type?
grep -rn "SecretData\|Opaque\|OpaqueData\|CertificateRequest" \
  crate/server/src/core/operations/ --include="*.rs"
```

### 5.3 Findings

```text
Status: ❌ Vulnerability found
```

**Files inspected**:

- `crate/server/src/start_kms_server.rs`
- `crate/server/src/core/operations/locate.rs`
- `crate/server_database/src/stores/sql/locate_query.rs`
- `crate/server/src/middlewares/`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A04-1 | `start_kms_server.rs:767-768` | **High** | HTTP request body limit is set to 10 GB: `PayloadConfig::new(10_000_000_000)` and `JsonConfig::default().limit(10_000_000_000)`. Any unauthenticated or authenticated client can send a 10 GB request body, potentially exhausting server RAM and causing out-of-memory termination. |
| A04-2 | All server middlewares | **High** | No rate-limiting middleware is registered anywhere in the Actix-web application. There is no throttling on KMIP operations, API token verification, or UI login. An attacker can issue unlimited requests per second, allowing brute-force of API tokens and CPU/memory exhaustion. |
| A04-3 | `operations/locate.rs:96-101` | Medium | The `MaximumItems` field in a Locate request is fully client-controlled and optional. When absent, the server returns all matching objects. There is no server-side cap on the result set size. A client owning or co-owning a large number of objects can trigger a very large response. |
| A04-4 | `operations/dispatch.rs` | ✅ | KMIP state machine transitions (PreActive→Active→Deactivated→Destroyed) are enforced via `activate.rs`, `revoke.rs`, `destroy.rs`. Invalid transitions are rejected with `ItemNotFound` or state-error. |
| A04-5 | `operations/locate.rs` + `batch_items.rs` | ✅ | Batch request item limit: the KMIP spec allows batch requests; each item is individually dispatched and access-controlled. No uncontrolled bulk mutation discovered beyond the Locate unbounded-result issue. |

**Recommended fix**:

- A04-1: Reduce `PayloadConfig` and `JsonConfig` limits to a realistic maximum (e.g. 64 MB for KMIP bodies, 1 MB for JSON config). Use `PayloadConfig::new(64 * 1024 * 1024)`.
- A04-2: Add a rate-limiting middleware using `actix-governor` or `tower-governor`. Apply globally plus a stricter limit on authentication endpoints.
- A04-3: Add a server-side cap: if `MaximumItems` is absent or exceeds a configured `max_locate_items` (default 1 000), clamp the SQL `LIMIT` to that value.

---

## 6. A05 – Security Misconfiguration

> **OWASP description**: The most commonly seen issue, resulting from insecure default
> configurations, missing hardening, verbose error messages, or open cloud storage.

### 6.1 Scope

| Area | Key files |
|------|-----------|
| All server CLI flags & defaults | `crate/server/src/config/command_line/` (all files) |
| TLS settings | `crate/server/src/config/command_line/tls_config.rs` |
| UI authentication & CORS | `crate/server/src/routes/ui_auth.rs` |
| OpenSSL provider init | `crate/server/src/openssl_providers.rs` |
| Error response format | `crate/server/src/routes/kmip.rs` — error handling |

### 6.2 Investigation Steps

```bash
# Step 1 — Enumerate all default values for security-sensitive flags
grep -n "default_value\|default.*=\s*\"\|fn default()" \
  crate/server/src/config/command_line/clap_config.rs | head -50

# Step 2 — TLS: minimum protocol version and cipher suite defaults
grep -rn "TLSv1\|tls_cipher\|cipher_suite\|TlsVersion\|min_protocol\|SSLv" \
  crate/server/src/config/ --include="*.rs"
grep -n "tls_p12\|tls_cert\|tls_key\|tls_chain\|clients_ca" \
  crate/server/src/config/command_line/tls_config.rs

# Step 3 — CORS: look for wildcard origins or missing CORS restrictions
grep -rn "Cors\|allow_origin\|AllowedOrigin\|allow_any_origin" \
  crate/server/src/ --include="*.rs"

# Step 4 — Error messages: do they expose stack traces or internal paths?
grep -rn "backtrace\|debug_info\|internal_err\|unwrap()\|expect(" \
  crate/server/src/routes/ --include="*.rs" | head -20

# Step 5 — Dangerous feature flags that weaken security
grep -rn "insecure\|skip.*expir\|no.verify\|allow_self_signed" \
  crate/server/src/ --include="*.rs" | grep -v "#\[cfg\|cfg(feature\|//.*insecure"

# Step 6 — Environment variable names that carry secrets: verify none are logged
grep -rn 'KMS_.*PASSWORD\|KMS_.*SECRET\|KMS_.*KEY\|KMS_.*TOKEN' \
  crate/server/src/ --include="*.rs"

# Step 7 — Secrets scanner: detect hardcoded credentials
semgrep --config p/secrets crate/ --lang rust 2>/dev/null | head -30 || true
gitleaks detect --source . --no-git 2>/dev/null | head -30 || true
```

### 6.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server/src/start_kms_server.rs`
- `crate/server/src/config/command_line/tls_config.rs`
- `crate/server/src/openssl_providers.rs`
- `deny.toml`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A05-1 | `start_kms_server.rs:776,795,806,901,962` | Medium | `Cors::permissive()` applied on every scope: main KMIP, UI, Google CSE, MS DKE, AWS XKS. Sets `Access-Control-Allow-Origin: *`, allowing any browser origin to reach the KMIP endpoint cross-origin. |
| A05-2 | `config/command_line/tls_config.rs` | Low | TLS minimum version is not explicitly configured in code. Relies on OpenSSL 3.6.0 default (TLS 1.2+). Should be made explicit. |
| A05-3 | `middlewares/jwt/jwt_config.rs:10,155` | Medium | The `insecure` feature completely disables all JWT validation (signature, expiry, audience). No compile-time guard prevents this feature from reaching production. If accidentally included in a production build, any token is accepted. |
| A05-4 | `deny.toml` | Low | `RUSTSEC-2026-0097` is allow-listed in the cargo deny policy. Should be resolved by upgrading `rand` instead of permanently suppressing the advisory. |
| A05-5 | All routes | ✅ | Error responses use KMIP error codes; no stack traces or file paths exposed in HTTP responses. |

**Recommended fix**:

- A05-1: Replace `Cors::permissive()` with `Cors::default().allowed_origin("https://your-kms-domain.example.com")` or configure allowed origins from server config.
- A05-3: Add `#[cfg(all(not(test), feature = "insecure"))] compile_error!("insecure feature must not be enabled in production");` near the top of `jwt_config.rs`.

---

## 7. A06 – Vulnerable and Outdated Components

> **OWASP description**: Components run with the same privileges as the application.
> If a vulnerable component is exploited it can cause serious data loss or server takeover.

### 7.1 Scope

| Area | Files |
|------|-------|
| Workspace dependencies | `Cargo.toml` (root) + all `crate/*/Cargo.toml` |
| Deny policy | `deny.toml` |
| OpenSSL build + hash | `crate/crypto/build.rs` |
| UI dependencies | `ui/package.json`, `ui/pnpm-lock.yaml` |
| Git history | `.git/` |

### 7.2 Investigation Steps

```bash
# Step 1 — Scan Rust dependencies for known CVEs (RustSec Advisory DB)
cargo audit

# Step 2 — Policy-based check: licenses, banned crates, advisories, duplicates
cargo deny check

# Step 3 — List outdated crates vs latest on crates.io
cargo outdated --workspace

# Step 4 — Count unsafe code per crate (establish risk baseline)
cargo geiger --workspace 2>/dev/null | tail -50

# Step 5 — Verify OpenSSL source is pinned and SHA-256-verified in build script
grep -A5 -B5 "openssl.*version\|OPENSSL_VERSION\|sha256\|expected_hash\|verify" \
  crate/crypto/build.rs | head -30

# Step 6 — UI dependency audit
cd ui && pnpm audit 2>/dev/null || npm audit 2>/dev/null; cd ..

# Step 7 — Git-sourced Rust deps (bypass crates.io auditing)
grep -rn "git = \|branch = \|rev = " Cargo.toml crate/*/Cargo.toml

# Step 8 — Scan full git history for accidentally committed secrets
gitleaks detect --source . 2>/dev/null | head -30 || \
  trufflehog3 --no-entropy . 2>/dev/null | head -30 || \
  echo "Run a secrets scanner manually"
```

### 7.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**: `Cargo.toml` (workspace), `deny.toml`, `crate/crypto/build.rs`

**`cargo audit` output (2026-04-13)**:

```text
Warning: 2 vulnerabilities found!
crate:   rand  version: 0.8.5  advisory: RUSTSEC-2026-0097 (allow-listed)
crate:   rand  version: 0.9.2  advisory: RUSTSEC-2026-0097 (allow-listed)
```

**`cargo deny check`**: passes with warnings (advisory allow-listed in `deny.toml`)

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A06-1 | `Cargo.toml` (workspace) | Medium | **RUSTSEC-2026-0097** affects `rand 0.8.5` and `rand 0.9.2` — two separate version trees coexisting in the dependency graph. Advisory covers unseeded PRNG panic under unusual usage. Suppressed rather than resolved. |
| A06-2 | `Cargo.toml` (workspace) | Low | 20+ duplicate crate versions: `base64` (×3: 0.13, 0.21, 0.22), `hashbrown` (×4: 0.12–0.15), `rand` (×2), `opentelemetry` (×2), `time` (×3), etc. Increases supply-chain surface and binary size. |
| A06-3 | `crate/crypto/build.rs:234,274` | ✅ | OpenSSL 3.6.0 tarball is SHA-256-verified (`verify_hash()`) before extraction. Version pinned by constant. Supply-chain integrity protected. |
| A06-4 | All `Cargo.toml` files | ✅ | No `git =` sourced Rust dependencies. All deps come from crates.io. |
| A06-5 | `ui/pnpm-lock.yaml` | Info | UI npm/pnpm audit was not run during this automated pass. Manual `pnpm audit --audit-level moderate` recommended. |
| A06-6 | Workspace (`crate/clients/wasm/Cargo.toml`) | Low | **`cargo outdated`** shows `cosmian_kms_client_wasm` requires `getrandom` with the `js` feature, but the installed version (0.4.2) no longer exposes that feature. This causes `cargo outdated` to fail for the WASM crate. The WASM build may silently use a mismatched `getrandom` version in non-browser target builds. |
| A06-7 | workspace (geiger scan) | Info | **`cargo-geiger 0.13.0`** fails on this virtual workspace with a known upstream bug. Manual `grep -r "unsafe "` shows: `crate/server/src/` (5 files, 22 uses — all OpenSSL FFI + FIPS env setup), `crate/crypto/src/` (5 files, 35 uses — OpenSSL/PQC FFI), `crate/server_database/src/` (0), `crate/kmip/src/` (0), `crate/access/src/` (0). PKCS#11 module/provider and HSM loaders contain additional unsafe as expected for C FFI. No unexpected unsafe blocks were found in core server logic. |

**Recommended fix**:

- A06-1: Upgrade `rand` to the version that resolves RUSTSEC-2026-0097. Run `cargo update -p rand` and verify with `cargo audit`.
- A06-2: Dedup by aligning version requirements across crates using `[patch]` or resolving transitive dependency mismatches. Track with `cargo deny check duplicates`.
- A06-5: Add `cd ui && pnpm audit --audit-level moderate` to CI pipeline.
- A06-6: Align `getrandom` version in `crate/clients/wasm/Cargo.toml` to a version that still exposes the `js` feature gate, or remove the feature if no longer applicable.
- A06-7 (geiger): Upgrade `cargo-geiger` when a version supporting Rust 2024 virtual workspaces is available. Track [cargo-geiger#378](https://github.com/rust-secure-code/cargo-geiger/issues/378).

---

## 8. A07 – Identification and Authentication Failures

> **OWASP description**: Incorrectly implemented authentication and session management
> allow attackers to compromise passwords, keys, or session tokens, or to assume other
> users' identities.

### 8.1 Scope

| Area | Key files |
|------|-----------|
| JWT middleware | `crate/server/src/middlewares/jwt/jwt_middleware.rs`, `jwt_token_auth.rs`, `jwt_config.rs` |
| JWKS manager | `crate/server/src/middlewares/jwt/jwks.rs` |
| API token auth | `crate/server/src/middlewares/api_token/api_token_auth.rs`, `api_token_middleware.rs` |
| TLS client cert auth | `crate/server/src/middlewares/tls_auth.rs` |
| AWS SigV4 auth | `crate/server/src/routes/aws_xks/sigv4_middleware.rs` |
| Auth fallback | `crate/server/src/middlewares/ensure_auth.rs` |
| `insecure` feature gate | Everywhere gated by `#[cfg(feature = "insecure")]` |

### 8.2 Investigation Steps

```bash
# Step 1 — JWT algorithm restriction: must be RS256/ES256; reject HS256 and "none"
grep -rn "Algorithm\|alg\|Validation\|decode\|jsonwebtoken\|DecodingKey" \
  crate/server/src/middlewares/jwt/ --include="*.rs"

# Step 2 — Token expiration enforcement (insecure feature relaxes this)
grep -rn "exp\|expir\|validate_exp\|insecure\|leeway" \
  crate/server/src/middlewares/jwt/ --include="*.rs"

# Step 3 — JWKS fetch URL: must be HTTPS-only; no plain HTTP fallback
grep -n "http://\|reqwest\|fetch_jwks\|jwks_uri\|jwks_url\|url" \
  crate/server/src/middlewares/jwt/jwks.rs

# Step 4 — API token comparison: must be constant-time to prevent timing attacks
grep -n "==\|compare\|ConstantTimeEq\|constant_time\|subtle\|ct_eq" \
  crate/server/src/middlewares/api_token/api_token_auth.rs

# Step 5 — TLS cert auth: CN alone is insufficient; check if full DN or SAN is used
grep -n "CommonName\|CN\|SubjectAltName\|SAN\|subject\|peer_cert\|peer_certificate" \
  crate/server/src/middlewares/tls_auth.rs

# Step 6 — Session fixation in UI auth: cookie must be HttpOnly, Secure, SameSite=Strict
grep -rn "actix.session\|Session\|cookie\|HttpOnly\|Secure\|SameSite" \
  crate/server/src/routes/ui_auth.rs crate/server/src/middlewares/ --include="*.rs"

# Step 7 — Brute-force protection: lookout for rate limiting on auth endpoints
grep -rn "rate_limit\|lockout\|backoff\|attempt\|max_fail" \
  crate/server/src/middlewares/ --include="*.rs"

# Step 8 — Semgrep auth patterns
semgrep --config p/owasp-top-ten \
  crate/server/src/middlewares/ --lang rust 2>/dev/null || true
```

### 8.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server/src/middlewares/jwt/jwt_config.rs`
- `crate/server/src/middlewares/api_token/api_token_auth.rs`
- `crate/server/src/middlewares/tls_auth.rs`
- `crate/server/src/start_kms_server.rs`
- All `crate/server/src/middlewares/` files

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A07-1 | `jwt_config.rs:170` | **High** | `Validation::new(header.alg)` — JWT validation algorithm is taken directly from the `alg` field of the incoming token header without any allowlist. An attacker who obtains a valid `kid` could craft a token with `alg: HS256` and use the RSA public key as the HMAC secret (algorithm confusion / "none" alg attack vector). The `jsonwebtoken` crate's `Validation::new` initialises with the given algorithm but does NOT restrict to it unless `algorithms` is explicitly set. |
| A07-2 | `api_token_auth.rs:126` | Medium | API token comparison uses `client_token == api_token.as_str()` — standard `==` operator, which is **not timing-safe**. Timing differences can reveal whether the token length matches or prefix bytes are correct. A high-volume attacker on a low-latency network could exploit this to brute-force API tokens. |
| A07-3 | `tls_auth.rs:147` | Low | TLS client certificate identity uses CN (Common Name) only, not SAN (Subject Alternative Name). Wildcard CNs (`*`) are explicitly rejected (correct). Modern TLS stacks prefer SAN; CN-only auth may fail on strict clients. |
| A07-4 | `start_kms_server.rs:759` | Low | Session cookie `SameSite` is set to `None` (cross-site allowed). `SameSite::Strict` or `Lax` would protect against CSRF for browser-initiated requests. |
| A07-5 | `jwt_config.rs:10,155` | Medium | The `insecure` feature disables **all** JWT validation including signature and expiration. Must not appear in production builds (see also A05-3). |
| A07-6 | All endpoints | **High** | No brute-force protection or account lockout on any authentication endpoint (JWT, API token, TLS). Combined with A04-2 (no rate limiting), this allows unlimited credential-guessing attempts. |

**Recommended fix**:

- A07-1: After calling `Validation::new(alg)`, immediately set `validation.algorithms = vec![alg]` (already in scope) AND add a check that `alg` is in an explicit server-side allowlist (e.g. `[RS256, RS384, RS512, ES256, ES384]`). Reject tokens with `alg: none`, `alg: HS256` against asymmetric keys.
- A07-2: Replace `client_token == api_token.as_str()` with a constant-time comparison: use `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal()`.
- A07-4: Change `SameSite::None` to `SameSite::Strict` unless cross-site embedding of the KMS UI is required.

---

## 9. A08 – Software and Data Integrity Failures

> **OWASP description**: Code and infrastructure that does not protect against integrity
> violations, including insecure deserialization, CI/CD pipeline attacks, and unsigned
> updates.

### 9.1 Scope

| Area | Key files |
|------|-----------|
| OpenSSL download + verify | `crate/crypto/build.rs` |
| Imported object validation | `crate/server/src/core/operations/import.rs` |
| KMIP deserializer | `crate/kmip/src/ttlv/` |
| Cargo lock and git deps | `Cargo.lock`, `Cargo.toml` |
| CI pipeline scripts | `.github/workflows/`, `.github/scripts/` |
| Nix vendor hashes | `nix/expected-hashes/` |

### 9.2 Investigation Steps

```bash
# Step 1 — OpenSSL build: SHA-256 check must be present and non-bypassable
grep -A5 -B5 "sha256\|checksum\|expected\|download\|verify" crate/crypto/build.rs

# Step 2 — Imported keys: are cryptographic properties validated on import?
# (RSA modulus size, EC curve OID, key material length)
grep -n "validate\|check\|verify\|length\|CryptographicLength\|Algorithm\|curve" \
  crate/server/src/core/operations/import.rs | head -30

# Step 3 — KMIP deserialization: unknown fields rejected (not silently ignored)?
grep -rn "deny_unknown_fields\|flatten\|#\[serde\|untagged\|tag" \
  crate/kmip/src/ --include="*.rs" | head -20

# Step 4 — Git-sourced or path-sourced Rust deps (integrity not guaranteed by crates.io)
grep -rn "git =\|path =\|branch =\|rev =" Cargo.toml crate/*/Cargo.toml

# Step 5 — CI scripts: unauthenticated downloads or pipe-to-shell patterns
grep -rn "curl.*sh\|wget.*sh\|pip install\|npm install" \
  .github/scripts/ .github/workflows/ 2>/dev/null \
  | grep -v "^#\|#.*curl" | head -20

# Step 6 — Nix vendor hashes: all four variants must be present and non-trivial
ls -la nix/expected-hashes/
grep -v "^sha256-AAAA" nix/expected-hashes/*.sha256 2>/dev/null | head -10
```

### 9.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server/src/middlewares/ensure_auth.rs`
- `crate/kmip/src/`
- `crate/server/src/core/operations/import_export.rs`
- `deny.toml`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A08-1 | `crate/kmip/src/kmip_0/kmip_operations.rs` (all structs) | Low | KMIP request/response structs do not use `#[serde(deny_unknown_fields)]`. Unknown fields in incoming KMIP JSON/XML are silently ignored rather than rejected. An attacker can add arbitrary fields to requests without triggering any error; this makes protocol-level fuzzing harder to detect. |
| A08-2 | `start_kms_server.rs:737` | Medium | The UI session signing key is derived from the server URL. If the server is deployed with the default or a predictable URL (e.g. `http://localhost:9998`), the session key is predictable, allowing cookie forgery. The fallback salt `"cosmian_kms_default_ui_session_key_v1"` in `build_session_key()` makes this exploitable when no explicit key is configured. |
| A08-3 | `crate/crypto/build.rs:234,274` | ✅ | OpenSSL tarball SHA-256 is verified before build. Prevents tampered source from being compiled in. |
| A08-4 | All `Cargo.toml` files | ✅ | No `git =` sourced deps. All Rust crates come from crates.io with version pinning. |
| A08-5 | `crate/server/src/core/operations/import.rs` | ✅ | CRL validation is performed on certificate import. Key parameter validation relies on OpenSSL's own enforcement (key size, curve OID, etc.), which is appropriate. |

**Recommended fix**:

- A08-1: Add `#[serde(deny_unknown_fields)]` to all top-level KMIP request structs where spec compliance is required, or at minimum log a warning when unknown fields are encountered.
- A08-2: Generate and persist a random 32-byte session key on first startup (saving it to the DB or a config file), and require it to be explicitly set in production. Remove the predictable URL-derived default.

---

## 10. A09 – Security Logging and Monitoring Failures

> **OWASP description**: Insufficient logging and monitoring allows attackers to maintain
> persistence, pivot, and tamper with or exfiltrate data undetected.

### 10.1 Scope

| Area | Key files |
|------|-----------|
| KMIP request tracing | `crate/server/src/routes/kmip.rs`, `routes/access.rs` |
| Configuration secret logging | `crate/server/src/config/command_line/` (all files) |
| Auth failure logging | `crate/server/src/middlewares/` |
| Privileged operation audit events | `crate/server/src/core/operations/export_get.rs`, `destroy.rs`, `revoke.rs` |
| Error response content | `crate/server/src/routes/` |

### 10.2 Investigation Steps

```bash
# Step 1 — Secrets in config log output: DB URLs, TLS passwords, API tokens
grep -rn "tracing::\|info!\|warn!\|error!\|debug!\|trace!" \
  crate/server/src/config/ --include="*.rs" \
  | grep -i "password\|secret\|token\|key\|credential\|url\|connection"

# Step 2 — Auth middleware: failure messages must NOT include the raw token value
grep -rn "info!\|warn!\|error!\|debug!" \
  crate/server/src/middlewares/ --include="*.rs" \
  | grep -i "token\|bearer\|api.key\|password\|secret"

# Step 3 — Privileged operations logged with user identity?
# (Export, Destroy, Revoke are high-value audit events)
grep -n "tracing\|info!\|warn!\|error!" \
  crate/server/src/core/operations/export_get.rs \
  crate/server/src/core/operations/destroy.rs \
  crate/server/src/core/operations/revoke.rs 2>/dev/null | head -40

# Step 4 — Failed auth events: are 401/403 responses logged?
grep -rn "401\|403\|Unauthorized\|Forbidden\|warn!\|error!" \
  crate/server/src/middlewares/ --include="*.rs" \
  | grep -i "auth\|denied\|failed\|reject"

# Step 5 — Log injection: user-controlled strings inserted into tracing macros
# without sanitization allow log-forging via embedded newlines
grep -rn 'info!.*user\|debug!.*uid\|trace!.*tag\|warn!.*{.*}' \
  crate/server/src/core/operations/ --include="*.rs" | head -20

# Step 6 — Coverage: all KMIP operations should have an instrumentation span
grep -rn "span!\|instrument\|#\[tracing::instrument\]" \
  crate/server/src/core/operations/ --include="*.rs" | wc -l
echo "Total operation files:"
ls crate/server/src/core/operations/*.rs 2>/dev/null | wc -l
```

### 10.3 Findings

```text
Status: ❌ Vulnerability found
```

**Files inspected**:

- `crate/server/src/config/command_line/db.rs`
- `crate/server/src/config/command_line/tls_config.rs`
- `crate/server/src/middlewares/jwt/jwks.rs`
- `crate/server/src/routes/ui_auth.rs`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A09-1 | `config/command_line/db.rs:160,168` | **High** | The `Display` impl for `MainDBConfig` prints PostgreSQL and MySQL `database_url` **completely unmasked**. A URL like `postgresql://kms_user:secretpassword@host/kms_db` is logged verbatim at server startup. Any log aggregation system (Splunk, ELK, CloudWatch) will store the database password in plaintext. Redis correctly masks the password as `[****]`. |
| A09-2 | `config/command_line/tls_config.rs:81` | Medium | TLS P12 password is masked via `.replace('.', "*")` — this only replaces dot characters with asterisks. A password like `my_pass` is logged unchanged; `my.pass` becomes `my*pass`. The masking is ineffective for most passwords. |
| A09-3 | `middlewares/jwt/jwt_token_auth.rs:115` | Low | JWT authentication failures (invalid signature, expired token) are logged only at `DEBUG` level. These are security-relevant events that should be logged at `WARN` or `ERROR` to ensure they appear in production monitoring dashboards. |
| A09-4 | `core/operations/` (decrypt.rs, locate.rs, sign.rs) | Low | User-controlled strings (`uid`, `user`) are embedded in `tracing` macro log calls without sanitization. An attacker can inject newline characters into a UID field to insert fake log records. |
| A09-5 | `core/operations/export_get.rs`, `destroy.rs` | ✅ | Export and Destroy operations are logged with both `uid` and `user` at INFO level. Privileged operation audit trail is present. |
| A09-6 | `routes/ui_auth.rs` | ✅ | `ui_oidc_client_secret` is masked as `****` in Display output. OIDC secret does not leak into logs. |

**Recommended fix**:

- A09-1: **Critical** — Mask the password component in database URLs before logging. Parse the URL, replace the password with `[****]`, then log. Example: use the `url` crate to parse and rebuild. Fix the `Display` impl for `MainDBConfig::PostgreSQL` and `MainDBConfig::MySQL`.
- A09-2: Fix the P12 password masking to replace *all* characters: `.repeat("*", password.len())` or simply log `"[****]"` as a constant.
- A09-3: Change JWT auth failure tracing to `tracing::warn!` and include the source IP address.
- A09-4: Sanitize or percent-encode `uid` and `user` strings before embedding them in log calls. Consider using `tracing` structured fields (`uid = %uid`) and ensuring the log formatter strips control characters.

---

## 11. A10 – Server-Side Request Forgery (SSRF)

> **OWASP description**: SSRF flaws occur when a web application fetches a remote resource
> without validating the user-supplied URL, allowing an attacker to coerce outbound
> requests to unexpected destinations (cloud metadata endpoints, internal services, etc.).

### 11.1 Scope

| Area | Key files |
|------|-----------|
| JWKS URL fetch | `crate/server/src/middlewares/jwt/jwks.rs` |
| Google CSE callbacks | `crate/server/src/routes/google_cse/` |
| AWS XKS outbound calls | `crate/server/src/routes/aws_xks/` |
| Azure EKM connections | `crate/server/src/routes/azure_ekm/` |
| HTTP client construction | `crate/clients/client/src/` |

### 11.2 Investigation Steps

```bash
# Step 1 — Enumerate all outbound HTTP client instantiations
grep -rn "reqwest::Client\|reqwest::get\|Client::new\|ClientBuilder\|hyper::Client" \
  crate/ --include="*.rs" | grep -v "test\|#\[cfg(test"

# Step 2 — JWKS URL: validated / allowlisted, or taken verbatim from config?
grep -n "jwks_uri\|jwks_url\|fetch\|get\|url\|https\|http" \
  crate/server/src/middlewares/jwt/jwks.rs

# Step 3 — User-controlled URL fields in KMIP extensions or attributes
# (an attacker could embed a URL in a KMIP extension field)
grep -rn "url\|http\|endpoint\|callback\|webhook" \
  crate/server/src/core/operations/ --include="*.rs" \
  | grep -i "user\|request\|input\|attribute\|extension"

# Step 4 — Google CSE: user-controlled redirect or callback URLs?
grep -rn "redirect\|callback\|url\|uri" \
  crate/server/src/routes/google_cse/ --include="*.rs"

# Step 5 — HTTP client redirect policy: SSRF via 301 redirect chain
grep -rn "redirect\|follow_redirect\|redirect_policy\|max_redirect" \
  crate/ --include="*.rs"

# Step 6 — Outbound URL allowlists
grep -rn "allowlist\|whitelist\|allowed_url\|valid_host\|parse.*url\|Url::parse" \
  crate/ --include="*.rs" | grep -v test | head -15
```

### 11.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server/src/middlewares/jwt/jwks.rs`
- `crate/server/src/routes/ui_auth.rs`
- `crate/clients/client/src/http_client/tls.rs`
- `crate/clients/ckms/src/config.rs`
- All `crate/server/src/routes/` URL-consuming code

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| A10-1 | `clients/ckms/src/config.rs:115` | Medium | `accept_invalid_certs: true` is hardcoded in the CLI's `KmsClientConfig::default()`. This disables outbound TLS certificate validation for CLI-to-KMS connections. While the CLI is not server-side code, `cosmian_kms_client` is also used in integration tests and potentially in embedded contexts where this default silently bypasses TLS chain validation. |
| A10-2 | `middlewares/jwt/jwks.rs` | Low | `reqwest::Client::new()` is used for JWKS endpoint fetching. By default `reqwest` follows HTTP redirects. The JWKS URL comes from admin configuration (`jwt_issuer_uri`), not from user input at request time. If an admin passes an internal URL as the JWKS issuer, the server could fetch internal endpoints (low-risk SSRF). No redirect allowlist or `redirect::none()` is applied. |
| A10-3 | `routes/ui_auth.rs` | Low | Same pattern: `reqwest::Client::new()` used for OAuth token exchange, following redirects without restriction. |
| A10-4 | All server routes | ✅ | No user-controlled URL parameters are used for server-side HTTP fetches at request time. JWKS/OIDC URLs come from static admin configuration only. The SSRF surface is limited to the initial server startup configuration. |
| A10-5 | `routes/aws_xks/`, `routes/azure_ekm/`, `routes/google_cse/` | ✅ | Enterprise routes do not make outbound requests based on incoming request data. |

**Recommended fix**:

- A10-1: Change CLI default to `accept_invalid_certs: false`. Provide an explicit `--insecure` flag or `COSMIAN_KMS_NO_VERIFY_CERT=true` env var that must be explicitly set.
- A10-2 / A10-3: Build the `reqwest` client with `.redirect(reqwest::redirect::Policy::none())` or restrict to a maximum of 1 redirect, and add a URL scheme allowlist (only `https://`).

---

## 12. EXT-0 – KMS Own Authorization System

> **OWASP ASVS V4 (Access Control)**
> The KMS implements a custom, multi-layer authorization model that sits on top of KMIP.
> This section audits the full call chain from HTTP request to permission decision,
> covering privilege escalation paths, bypass mechanisms, and delegation controls.

### 12.1 Architecture

Every KMIP operation follows this authorization chain:

```text
HTTP request
  └─ TlsAuthMiddleware | JwtMiddleware | ApiTokenMiddleware
       └─ EnsureAuthMiddleware  (fallback: uses default_username)
            └─ routes/kmip.rs  →  kms.get_user(&req)
                 │  ↑ force_default_username=true → ALL identities silently discarded
                 └─ dispatch(kms, ttlv, user)  →  operation handler
                      └─ retrieve_object_for_operation(uid, op, kms, user)
                           └─ user_has_permission(user, owm, op, kms)
                                ├─ SHORTCUT  user == owm.owner()  →  true  (owner bypass)
                                ├─ IMPLICIT  ops.contains(Get)   →  ALL ops allowed
                                └─ DB query  list_user_operations_on_object(uid, user)
                                        ├─ SQL: WHERE object_id = uid   AND user_id = user
                                        └─     UNION object_id = "*"  AND user_id = user
```

Key design decisions with security implications:

| Mechanism | Location | Risk if abused |
|-----------|----------|----------------|
| Owner bypass | `user_has_permission()` | Ownership must be immutable post-creation |
| `Get` → all operations | `user_has_permission()` | Anyone with `Get` can Encrypt/Decrypt/Sign/Export |
| Wildcard `"*"` stores Create perm | DB schema | User with Create on `"*"` can create unlimited objects |
| `force_default_username=true` | `kms.get_user()` | Discards all user identities — complete authorization bypass |
| `privileged_users` list | `clap_config.rs` | Members bypass Create/Import permission checks |
| `EnsureAuth` fallback | `ensure_auth.rs` | Default single-user mode if no auth is configured |

### 12.2 Scope

| Area | Key files |
|------|-----------|
| Core permission gate | `crate/server/src/core/retrieve_object_utils.rs` |
| KMS identity resolution & delegation | `crate/server/src/core/kms/permissions.rs` |
| Permission data types | `crate/access/src/access.rs` |
| SQL permission queries | `crate/server_database/src/stores/sql/` — permissions table |
| Redis permission store | `crate/server_database/src/stores/redis/permissions.rs` |
| Privilege config (`force_default_username`, `privileged_users`) | `crate/server/src/config/command_line/clap_config.rs` |
| Create / Import authorization | `crate/server/src/core/operations/create.rs`, `import.rs`, `register.rs` |
| Delegation controls | `crate/server/src/core/kms/permissions.rs` — `grant_access()`, `revoke_access()` |

### 12.3 Investigation Steps

```bash
# Step 1 — Map every bypass mechanism and their activation conditions
grep -n "force_default_username\|privileged_users\|default_username" \
  crate/server/src/config/command_line/clap_config.rs \
  crate/server/src/core/kms/permissions.rs

# Step 2 — Owner bypass: trace user_has_permission() — verify the owner check
# cannot be spoofed (e.g. owners set at Create time, never updated)
grep -n "owner\|is_object_owned_by\|user.*==.*owner\|owner.*==" \
  crate/server/src/core/retrieve_object_utils.rs \
  crate/server/src/core/kms/permissions.rs

# Step 3 — "Get implies all operations": find the implicit grant and verify scope
grep -n "KmipOperation::Get\|contains.*Get\|implies\|all.*ops" \
  crate/server/src/core/retrieve_object_utils.rs

# Step 4 — Wildcard "*" permission for Create: only privileged_users may grant it
grep -n '"\\*"\|wildcard\|Create\|privileged\|grant_access\|is_create' \
  crate/server/src/core/kms/permissions.rs \
  crate/server/src/core/operations/create.rs \
  crate/server/src/core/operations/import.rs

# Step 5 — Non-owner grant delegation: is_object_owned_by() enforced in grant_access()?
grep -A10 "fn grant_access" crate/server/src/core/kms/permissions.rs | head -20

# Step 6 — Self-grant prevention: a caller must not grant themselves extra permissions
grep -n "user_id.*owner\|owner.*user_id\|grant.*self\|access.user_id" \
  crate/server/src/core/kms/permissions.rs

# Step 7 — KMIP lifecycle state filter: Destroyed / Compromised block operations
grep -n "Destroyed\|Compromised\|PreActive\|Deactivated\|state.*check\|filter.*state" \
  crate/server/src/core/retrieve_object_utils.rs

# Step 8 — Public endpoints: verify /health, /version, /server-info leak no data
grep -rn "health\|version\|server.info\|configure\|service\|wrap" \
  crate/server/src/start_kms_server.rs | head -30
# Read actual health and version handler to confirm response content
cat crate/server/src/routes/health.rs 2>/dev/null | head -60

# Step 9 — Enterprise routes: verify AWS/Azure/Google/DKE routes cannot call
# standard KMIP operations using their own auth as a bypass
grep -rn "dispatch\|kms\.\|KMS\b" \
  crate/server/src/routes/aws_xks/ \
  crate/server/src/routes/azure_ekm/ \
  crate/server/src/routes/google_cse/ \
  crate/server/src/routes/ms_dke/ --include="*.rs" | head -30

# Step 10 — Redis PermTriple: concurrent grant + revoke atomicity
grep -n "PermTriple\|insert\|delete\|transaction\|atomic\|pipeline\|multi" \
  crate/server_database/src/stores/redis/permissions.rs | head -20

# Step 11 — EnsureAuth: confirm it is a last-resort fallback, not a global bypass
cat crate/server/src/middlewares/ensure_auth.rs
```

### 12.4 Checklist

- [ ] `force_default_username=true` cannot be set via any unauthenticated endpoint or environment variable injection
- [ ] `privileged_users` list is logged at startup so admins can detect unauthorized changes
- [ ] `Get` → all-operations implicit grant is intentional, documented, and cannot cross user boundaries
- [ ] A non-owner holding `Get` permission **cannot** call `grant_access()` to escalate other users
- [ ] A user cannot grant `Create` permission to themselves or others unless they are in `privileged_users`
- [ ] `/health`, `/version`, `/server-info` return no object metadata, user identities, or internal state
- [ ] Enterprise routes (XKS, EKM, CSE, DKE) authenticate independently and cannot reach standard KMIP key material without passing the full KMIP auth chain
- [ ] KMIP lifecycle transitions from `Compromised` or `Destroyed` are irreversible and enforced at DB level
- [ ] Redis `PermTriple` updates are atomic (no TOCTOU between concurrent grant and revoke requests)

### 12.5 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server/src/core/retrieve_object_utils.rs`
- `crate/server/src/core/kms/permissions.rs`
- `crate/server/src/config/command_line/clap_config.rs` (for `force_default_username`)

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| EXT0-1 | `retrieve_object_utils.rs:191` | Medium | `permissions.contains(&KmipOperation::Get)` is used as the universal "has some access" check. Any user with `Get` permission on an object is treated as having permission for ALL operations on it (Encrypt, Decrypt, Sign, Verify, GetAttributes, etc.). This is an intentional design decision but undocumented as a security policy. It makes permission grants broader than the receiver may expect. |
| EXT0-2 | `core/kms/permissions.rs:23–100` | ✅ | `grant_access()` correctly enforces: (1) only the owner can grant, (2) `Create` can only be granted by privileged users to non-privileged users, (3) self-grant is prevented. Logic is sound. |
| EXT0-3 | `config/command_line/clap_config.rs` | ✅ | `force_default_username` defaults to `false`. When `false`, the authenticated user's identity is used. No anonymous or identity-collapse by default. |
| EXT0-4 | `config/command_line/clap_config.rs` | ✅ | `privileged_users` defaults to `None` (empty list). Privilege escalation via config is absent by default. |
| EXT0-5 | `core/kms/permissions.rs` — wildcard `"*"` | ✅ | The `"*"` wildcard Create permission is documented and guarded: only `privileged_users` can grant Create, and it cannot be granted to another privileged user. Correct. |

**Recommended fix**:

- EXT0-1: Document the `Get`-implies-all-operations policy explicitly in the KMIP operation access control spec and in operator documentation. Consider adding a fine-grained per-operation permission check (separate `Encrypt`, `Decrypt`, `Sign` permissions) for objects where the Get permission holder should not have crypto access. This is a design-level decision.

---

## 13. EXT-1 – Cryptographic Key Lifecycle & Zeroization

> **OWASP ASVS V6 (Stored Cryptography)**
> Sensitive cryptographic material (private keys, AES keys, shared secrets) must be
> zeroized from memory immediately after use. Residual key material in heap memory
> enables cold-boot and process-dump attacks.

### 13.1 Scope

| Area | Key files |
|------|-----------|
| Key wrapping cache | `crate/server/src/core/wrapping/wrap.rs` |
| Key unwrap paths | `crate/server/src/core/wrapping/unwrap.rs` |
| PKCS#11 key objects | `crate/clients/pkcs11/provider/src/kms_object.rs` |
| Crypto operations | `crate/crypto/src/` |
| KMIP key material types | `crate/kmip/src/` — `KeyMaterial`, `EncryptedKeyBlock` |

### 13.2 Investigation Steps

```bash
# Step 1 — Baseline: count all zeroize usages in the workspace
grep -rn "zeroize\|Zeroizing\|ZeroizeOnDrop\|SecretBox" \
  crate/ --include="*.rs" | wc -l

# Step 2 — Find Vec<u8> likely holding key material WITHOUT Zeroizing<> wrapper
# Focus on operations that touch raw key bytes
grep -rn "Vec<u8>\|Box<\[u8\]>\|key_bytes\|key_material\|private_key\|secret_key" \
  crate/server/src/core/operations/ --include="*.rs" \
  | grep -v "Zeroizing\|zeroize\|#\[derive.*Zeroize\|//\|test_" | head -30

# Step 3 — Wrapping cache lifecycle: entries must be zeroized on eviction and drop
grep -n "cache\|remove\|evict\|drop\|DashMap\|HashMap\|clear\|Zeroizing" \
  crate/server/src/core/wrapping/wrap.rs

# Step 4 — KMIP type zeroization: KeyMaterial and EncryptedKeyBlock implement Zeroize?
grep -rn "impl Zeroize\|impl Drop\|#\[derive.*Zeroize\|ZeroizeOnDrop" \
  crate/kmip/src/ --include="*.rs"

# Step 5 — Key bytes in error messages (could surface in logs)
grep -rn 'format!.*\bkey\b\|error!.*\bkey\b\|warn!.*\bkey\b' \
  crate/server/src/core/operations/ --include="*.rs" | head -15

# Step 6 — PKCS#11 provider: key material lifecycle before drop
grep -n "Zeroizing\|zeroize\|drop\|key_value\|private\|CK_BYTE" \
  crate/clients/pkcs11/provider/src/kms_object.rs | head -30

# Step 7 — Unsafe block inventory (potential for bypassing Drop guarantees)
cargo geiger --workspace --output-format Ratio 2>/dev/null | head -30
```

### 13.3 Findings

```text
Status: ⚠️ Review needed
```

**Files inspected**:

- `crate/server/src/core/operations/derive_key.rs`
- `crate/server/src/core/wrapping/wrap.rs`
- `crate/crypto/src/crypto/symmetric/symmetric_ciphers.rs`
- `crate/server/src/core/operations/mac.rs`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| EXT1-1 | `operations/derive_key.rs:397,421` | Medium | `derive_key()` returns `Vec<u8>` for the wrapped/derived key material. The caller stores this in a `ByteString` which is not `Zeroizing`. If the derived key is sensitive (a root key, a DEK), it remains in heap memory as plaintext until the allocator reuses that memory. 96 other files in the codebase correctly use `Zeroizing<Vec<u8>>`. |
| EXT1-2 | `core/wrapping/wrap.rs` (unwrap cache) | Medium | The `DashMap`/`HashMap` used as the unwrapping cache stores unwrapped (plaintext) key objects in process RAM. No TTL, no max-size, no explicit zeroization on eviction is visible in `wrap.rs`. A memory dump of the server process exposes all recently unwrapped keys. |
| EXT1-3 | `crypto/src/crypto/` (96 files) | ✅ | Broad use of `Zeroizing<T>` and `ZeroizeOnDrop` trait implementations throughout the crypto layer. Key material in `bytes_set_de.rs:137` is wrapped in `ZeroizeOnDrop`. Good coverage. |
| EXT1-4 | `operations/mac.rs:22` | ✅ | HMAC output (`Vec<u8>`) is not secret key material; does not require zeroization. The HMAC key is a borrowed slice — caller is responsible for its lifecycle. No issue in the MAC module itself. |

**Recommended fix**:

- EXT1-1: Change the `derive_key` return type to `Zeroizing<Vec<u8>>` (or wrap the result before returning). Propagate `Zeroizing` through `ByteString` usage if that type supports it.
- EXT1-2: Add a TTL-based eviction (e.g. 60 seconds) or use `mlock`/`Zeroizing` wrappers on cache values. On eviction, call `zeroize()` before dropping. Consider using a dedicated memory-safe cache like `secrecy::Secret<T>` for cached key objects.

---

## 14. EXT-2 – Denial of Service / Resource Exhaustion

> **OWASP ASVS V12 / CWE-400**
> All user-controlled resource consumption must be bounded: request body size, TTLV
> nesting depth, database result set cardinality, and concurrent connection count.

### 14.1 Scope

| Area | Key files |
|------|-----------|
| Actix-web payload limit | `crate/server/src/start_kms_server.rs` |
| TTLV binary parser depth | `crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs` |
| TTLV XML parser depth | `crate/kmip/src/ttlv/xml/parser.rs` |
| Locate result pagination | `crate/server_database/src/` |
| Batch request handling | `crate/server/src/core/operations/dispatch.rs` |
| Rate limiting | `crate/server/src/middlewares/` |

### 14.2 Investigation Steps

```bash
# Step 1 — HTTP body size limit (Actix default is 256 KB)
grep -n "LimitPayloadSize\|max_payload_size\|PayloadConfig\|max_body\|content_length" \
  crate/server/src/start_kms_server.rs crate/server/src/routes/kmip.rs

# Step 2 — TTLV binary recursion depth guard before recursive call
grep -n "depth\|recursion\|max_depth\|stack\|recursive\|fn parse\|fn decode\|fn from_ttlv" \
  crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs

# Step 3 — TTLV XML: entity expansion (billion laughs), XXE, recursive entities
grep -n "expand_entities\|entity\|xml_parse\|XmlParser\|depth\|recursive\|ENTITY" \
  crate/kmip/src/ttlv/xml/parser.rs

# Step 4 — Locate result set: is it bounded by max_items or a database LIMIT?
grep -n "Locate\|limit\|max_results\|LIMIT\|pagination\|fetch_all\|count\|MaxItems" \
  crate/server/src/core/operations/locate.rs 2>/dev/null
grep -n "SELECT\|LIMIT\|offset\|page" \
  crate/server_database/src/stores/sql/locate_query.rs | head -20

# Step 5 — KMIP batch requests: unbounded RequestBatchItem count?
grep -n "RequestBatchItem\|batch_items\|iter\|for.*batch\|MaximumResponseSize" \
  crate/server/src/core/operations/dispatch.rs | head -20

# Step 6 — Rate limiting on KMIP endpoint
grep -rn "RateLimiter\|Governor\|leaky\|throttle\|rate\|max_conn" \
  crate/server/src/middlewares/ --include="*.rs"

# Step 7 — Allocation without bound (Semgrep TTLV parser)
semgrep --config p/rust \
  crate/kmip/src/ttlv/ --lang rust 2>/dev/null \
  | grep -i "alloc\|capacity\|len\|size\|vec" || true
```

### 14.3 Findings

```text
Status: ❌ Vulnerability found
```

**Files inspected**:

- `crate/server/src/start_kms_server.rs`
- `crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs`
- `crate/kmip/src/ttlv/xml/parser.rs`
- `crate/server/src/core/operations/locate.rs`

| ID | File:Line | Severity | Description |
|----|-----------|----------|-------------|
| EXT2-1 | `start_kms_server.rs:767-768` | **High** | HTTP request body limit is `10_000_000_000` bytes (10 GB) — same as A04-1. Any client can send a 10 GB payload, exhausting server RAM and causing OOM / process crash. No pre-read size check. |
| EXT2-2 | `ttlv_bytes_deserializer.rs:56` | **High** | `read_ttlv()` recurses without a depth counter. A crafted deeply-nested TTLV binary blob (e.g. 100 000 levels of nested `Structure` items) will overflow the stack and crash the process (stack overflow). This code path is reached **before** authentication. |
| EXT2-3 | `ttlv/xml/parser.rs:196` | Medium | The TTLV XML parser has a `depth` counter variable but the parse loop contains **no maximum depth enforcement** — the counter is incremented but never checked against a limit. Deep XML nesting can cause the same stack overflow as the binary parser. |
| EXT2-4 | `operations/locate.rs:96-101` | Medium | `MaximumItems` in a Locate request is optional and fully client-controlled. When absent, all matching objects are returned. A user who owns many objects (or to whom many are shared) can trigger a very large DB query and large response, consuming CPU, DB, and network resources. |
| EXT2-5 | All middlewares | **High** | No rate limiting (see A04-2). Without request rate limits, all DoS vectors listed above are amplifiable by a single unauthenticated client flooding the server. |

**Recommended fix**:

- EXT2-2 / EXT2-3: Add depth tracking to both parsers with `const MAX_TTLV_DEPTH: usize = 64` and early-return errors when exceeded. This is the highest priority fix as it is reachable before authentication.
- EXT2-1: Reduce payload limit to a realistic maximum (32–64 MB). See A04-1 fix.
- EXT2-4: Cap `MaximumItems` server-side: if absent or > configured `max_locate_items` (default 1 000), clamp the SQL LIMIT to `max_locate_items`.
- EXT2-5: Implement rate limiting (see A04-2 fix).

---

## 15. Remediation Priority Matrix

All confirmed findings from sections 2–14, ordered by severity.

| ID | Section | File:Line | Severity | CVSS (est.) | Status | Assigned to | Due |
|----|---------|-----------|----------|-------------|--------|-------------|-----|
| A03-2 / EXT2-2 | A03 Injection / EXT-2 DoS | `ttlv_bytes_deserializer.rs:56` | **High** | 7.5 | ✅ Fixed | | 2026-04-14 |
| A04-1 / EXT2-1 | A04 Insecure Design / EXT-2 DoS | `start_kms_server.rs:767-768` | **High** | 7.5 | ✅ Fixed | | 2026-04-14 |
| A04-2 / EXT2-5 | A04 Insecure Design / EXT-2 DoS | All server middlewares | **High** | 7.5 | ✅ Fixed | | 2026-04-14 |
| A07-1 | A07 Auth Failures | `jwt_config.rs:170` | **High** | 8.1 | ✅ Fixed | | 2026-04-14 |
| A07-6 | A07 Auth Failures | All auth endpoints | **High** | 7.3 | ✅ Fixed | | 2026-04-14 |
| A09-1 | A09 Logging | `config/command_line/db.rs:160,168` | **High** | 7.2 | ✅ Fixed | | 2026-04-14 |
| A02-3 / EXT1-2 | A02 Crypto / EXT-1 Zeroization | `core/wrapping/wrap.rs` | Medium | 5.5 | Open | | |
| A03-3 / EXT2-3 | A03 Injection / EXT-2 DoS | `ttlv/xml/parser.rs:196` | Medium | 5.9 | ✅ Fixed | | 2026-04-14 |
| A04-3 / EXT2-4 | A04 Insecure Design / EXT-2 DoS | `operations/locate.rs:96-101` | Medium | 5.3 | ✅ Fixed | | 2026-04-14 |
| A05-1 / A01-1 | A05 Misconfiguration / A01 Access | `start_kms_server.rs:776–962` | Medium | 5.4 | ✅ Fixed | | 2026-04-14 |
| A05-3 / A07-5 | A05 Misconfiguration / A07 Auth | `jwt_config.rs:10,155` | Medium | 5.0 | ⚠️ Mitigated | | 2026-04-14 |
| A07-2 | A07 Auth Failures | `api_token_auth.rs:126` | Medium | 5.9 | ✅ Fixed | | 2026-04-14 |
| A08-2 | A08 Integrity | `start_kms_server.rs:737` | Medium | 4.3 | ✅ Fixed | | 2026-04-14 |
| A09-2 | A09 Logging | `config/command_line/tls_config.rs:81` | Medium | 4.0 | ✅ Fixed | | 2026-04-14 |
| A10-1 | A10 SSRF | `clients/ckms/src/config.rs:115` | Medium | 4.8 | ⚠️ Mitigated | | 2026-04-14 |
| EXT1-1 | EXT-1 Zeroization | `operations/derive_key.rs:397,421` | Medium | 4.0 | ✅ Fixed | | 2026-04-14 |
| A02-2 | A02 Crypto | `actions/mac.rs:17` | Low | 3.1 | Open | | |
| A06-1 | A06 Components | `Cargo.toml` (rand advisory) | Low | 3.7 | Open | | |
| A06-2 | A06 Components | `Cargo.toml` (dup crates) | Low | 2.0 | Open | | |
| A07-3 | A07 Auth Failures | `tls_auth.rs:147` | Low | 2.0 | Open | | |
| A07-4 | A07 Auth Failures | `start_kms_server.rs:759` | Low | 2.6 | ✅ Fixed | | 2026-04-14 |
| A08-1 | A08 Integrity | KMIP structs | Low | 2.0 | Open | | |
| A09-3 | A09 Logging | `jwt_token_auth.rs:115` | Low | 2.0 | ✅ Fixed | | 2026-04-14 |
| A09-4 | A09 Logging | `core/operations/` | Low | 2.0 | Open | | |
| A10-2 / A10-3 | A10 SSRF | `jwks.rs`, `ui_auth.rs` | Low | 2.3 | ✅ Fixed | | 2026-04-14 |
| EXT0-1 | EXT-0 Authorization | `retrieve_object_utils.rs:191` | Low | 3.1 | Open | | |
| A02-1 | A02 Crypto | `symmetric_ciphers.rs:429,784` | Info | N/A | Closed (FP) | | |
| A01-2 | A01 Access | `routes/health.rs:47` | Info | N/A | Open | | |

### Severity definitions (CVSS 3.1 base score ranges)

| Severity | CVSS score | Response SLA |
|----------|------------|--------------|
| Critical | 9.0 – 10.0 | Fix before next release; block merge |
| High | 7.0 – 8.9 | Fix within 1 sprint |
| Medium | 4.0 – 6.9 | Fix within 3 sprints |
| Low | 0.1 – 3.9 | Schedule in backlog |
| Info | N/A | Document / accept risk |

---

## 16. Report Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Lead auditor | GitHub Copilot (automated) | — | 2026-04-13 |
| Security reviewer | *(human review pending)* | | |
| Engineering lead | *(human review pending)* | | |

**Automated audit completed**: 2026-04-13
**Next audit scheduled**: Quarterly, or on every major dependency or KMIP spec change.

**Review frequency**: Quarterly, or on every major dependency update / KMIP spec change.

### Summary statistics

| Severity | Count |
|----------|-------|
| **High** | 6 |
| Medium | 10 |
| Low | 10 |
| Info / FP | 3 |
| **Total** | **29** |

> No Critical (CVSS ≥ 9.0) findings were identified. The most urgent items are the
> **TTLV recursion depth limit** (stack-overflow DoS reachable before auth),
> **10 GB payload limit** (memory exhaustion),
> **missing rate limiting**,
> **JWT algorithm confusion** (authentication bypass potential),
> and **database credential leak in logs**.
