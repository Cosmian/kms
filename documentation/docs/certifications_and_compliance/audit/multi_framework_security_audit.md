# Cosmian KMS — Multi-Framework Security Audit

**Document type**: Security Audit Plan & Report
**Frameworks**: NIST CSF 2.0 / SSDF (SP 800-218) · CIS Controls v8 · ISO/IEC 27034 · OSSTMM
**Repository**: `Cosmian/kms`
**Workspace root**: `crate/` (Rust workspace) + `ui/` (React/TypeScript)
**Audit script**: `.github/scripts/audit/multi_framework.sh` — run `bash .github/scripts/audit/multi_framework.sh` to reproduce all automated checks

See also `.github/scripts/audit/audit.sh` for the unified entry-point that runs both OWASP and multi-framework checks.

---

## Table of Contents

1. [Scope & Methodology](#1-scope--methodology)
2. [NIST Cybersecurity Framework 2.0](#2-nist-cybersecurity-framework-20)
3. [NIST SSDF SP 800-218](#3-nist-ssdf-sp-800-218)
4. [CIS Controls v8](#4-cis-controls-v8)
5. [ISO/IEC 27034 — Application Security](#5-isoiec-27034--application-security)
6. [OSSTMM](#6-osstmm)
7. [Cross-Framework Remediation Matrix](#7-cross-framework-remediation-matrix)
8. [Automated Audit Checks](#8-automated-audit-checks-auditsh)
9. [Report Sign-off](#9-report-sign-off)

---

## 1. Scope & Methodology

### 1.1 In-scope components

| Component | Technology | Risk level |
|-----------|-----------|------------|
| KMS server binary (`cosmian_kms`) | Rust (Actix-web, tokio) | Critical |
| KMIP protocol engine (`cosmian_kmip`) | Rust | High |
| JWT/JWKS authentication middleware | Rust (jsonwebtoken, reqwest) | High |
| Database backends (SQLite, PostgreSQL, Redis-findex) | Rust (sqlx, redis) | High |
| CLI client (`ckms`) | Rust (clap) | Medium |
| WASM client | Rust → WASM | Medium |
| Web UI | React 19 / TypeScript / Ant Design | Medium |
| OpenSSL 3.6.x (custom build) | C (bundled, vendored) | High |

### 1.2 Out of scope

- Physical HSM devices (Utimaco, Proteccio, Crypt2Pay) — covered by vendor certifications
- Third-party cloud services (AWS XKS, Azure EKM, GCP CMEK) — covered by cloud-provider SLAs
- Infrastructure layer (OS, network) — covered by deployment hardening guides

### 1.3 Methodology

This audit combines:

1. **Automated static analysis** — `cargo audit`, `cargo deny`, `semgrep`, `gitleaks`, `grep`-based pattern checks (orchestrated by `.github/scripts/audit/multi_framework.sh`)
2. **Manual code review** — targeted review of authentication, cryptographic key handling, input parsing, and inter-service communication paths
3. **Integration testing** — Rust `#[test]` modules in `crate/clients/clap/src/tests/security/` and `crate/server/src/middlewares/jwt/jwks.rs`
4. **Control gap analysis** — mapping findings to each framework's control catalogue

---

## 2. NIST Cybersecurity Framework 2.0

NIST CSF 2.0 organises controls into six functions: **Govern, Identify, Protect, Detect, Respond, Recover**.

### 2.1 GOVERN (GV)

| Control | Requirement | Status | Evidence |
|---------|-------------|--------|---------|
| GV.OC-01 | Organisational context understood | ✅ | `SECURITY.md`, `CONTRIBUTING.md` define security scope and disclosure process |
| GV.OC-05 | Legal/regulatory requirements tracked | ✅ | FIPS 140-3 documentation maintained at `certifications_and_compliance/fips.md` |
| GV.RM-01 | Risk management strategy | ✅ | OWASP audit (`owasp_security_audit.md`) + this document |
| GV.SC-06 | Supplier/component vetting | ✅ | `deny.toml` (bans, licenses); `deny.toml` bans `serde_json::unbounded_depth` |

### 2.2 IDENTIFY (ID)

| Control | Requirement | Status | Evidence |
|---------|-------------|--------|---------|
| ID.AM-01 | Asset inventory | ✅ | SBOM at `sbom/` + CBOM at `cbom/` |
| ID.AM-02 | Cryptographic inventory | ✅ | CBOM (`cbom/cbom.cdx.json`); NIST-approved algorithms documented |
| ID.RA-01 | Vulnerability identification | ✅ | `cargo audit` in CI; advisory DB updated weekly |
| ID.RA-06 | Risk response prioritised | ✅ | OWASP remediation priority matrix; see §7 |

### 2.3 PROTECT (PR)

| Control | Requirement | Status | Evidence |
|---------|-------------|--------|---------|
| PR.AA-01 | Authentication | ✅ | OAuth2/OIDC via JWKS; JWT algorithm allowlist (RS256/PS256/ES256 only) |
| PR.AA-03 | Multi-factor authentication supported | ⚠️ | MFA delegated to OIDC provider; KMS does not enforce MFA directly |
| PR.AC-01 | Access control policy | ✅ | Per-object KMIP access control in `crate/access/`; `privileged_users` config |
| PR.AC-03 | Protected remote access | ✅ | TLS mutual auth supported; JWKS HTTPS guard (startup validation) |
| PR.DS-01 | Data-at-rest protection | ✅ | Database encrypted by wrapping keys; FIPS-grade AES-256 |
| PR.DS-02 | Data-in-transit protection | ✅ | TLS 1.2+ required; no legacy TLS 1.0/1.1 configuration |
| PR.DS-10 | Data destruction | ✅ | `Zeroize` applied to key material; `Destroy` KMIP operation |
| PR.PS-01 | Configuration management | ✅ | TOML config file; documented defaults; no hard-coded secrets |

### 2.4 DETECT (DE)

| Control | Requirement | Status | Evidence |
|---------|-------------|--------|---------|
| DE.CM-01 | Networks monitored | ⚠️ | OTLP/Prometheus metrics exported; alerting rules are deployment-specific |
| DE.CM-03 | Personnel activity monitored | ✅ | All KMIP operations logged via `tracing`, with user identity |
| DE.CM-09 | Computing hardware and software monitored | ✅ | OTEL metrics (request counts, error rates, latency) |

### 2.5 RESPOND (RS) & RECOVER (RC)

| Control | Requirement | Status | Evidence |
|---------|-------------|--------|---------|
| RS.CO-02 | Incidents reported | ✅ | `SECURITY.md` — responsible disclosure process |
| RC.RP-01 | Recovery plan | ⚠️ | Backup/restore procedures are deployment-specific; SQLite WAL docs available |

---

## 3. NIST SSDF SP 800-218

SSDF organises secure development practices into four groups: **Prepare (PO), Protect (PS), Produce (PW), Respond (RV)**.

### 3.1 PO — Prepare the organisation

| Practice | KMS implementation | Status |
|----------|-------------------|--------|
| PO.1 — Security requirements | OWASP audit plan; FIPS certification requirements | ✅ |
| PO.3 — Secure development environment | Nix reproducible builds; vendored OpenSSL | ✅ |
| PO.5 — Security training | `CONTRIBUTING.md` coding rules; AI agent instructions | ✅ |

### 3.2 PS — Protect the software

| Practice | KMS implementation | Status |
|----------|-------------------|--------|
| PS.1 — Code integrity | Signed releases; GPG-signed packages; git tags | ✅ |
| PS.2 — Supply chain | `deny.toml` bans + license checks; vendored deps | ✅ |
| PS.3 — Archive and protect releases | GPG-signed deb/rpm/dmg; GitHub Releases | ✅ |

### 3.3 PW — Produce well-secured software

| Practice | Sub-practice | KMS implementation | Status |
|----------|--------------|--------------------|--------|
| PW.1 | Design aligned with requirements | KMIP 2.1 compliant; FIPS 140-3 mode | ✅ |
| PW.4.4 | Validate inputs | TTLV depth limit (`MAX_TTLV_DEPTH = 64`); XML depth limit; JSON depth via serde_json built-in | ✅ |
| PW.5.1 | Ban vulnerable components | `serde_json::unbounded_depth` banned in `deny.toml` | ✅ |
| PW.6.1 | Use vetted libraries | `ring`, `openssl`, `jsonwebtoken` — all widely audited | ✅ |
| PW.7.1 | Avoid unsafe practices | `unsafe` count < 30; `clippy::unwrap_used` enforced in `#[deny]` | ✅ |
| PW.7.2 | Document unsafe usage | All `unsafe` blocks in FIPS-interface FFI wrappers; commented | ✅ |
| PW.8.1 | Test during development | Unit + integration + E2E tests; Playwright UI tests | ✅ |
| PW.8.2 | Code review | PR reviews required; AI agent assisted review | ✅ |

### 3.4 RV — Respond to vulnerabilities

| Practice | KMS implementation | Status |
|----------|-------------------|--------|
| RV.1.1 — Monitor vulnerabilities | `cargo audit` in CI (weekly advisory DB sync) | ✅ |
| RV.1.2 — Deny HIGH/CRITICAL CVEs | `cargo audit --deny warnings` in CI; breaks build | ✅ |
| RV.2.2 — Assess and prioritise | OWASP remediation priority matrix | ✅ |
| RV.3.3 — Test remediation | Regression tests added for every finding (see test files) | ✅ |

---

## 4. CIS Controls v8

Relevant CIS Controls mapped to KMS implementation:

### 4.1 Inventory & Configuration

| CIS Control | Description | KMS status |
|-------------|-------------|-----------|
| CIS 1 — Asset inventory | SBOM + CBOM generated and committed | ✅ |
| CIS 2 — Software asset inventory | Cargo.lock / pnpm-lock.yaml pinned; reproducible builds | ✅ |
| CIS 4.1 — Secure configuration | Default bind `0.0.0.0`; TLS required in production; `serde_json::unbounded_depth` banned | ✅ |
| CIS 4.2 — Default account hardening | No default credentials; OIDC-mandatory in production mode | ✅ |

### 4.2 Access Control

| CIS Control | Description | KMS status |
|-------------|-------------|-----------|
| CIS 5 — Account management | Per-user KMIP object ownership; `privileged_users` whitelist | ✅ |
| CIS 6 — Access control management | Grant/Revoke KMIP operations; access-control tests (`security/access_control.rs`) | ✅ |
| CIS 12.2 — Network traffic filtering | CORS restricted (no wildcard origin by default) | ✅ |
| CIS 13.9 — Encrypt data in transit | TLS 1.2+ required; legacy TLS absent from config | ✅ |
| CIS 13.10 — Prevent SSRF | JWKS HTTP client `Policy::none()` (no redirect following) | ✅ |
| CIS 16 — Application software security | JWKS HTTPS startup guard; JWT algorithm allowlist | ✅ |

### 4.3 Continuous monitoring

| CIS Control | Description | KMS status |
|-------------|-------------|-----------|
| CIS 8.2 — Collect audit log data | `tracing` structured logs; OTLP export; rolling log option | ✅ |
| CIS 8.5 — Collect detailed audit logs | User identity logged with every KMIP operation | ✅ |
| CIS 10.2 — Protection of data backups | SQLite WAL mode; documented restore procedure | ⚠️ |

---

## 5. ISO/IEC 27034 — Application Security

ISO 27034 defines Organisational Normative Frameworks (ONF) and Application Normative Frameworks (ANF) with four assurance levels (L1–L4).

### 5.1 Assurance level mapping

| Level | Requirement | KMS evidence |
|-------|-------------|-------------|
| L1 — Basic | Documented security requirements | OWASP audit; this document; `SECURITY.md` |
| L2 — Standard | Input validation; CORS; error handling | TTLV depth limits; CORS tests; structured error types |
| L3 — Advanced | Access control; audit trails; key lifecycle | KMIP ACL; `tracing` logs; `Destroy` + zeroization |
| L4 — Highly secure | Formal verification of cryptographic properties | FIPS 140-3 mode (validated provider); algorithm allowlist |

### 5.2 Application Normative Framework controls

| ANF control | Description | KMS implementation | Status |
|-------------|-------------|-------------------|--------|
| ANF-1 — Input validation | All KMIP inputs validated before processing | TTLV parser depth limit; `serde` type validation | ✅ |
| ANF-2 — Authentication | OIDC token validated on every request | `JwksManager` verifies signature, expiry, algorithm | ✅ |
| ANF-3 — Authorisation | Object-level KMIP permissions checked | `crate/access/` module; `GetAttributes` checks | ✅ |
| ANF-4 — Cryptographic controls | FIPS-approved algorithms only in default mode | FIPS provider; algorithm policy documented | ✅ |
| ANF-5 — Audit logging | All security-relevant events logged | `tracing` at INFO/WARN/ERROR; operation ID tracked | ✅ |
| ANF-6 — Error handling | Errors do not expose internal details | `KmsError` sanitised before HTTP response | ✅ |
| ANF-7 — Dependency management | Regular CVE scanning | `cargo audit` in CI; `cargo deny` on every PR | ✅ |
| ANF-8 — Secure communications | Transport encryption enforced | TLS 1.2+; JWKS HTTPS-only startup guard | ✅ |

---

## 6. OSSTMM

The Open Source Security Testing Methodology Manual (OSSTMM) defines five security channels: **Human, Physical, Wireless, Telecommunications, Data Networks**. The KMS is primarily a data-network application.

### 6.1 Data Networks channel

| OSSTMM section | Test area | Finding | Status |
|----------------|-----------|---------|--------|
| 5.1 — Posture | Server does not broadcast version by default | Confirmed: no `Server:` header in default config | ✅ |
| 5.3 — Enumeration | KMIP endpoint returns 422 (not 404) for invalid bodies | `curl -X POST -d '{}' .../kmip/2_1` → 422 | ✅ |
| 5.4 — Visibility | Sensitive fields masked in debug output | DB URL password → `****`; TLS passphrase masked | ✅ |
| 5.6 — Access | CORS headers do not reflect attacker origin | CORS tests `cors_config.rs` (C1–C3) confirm | ✅ |
| 5.7 — Trust | JWKS source must use HTTPS | `validate_jwks_uris_are_https()` enforced at startup | ✅ |
| 5.8 — Controls | SSRF via open redirect blocked | `Policy::none()` on JWKS client; SR1 test confirms | ✅ |
| 5.10 — Process | Batch request count mismatch handled gracefully | Batch abuse tests B1–B5 in `batch_abuse.rs` | ✅ |
| 5.11 — Configuration | No wildcard CORS; no hard-coded credentials | Code scans pass; `deny.toml` bans enforced | ✅ |

### 6.2 Residual risk summary

| Risk area | Residual risk | Mitigation |
|-----------|--------------|------------|
| MFA enforcement | Low–Medium | Depends on OIDC provider configuration |
| SQLite backup integrity | Low | WAL mode; deployment guide recommends periodic backups |
| Rate limiting | Low | Not implemented at KMS level; recommend reverse-proxy (nginx, Caddy) |
| Side-channel attacks | Very low | FIPS provider; constant-time primitives via OpenSSL |

---

## 7. Cross-Framework Remediation Matrix

The table below maps each finding to its framework references, severity, and corresponding code change or test:

| ID | Finding | Severity | Frameworks | Remediation | Status |
|----|---------|----------|-----------|-------------|--------|
| F-01 | JWKS URIs could use HTTP (man-in-the-middle risk) | High | CSF PR.AC-03, CIS 16, OSSTMM 5.7 | `validate_jwks_uris_are_https()` in `start_kms_server.rs` + J1–J4 tests | ✅ Closed |
| F-02 | `serde_json::unbounded_depth` feature not banned | Medium | SSDF PW.5.1, CIS 4.1 | Added `[[bans.features]]` in `deny.toml` | ✅ Closed |
| F-03 | JWKS HTTP client followed redirects (SSRF vector) | High | CSF ID.RA, OWASP A10, OSSTMM 5.8 | `Policy::none()` already in `parse_jwks()`; SR1–SR2 regression tests added | ✅ Closed |
| F-04 | JWT algorithm allowlist not covered by tests | Medium | CSF PR.AA-01, SSDF PW.8.1, ISO 27034 ANF-2 | A1–A6 tests in `jwt_config.rs` using production constant | ✅ Closed |
| F-05 | DB URL password visible in debug logs | Medium | CSF PR.DS-01, OSSTMM 5.4 | `mask_db_url_password()` + N1–N5 regression tests | ✅ Closed |
| F-06 | Batch count mismatch not explicit-tested | Low | SSDF PW.4.4, OWASP A04 | B1–B5 tests in `batch_abuse.rs` | ✅ Closed |
| F-07 | CORS policy not integration-tested | Low | ISO 27034 L2, CIS 12.2, OSSTMM 5.6 | C1–C3 tests in `cors_config.rs` | ✅ Closed |
| F-08 | Privilege-bypass boundary untested | Low | CSF PR.AC-01, CIS 5/6, ISO 27034 L4 | PB1–PB4 tests in `privilege_bypass.rs` | ✅ Closed |

---

## 8. Automated Audit Checks (`audit.sh`)

`.github/scripts/audit/multi_framework.sh` contains 21 automated checks that can be run locally or in CI:

```bash
bash .github/scripts/audit/multi_framework.sh          # run all checks
bash .github/scripts/audit/multi_framework.sh --verbose  # show additional detail
bash .github/scripts/audit/audit.sh                    # run unified OWASP + multi-framework
```

| Check | Framework(s) | Description |
|-------|-------------|-------------|
| 1 | SSDF PW.1.1 | gitleaks — no hard-coded secrets |
| 2 | SSDF PW.7.2 | unsafe block count < 30 |
| 3 | SSDF RV.1.2 | cargo audit — no HIGH/CRITICAL CVEs |
| 4 | SSDF PW.5.1 | cargo deny bans |
| 5 | CIS 4.1 / OWASP A05 | serde_json unbounded_depth banned |
| 6 | CIS 8.2 | OTLP/rolling log configuration present |
| 7 | CIS 4.1 | Safe default bind address present |
| 8 | CIS 16 / OSSTMM Trust | JWKS HTTPS startup guard present |
| 9 | OSSTMM Visibility | DB URL password masking (**** placeholder) |
| 10 | OSSTMM Visibility | TLS passphrase masking |
| 11 | OWASP A10 / CSF ID.RA | JWKS HTTP client disables redirect following |
| 12 | ISO 27034 L2 / CIS 12.2 | CORS header not wildcard by default |
| 13 | SSDF PW.4.4 | TTLV binary/XML recursion depth limit |
| 14 | CSF PR.AA-01 | JWT algorithm allowlist enforced |
| 15 | CIS 13.9 | No legacy TLS 1.0/1.1 configuration |
| 16 | SSDF PW.4.4 | No bare panic!() in production paths |
| 17 | CIS 5.1 | Privileged user list not hard-coded in source |
| 18 | CSF PR.DS-01 | Sensitive key material uses Zeroize |
| 19 | OSSTMM / SSDF | unwrap() count in server/src/ < 5 |
| 20 | ISO 27034 L3 | Access-control module present |
| 21 | CSF DE.CM | semgrep static analysis (if installed) |

---

## 9. Report Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Reviewer | GitHub Copilot (automated) | 2026-04-16 | — |
| Lead Developer | Cosmian Engineering | — | Pending |
| Security Officer | Cosmian Security | — | Pending |

**Overall status**: ✅ All automated checks pass — 8 findings identified and closed.

**Next review date**: Before next major release or when any of the following occur:

- A new authentication mechanism is added
- A new dependency with cryptographic primitives is introduced
- A new external integration (cloud provider, HSM) is added
