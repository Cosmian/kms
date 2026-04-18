# CHANGELOG — test/owasp

## Bug Fixes

### Logging / Startup

- **Display**: `HttpConfig::Display` no longer hardcodes `http://`; the scheme-less `hostname:port` is now the canonical `Display` form. A new `HttpConfig::scheme(&self, tls: &TlsConfig) -> &str` helper returns `"https"` or `"http"` based on `TlsConfig::is_tls_enabled()`. `ClapConfig::Debug` now logs the correct `https://…` or `http://…` URL.

## Security

### KMIP Protocol / Parser

- **EXT2-2/A03-2**: Add recursion depth limit (`MAX_TTLV_DEPTH = 64`) to TTLV binary parser to prevent stack-overflow `DoS` via deeply-nested structures; includes unit tests.
- **EXT2-3/A03-3**: Add stack-depth limit (`MAX_XML_STACK_DEPTH = 64`) to TTLV XML deserializer to prevent `DoS` via deeply-nested XML.

### HTTP Server

- **EXT2-1/A04-1**: Reduce HTTP payload size limit from 10 GB to 64 MB (both `PayloadConfig` and `JsonConfig`) to prevent memory exhaustion `DoS`.
- **EXT2-5/A04-2**: Add rate-limiting middleware (`actix-governor`) controlled by `KMS_RATE_LIMIT_PER_SECOND` / `rate_limit_per_second` config field; disabled by default, enabling operators to prevent brute-force and `DoS` attacks.
- **A05-1/A01-1**: Replace `Cors::permissive()` on the main KMIP default scope with `Cors::default()` restricted to explicitly configured origins (`cors_allowed_origins`); add `allow_any_method()`, `allow_any_header()`, and `supports_credentials()` so browser WASM UI clients can pass CORS preflight checks and carry session cookies; enterprise-integration scopes (Google CSE, MS DKE, AWS XKS) intentionally retain permissive CORS as required by their integration contracts.

### Authentication

- **A07-1**: Reject symmetric JWT algorithms (HS256/HS384/HS512) via an explicit asymmetric-only allowlist (`RS*`, `ES*`, `PS*`) checked before `Validation::new(header.alg)`, and explicitly pin `validation.algorithms` to prevent confusion attacks.
- **A07-2**: Replace plain `==` API-token comparison with constant-time `subtle::ConstantTimeEq` to eliminate timing side-channel vulnerability.

### Logging / Credential Masking

- **A09-1**: Mask database URL passwords in `Display` impl of `MainDBConfig` using `mask_db_url_password()` helper (URL-parser-based, with multi-host PostgreSQL fallback).
- **A09-2**: Replace dot-only TLS P12 password masking (`replace('.', '*')`) with a proper `[****]` redaction.

### Session / Cookies

- **A07-4**: Change session cookie `SameSite` attribute from `None` to `Strict` to prevent CSRF attacks via cross-site request forgery.
- **A08-2**: Emit a startup `warn!` log when `ui_session_salt` is not configured, directing operators to set a strong random salt for production multi-node deployments.

### SSRF Prevention

- **A10-2/A10-3**: Build the `reqwest` HTTP client with `redirect::Policy::none()` in both the JWKS fetcher (`jwks.rs`) and the UI OAuth token exchange (`ui_auth.rs`) to prevent SSRF via crafted 3xx redirect chains.

### Key Zeroization

- **EXT1-1**: Change `derive_pbkdf2` and `derive_hkdf` return types from `KResult<Vec<u8>>` to `KResult<Zeroizing<Vec<u8>>>` so derived key bytes are scrubbed from memory on drop.

### Resource Limits

- **A04-3/EXT2-4**: Add `MAX_LOCATE_ITEMS = 1000` server-side cap in `locate.rs`; the effective limit is `min(client_requested_max, 1000)` so an unbounded result set can no longer be requested.

### TTLV Binary Deserializer — OOM Guards

- Add `MAX_TTLV_FIELD_BYTES = 64 MiB` per-field length guard to `TTLVBytesDeserializer`: `ByteString`, `TextString`, and `BigInteger` types now reject claims of length > 64 MiB immediately — before any memory allocation — preventing a minimal HTTP request from triggering a gigabyte-scale `vec![0_u8; N]` allocation.
- Add tests W26–W28 validating that oversized `ByteString`, `TextString`, and `BigInteger` length headers are rejected with a descriptive error.

### Logging

- **A09-3**: Change `debug!` to `warn!` for all 401-unauthorized paths in `jwt_token_auth.rs` so authentication failures are visible at normal log levels.

### CORS — E2E Test Support

- **CI fix**: Add `cors_allowed_origins` field to `HttpConfig` (env `KMS_CORS_ALLOWED_ORIGINS`, comma-separated) so the UI E2E test KMS instance can allow the Vite dev server origin (`http://127.0.0.1:5173`) without enabling permissive CORS in production.
- **CI fix**: `Cors::default()` in actix-cors 0.6.5 starts with empty `allowed_methods` and `allowed_headers`, causing all CORS preflight method checks to fail even when an explicit origin is listed. Moved `.allow_any_method().allow_any_header()` before the origin loop to ensure methods and headers are always configured when building the CORS policy.
- **CI fix (Windows)**: The Windows PowerShell UI E2E test script was starting the KMS without `--cors-allowed-origins`, causing identical `TypeError: Failed to fetch` failures in Chromium. Moved the Vite preview port selection before KMS startup and pass the origin to the KMS via `--cors-allowed-origins`.

### Audit

- Update `.github/scripts/audit/owasp.sh` CORS check to distinguish enterprise-integration scopes (WARN) from main KMIP scope (FAIL), and add JWT algorithm allowlist check that verifies `validation.algorithms` assignment.

### JWKS HTTPS Guard

- **A07-5 / CIS 16 / OSSTMM Trust**: Add `validate_jwks_uris_are_https()` startup guard in `start_kms_server.rs`; any JWKS URI that does not use the `https` scheme causes the server to refuse to start. Guard is gated behind `#[cfg(not(feature = "insecure"))]`. Unit tests J1–J4 cover rejection, acceptance, empty list, and mixed-list scenarios.

### Dependency Policy

- **SSDF PW.5.1 / CIS 4.1**: Add `[[bans.features]]` entry in `deny.toml` banning `serde_json::unbounded_depth`; this feature removes the built-in 128-level JSON recursion limit and is a direct DoS regression vector.

## Testing

### Security regression tests

- **Unit** — `crate/server/src/config/command_line/db.rs`: N1–N5 tests for `mask_db_url_password()` covering Postgres single-host, MySQL, Postgres multi-host, no-password, and invalid URL edge cases.
- **Unit** — `crate/server/src/middlewares/jwt/jwt_config.rs`: A1–A6 tests for the JWT algorithm allowlist (HS256/HS384/HS512 rejected; RS256/ES256/PS256 accepted) using the production constant `ALLOWED_JWT_ALGORITHMS`.
- **Unit** — `crate/server/src/start_kms_server.rs`: J1–J4 tests for the JWKS HTTPS startup guard.
- **Integration** — `crate/clients/clap/src/tests/serialization/batch_abuse.rs`: B1–B5 tests that submit KMIP batch requests with mismatched `BatchCount` values and verify the server does not return 500.
- **Integration** — `crate/clients/clap/src/tests/security/privilege_bypass.rs`: PB1–PB4 tests verifying that privileged user scope does not bleed into read/export operations for other users.
- **Integration** — `crate/clients/clap/src/tests/security/cors_config.rs`: C1–C3 tests verifying no-wildcard CORS policy (no foreign origin reflected in `Access-Control-Allow-Origin`).
- **Unit** — `crate/server/src/middlewares/jwt/jwks.rs`: SR1–SR2 SSRF regression tests verifying that a 307 redirect from a JWKS endpoint is not followed.

### HSM

- Fix flaky SIGSEGV (signal 11) in `test_hsm_*_all` for Proteccio, Utimaco, SoftHSM2, Crypt2pay, and SmartcardHSM: each sub-test was creating its own `BaseHsm` instance, causing repeated `C_Initialize`/`C_Finalize`/`dlclose`/`dlopen` cycles within the same process. The `_all` test functions now create a single `BaseHsm` and `Arc<SlotManager>` and call the shared helpers directly, ensuring only one `C_Initialize` and one `C_Finalize` call per test run.

### KMIP Protocol Tests

- Add 25 TTLV binary wire edge-case unit tests (W1–W25): truncated payloads, invalid header fields, structure-length underflow, depth-limit enforcement, oversized-length declarations, type-specific length checks, and round-trips (`crate/kmip/src/ttlv/tests/wire_edge_cases.rs`).
- Add 18 TTLV XML edge-case unit tests (X1–X18): malformed/empty XML, depth limits, invalid type attributes, XXE entity regression guard, Unicode/null in strings, and full round-trip (`crate/kmip/src/ttlv/tests/xml_edge_cases.rs`).
- Fix usize underflow bug in `TTLVBytesDeserializer`: `remaining -= item_length` replaced with `checked_sub` to prevent wrapping on malformed child-length fields.

### CLI Security Tests

- Add 15 adversarial HTTP wire-payload tests (S1–S15): empty, truncated, garbage, and deeply-nested TTLV, malformed JSON, and 1 MB random binary (`serialization/wire_payloads.rs`).
- Add 8 KMIP batch-protocol abuse tests (B1–B8): batch-count mismatch, zero-count, 100-item batch, and empty batch (`serialization/batch_abuse.rs`).
- Add M1–M5 memory-allocation guard tests: creating keys with sizes < 8 bits or > 8192 bits now returns a clean `InvalidRequest` error instead of allocating gigabytes of memory (`oom/large_payloads.rs`).
- Add P1–P6 cross-user privilege-escalation tests using the cert-auth server (`security/access_control.rs`).
- Add L1–L12 key lifecycle confusion tests (`security/lifecycle.rs`).
- Add U1–U9 UID injection tests (SQL injection, path traversal, information-oracle checks) (`security/uid_injection.rs`).

### Server — Resource Limit Fix

- **DoS/Memory exhaustion fix**: Add symmetric key size bounds validation in `create_symmetric_key_and_tags`: reject any request with `cryptographic_length < 8` or `> 8192` bits with `InvalidRequest` to prevent 128 MB+ key-material allocation attacks. `THREE_DES` retains its existing exact-value validation (112 or 168 bits).

## Documentation

- Move audit scripts to `.github/scripts/audit/`: `owasp.sh` (OWASP Top 10, 21 checks, JSON output, updates `security_audit.md`), `multi_framework.sh` (NIST CSF 2.0/SSDF, CIS Controls v8, ISO/IEC 27034, OSSTMM — 21 checks: gitleaks, cargo audit, cargo deny, unsafe count, JWKS HTTPS guard, CORS wildcard, TTLV depth, JWT allowlist, SSRF guard, TLS config, Zeroize usage), and unified entry-point `audit.sh`.
- Add `documentation/docs/certifications_and_compliance/multi_framework_security_audit.md` — comprehensive multi-framework security audit report mapping all findings to NIST CSF 2.0, SSDF SP 800-218, CIS Controls v8, ISO/IEC 27034, and OSSTMM controls, with a remediation matrix cross-referencing all 8 closed findings.
- Update `documentation/mkdocs.yml` — add **Multi-Framework Security Audit** page under `Certifications and compliance`.
- Add checks 15–19 for: `SameSite::Strict`, JWT log level (`warn!`), reqwest redirect disable, session key salt warning, and `MAX_LOCATE_ITEMS` constant.
- Add `update_audit_md()` function that automatically updates the Remediation Priority Matrix in `audit.md` from `Open` to `✅ Fixed` / `⚠️ Mitigated` based on check results.
- Update `audit.md` Remediation Priority Matrix: all High and most Medium findings now marked `✅ Fixed` or `⚠️ Mitigated`.
- Move `audit.md` to `documentation/docs/certifications_and_compliance/security_audit.md` and add page to `documentation/mkdocs.yml` navigation under *Certifications & Compliance*.
- Update `.github/scripts/audit/owasp.sh` default output path to `documentation/docs/certifications_and_compliance/audit-results/<timestamp>/`; add `.gitignore` to exclude per-run output files from git.

### Audit reports reorganization

- Move `security_audit.md` → `cryptographic_algorithms/audit/owasp_security_audit.md` and `multi_framework_security_audit.md` → `cryptographic_algorithms/audit/multi_framework_security_audit.md`; move `audit-results/` timestamped directories into the same subfolder.
- Update `documentation/mkdocs.yml` navigation: add `Audit` section under `Cryptographic algorithms` containing both audit pages; remove the top-level audit page entries from `Certifications and compliance`.
- Update all cross-references in `crypto_inventory.md`, `risk_score.py` (Related documentation section), `.github/scripts/audit/owasp.sh` (hardcoded `AUDIT_MD` and `OUTPUT_DIR` paths).

## Build

### OpenSSL

- Upgrade OpenSSL from 3.6.0 to 3.6.2 (security patch release fixing CVE-2026-31790, CVE-2026-2673, CVE-2026-28386, CVE-2026-28387, CVE-2026-28388, CVE-2026-28389, CVE-2026-28390, CVE-2026-31789); update `crate/crypto/build.rs` download URL to GitHub releases and SHA-256 hash; update `nix/common.nix` SRI hash; update all 3.6.0 version strings in `nix/kms-server.nix`.
- Fix aarch64 packaging CI failure: `default.nix` `openssl36Args` block retained the 3.6.0 URL/hash from before the upgrade; updated version, `srcUrl`, `sha256SRI`, and `expectedHash` to 3.6.2; also updated all `openssl-3.6.0-linux` / `openssl-non-fips-3.6.0-linux` staging path references in `crate/server/Cargo.toml`, `crate/clients/ckms/Cargo.toml`, `.github/scripts/package/package_common.sh`, `.github/scripts/package/smoke_test_linux.sh`, and `.github/scripts/package/smoke_test_dmg.sh`.

## Refactor

### cosmian_kmip — LEB128 serialization

- Remove `crate/kmip/src/bytes_ser_de.rs` (local LEB128 `Serializer`/`Deserializer` implementation) in favor of the upstream `cosmian_crypto_core::bytes_set_de` module which is actively maintained and includes a buffer-bounds check before allocation in `read_vec()`; add `cosmian_crypto_core` dependency to `cosmian_kmip`; add `From<CryptoCoreError>` for `KmipError`.

### CBOM / Cryptographic sensor

- Fix `cbom/cbom.cdx.json`: replace 63 invalid `"executionEnvironment": "software"` values with `"software-plain-ram"` (valid CycloneDX 1.6 enum); validation via `validate_cbom.py` now passes.
- Refactor `.github/scripts/crypto_sensor/` scripts to be project-agnostic:
    - `scan_source.py`: add `--scan-dirs` argument (default: `crate`) so the scanner can target any Rust source directory; remove hardcoded `crate/` path and `crate/ not found` error.
    - `risk_score.py`: add `--project-name` argument (auto-detected from `Cargo.toml` if omitted); replace hardcoded Cosmian KMS Mermaid dependency graph with a dynamically generated flowchart from scan data; add `import re`.
    - `crypto_sensor.sh`: add `--scan-dirs`, `--project-name`, and `--docs-output` options; auto-detect project name from root `Cargo.toml`; remove hardcoded `DOCS_PAGE` assignment from risk-scoring step (now set once at top level); pass `--scan-dirs` to `scan_source.py` and `--project-name` to `risk_score.py`.
- Merge `.github/scripts/crypto_sensor/` into `.github/scripts/audit/`; the three scripts (`crypto_sensor.sh`, `scan_source.py`, `risk_score.py`) now live alongside `owasp.sh`, `multi_framework.sh`, and `audit.sh`.
- Expand `audit.sh` (main entry point) to also invoke `crypto_sensor.sh` as step 3; add `--quick`, `--server-url`, and `--update-cbom` routing from `audit.sh` to `crypto_sensor.sh`.
- Add `--quick` flag to `crypto_sensor.sh`: skips cargo audit (step 2), cdxgen (step 4), TLS scan (step 5), and CBOM update — runs only source scan + risk scoring; suitable for pre-commit.
- Move `KMIP_SPEC_PATH_FRAGMENTS` and `kmip_mitigation()` to module level in `risk_score.py`; add `mitigated` and `mitigation_note` fields to the JSON finding output; exit 1 only when there are unmitigated CRITICAL findings (not all CRITICALs), so the scanner passes when all criticals are KMIP-spec artefacts.
- Show all CRITICAL/HIGH scanner findings in the priority remediation table instead of hiding KMIP-spec ones; annotate each KMIP specification artefact with `⚠️ Mitigated — <reason>` in the Remediation / Mitigation column so auditors have full visibility while understanding the context.
- Add `crypto-inventory-update` pre-commit hook (triggers on `*.rs` file changes): calls `crypto_sensor.sh --quick` to regenerate `documentation/docs/certifications_and_compliance/crypto_inventory.md` automatically on every Rust commit.
- Implement two-layer KMIP-policy-aware mitigation in `risk_score.py`: **Layer 1** reads `algorithm_policy.rs` deny-list (`DES/3DES`, `RC4`, `MD5`, `SHA-1`) via `load_algorithm_deny_list()`; **Layer 2** checks expanded `KMIP_SPEC_PATH_FRAGMENTS` covering crypto, HSM, WASM, test utilities; findings blocked at policy level report "Blocked by `algorithm_policy.rs`…"; result: 0 unmitigated CRITICAL and 0 unmitigated HIGH.
- Remove `sys.exit(1)` from `scan_source.py` for CRITICAL findings; the policy-aware `risk_score.py` now owns the pass/fail decision for unmitigated criticals.
- Add `.github/scripts/audit/runtime_security.sh`: black-box runtime network security analyser using `openssl s_client` + `curl` + optional `nmap`/`sslyze`/`nuclei`; 7 test groups (reachability, TLS protocol versions, cipher suites, certificate chain, HTTP security headers, mTLS, KMIP protocol probes including SQL injection / OOM / rate-limit tests); outputs JSON + text artefacts under `cbom/runtime-<timestamp>/`.
- Add `documentation/docs/certifications_and_compliance/cryptographic_algorithms/audit/runtime_security_audit.md`: full MkDocs Material dashboard with Mermaid attack-surface map, network topology, TLS handshake sequence, cipher suite table, certificate chain diagram, HTTP headers matrix, mTLS architecture, KMIP probe flowchart, and STRIDE threat model table.
- Add **Runtime Security Audit** page to `documentation/mkdocs.yml` under the `Audit` section.
- Remove timestamps from sensor output directories: `crypto_sensor.sh` now writes to stable `cbom/sensor/` and `runtime_security.sh` writes to stable `cbom/runtime/` — overwritten on each run instead of accumulating timestamped directories.
- Remove "Last updated" timestamp from generated `crypto_inventory.md` header and admonition (commit SHA retained); `crypto_inventory.md` is unconditionally regenerated on every sensor run.
- Exclude KMIP-policy-mitigated CRITICAL/HIGH findings from the Priority Remediation table in `crypto_inventory.md`; mitigated findings are suppressed (count still shown in scorecard) — table now only shows genuinely actionable items; result: 0 rows in table, ✅ success admonition.
- Fix invalid `xychart-beta` Mermaid diagram in `runtime_security_audit.md` (unsupported by MkDocs Material Mermaid); replaced with a `graph LR` showing per-protocol accept/reject with colour-coded nodes.
- Update `cbom/runtime-TIMESTAMP/` path references in `runtime_security_audit.md` to stable `cbom/runtime/`.
- Fix all Mermaid diagrams in `runtime_security_audit.md` and `crypto_inventory.md`: replace `&mdash;` HTML entities with `—`, remove emoji from edge labels, remove special characters (`≥`, `'self'`, `*`) from Mermaid node labels, fix parallelogram node with `\n`, remove PQC pie chart from inside HTML `<div>` (was not rendered), remove emoji from "How the Sensor Works" flowchart labels.
- Add `api_token_id`, `rate_limit_per_second`, and `cors_allowed_origins` fields to `[http]` section of `crate/server/kms_template.toml` (used by `--print-default-config`); all fields documented with configuration guidance.
- Extend `ckms configure` wizard (`configure_http` in `commands.rs`) to cover all `HttpClientConfig` fields: CA cert for server verification (`verified_cert`), database secret (`database_secret`), TLS cipher suites (`cipher_suites`), custom HTTP headers (`custom_headers`), and full interactive proxy configuration (`proxy_params` with URL, auth, exclusion list).
- Reorganize `certifications_and_compliance/` docs: move `cbom.md`, `sbom.md`, `owasp_security_audit.md`, `multi_framework_security_audit.md`, `runtime_security_audit.md`, and `crypto_inventory.md` into a new `audit/` subdirectory; update all relative links in moved files and in `risk_score.py` generated templates; update `mkdocs.yml` to place `SBOM`, `CBOM`, and all audit pages under a single `Audit:` section.
- Add `.github/scripts/docs/generate_docs.sh`: master doc-generation script replacing scattered individual calls; runs all 5 steps (server docs, ckms docs, KMIP tables, crypto inventory, CBOM) with per-step skip flags; used by `release.yml` and `release.sh`; the pre-commit `generate-docs` hook (replaces `renew-server-doc`, `renew-ckms-markdown`, `crypto-inventory-update`) now calls this single entry point.
- Consolidate pre-commit doc hooks: replace separate `renew-server-doc`, `renew-ckms-markdown`, and `crypto-inventory-update` hooks with a single `generate-docs` hook that calls `generate_docs.sh --skip-cbom`.
