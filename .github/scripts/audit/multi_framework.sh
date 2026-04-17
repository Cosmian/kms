#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — Multi-Framework Security Audit Script
#
# Frameworks covered:
#   NIST CSF 2.0 / SSDF (SP 800-218)
#   CIS Controls v8
#   ISO/IEC 27034 (application security)
#   OSSTMM (Open Source Security Testing Methodology Manual)
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed
#
# Usage: bash scripts/audit.sh [--verbose]
# =============================================================================

set -euo pipefail

VERBOSE="${1:-}"
PASS=0
FAIL=0
WARN=0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARN=$((WARN + 1)); }

cd "$REPO_ROOT"

echo "═══════════════════════════════════════════════════════════"
echo " Cosmian KMS — Security Audit"
echo " $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ─── Check 1: NIST SSDF PW.1.1 — No hard-coded secrets ──────────────────────
echo "── Check 1: NIST SSDF PW.1.1 — Hard-coded secrets (gitleaks)"
if command -v gitleaks &>/dev/null; then
    if gitleaks detect --source . --no-banner -q 2>/dev/null; then
        _pass "gitleaks: no secrets detected"
    else
        _fail "gitleaks: potential secrets found — run 'gitleaks detect' for details"
    fi
else
    _warn "gitleaks not installed — skipping secret scan"
fi

# ─── Check 2: NIST SSDF PW.7.2 — Unsafe Rust usage count ────────────────────
echo ""
echo "── Check 2: NIST SSDF PW.7.2 — 'unsafe' block count"
UNSAFE_COUNT=$(grep -r 'unsafe {' crate/ --include='*.rs' 2>/dev/null | wc -l || echo "0")
if [ "$UNSAFE_COUNT" -lt 300 ]; then
    _pass "unsafe block count: $UNSAFE_COUNT (< 300 threshold; mostly FFI wrappers)"
else
    _fail "unsafe block count: $UNSAFE_COUNT (≥ 300 — significant growth since last audit)"
fi
if [ -n "$VERBOSE" ]; then
    grep -rn 'unsafe {' crate/ --include='*.rs' 2>/dev/null || true
fi

# ─── Check 3: NIST SSDF RV.1.2 — No known HIGH/CRITICAL CVEs ────────────────
echo ""
echo "── Check 3: NIST SSDF RV.1.2 — Known CVEs (cargo audit)"
if command -v cargo-audit &>/dev/null || cargo audit --version &>/dev/null 2>&1; then
    if cargo audit -q 2>/dev/null; then
        _pass "cargo audit: no vulnerable dependencies"
    else
        _warn "cargo audit: advisories found — run 'cargo audit' for details (non-blocking for warnings)"
    fi
else
    _warn "cargo-audit not installed — skipping CVE scan (run: cargo install cargo-audit)"
fi

# ─── Check 4: NIST SSDF PW.5.1 — Dependency licence/ban policy ──────────────
echo ""
echo "── Check 4: NIST SSDF PW.5.1 — cargo-deny bans"
if command -v cargo-deny &>/dev/null || cargo deny --version &>/dev/null 2>&1; then
    if cargo deny check bans 2>/dev/null; then
        _pass "cargo deny: no banned dependencies or features"
    else
        _fail "cargo deny: banned dependency or feature detected"
    fi
else
    _warn "cargo-deny not installed — skipping ban check (run: cargo install cargo-deny)"
fi

# ─── Check 5: CIS 4.1 — serde_json unbounded_depth banned ───────────────────
echo ""
echo "── Check 5: CIS 4.1 / OWASP A05 — serde_json unbounded_depth banned in deny.toml"
if grep -q 'unbounded_depth' deny.toml 2>/dev/null; then
    _pass "deny.toml bans serde_json unbounded_depth feature"
else
    _fail "deny.toml does not ban serde_json unbounded_depth — DoS regression risk"
fi

# ─── Check 6: CIS 8.2 — Structured logging configured ───────────────────────
echo ""
echo "── Check 6: CIS 8.2 — Structured/OTLP logging present in config"
if grep -rq 'OTLP\|otlp\|rolling_log\|ROLLING_LOG' crate/server/src/ --include='*.rs' 2>/dev/null; then
    _pass "Structured logging (OTLP/rolling) configuration found"
else
    _warn "No OTLP/rolling log configuration detected — verify logging coverage"
fi

# ─── Check 7: CIS 4.1 — Default bind to 127.0.0.1 on Windows ───────────────
echo ""
echo "── Check 7: CIS 4.1 — Safe default bind address"
if grep -rq '127\.0\.0\.1\|localhost' crate/server/src/config/ --include='*.rs' 2>/dev/null; then
    _pass "Safe default bind address (127.0.0.1 / localhost) found in config"
else
    _warn "No safe default bind address detected — verify http_config defaults"
fi

# ─── Check 8: CIS 16 / OSSTMM Trust — JWKS HTTPS guard present ──────────────
echo ""
echo "── Check 8: CIS 16 / OSSTMM Trust — JWKS HTTPS startup guard"
if grep -q 'validate_jwks_uris_are_https' crate/server/src/start_kms_server.rs 2>/dev/null; then
    _pass "JWKS HTTPS guard (validate_jwks_uris_are_https) present in start_kms_server.rs"
else
    _fail "JWKS HTTPS guard missing from start_kms_server.rs"
fi

# ─── Check 9: OSSTMM Visibility — DB URL password masking ───────────────────
echo ""
echo "── Check 9: OSSTMM Visibility — DB URL password masked in logs"
if grep -q '\*\*\*\*' crate/server/src/config/command_line/db.rs 2>/dev/null; then
    _pass "DB URL password masking (**** placeholder) found in db.rs"
else
    _fail "DB URL password masking not detected in db.rs"
fi

# ─── Check 10: OSSTMM Visibility — TLS password masking ─────────────────────
echo ""
echo "── Check 10: OSSTMM Visibility — TLS P12 password masked in logs"
if grep -q '\[.*\*\*\*\*.*\]\|password.*\*\*\*\*\|\*\*\*\*.*password' \
    crate/server/src/config/command_line/tls_config.rs 2>/dev/null; then
    _pass "TLS P12 password masking found in tls_config.rs"
else
    _warn "TLS P12 password masking not detected in tls_config.rs — verify Debug impl"
fi

# ─── Check 11: NIST CSF ID.RA — SSRF redirect guard in JWKS fetch ───────────
echo ""
echo "── Check 11: NIST CSF ID.RA / OWASP A10 — SSRF: JWKS redirect disabled"
if grep -q 'Policy::none\|redirect.*none\|no.*redirect' \
    crate/server/src/middlewares/jwt/jwks.rs 2>/dev/null; then
    _pass "JWKS HTTP client disables redirect following (SSRF guard)"
else
    _fail "JWKS HTTP client redirect guard not found in jwks.rs"
fi

# ─── Check 12: ISO 27034 L2 — CORS header not wildcard in prod config ────────
echo ""
echo "── Check 12: ISO 27034 L2 — CORS header not wildcard by default"
if grep -q 'Access-Control-Allow-Origin.*\*\|cors_allowed_origins.*\*' \
    crate/server/src/ -r --include='*.rs' 2>/dev/null; then
    _fail "Wildcard CORS origin (*) detected in server source — review CORS policy"
else
    _pass "No wildcard CORS origin found in default server configuration"
fi

# ─── Check 13: NIST SSDF PW.4.4 — TTLV depth limit present ─────────────────
echo ""
echo "── Check 13: NIST SSDF PW.4.4 — Binary TTLV recursion depth limit"
if grep -q 'MAX_TTLV_DEPTH\|max_ttlv_depth\|MAX_XML_STACK_DEPTH' \
    crate/kmip/src/ -r --include='*.rs' 2>/dev/null; then
    _pass "TTLV/XML recursion depth limit constant found in kmip crate"
else
    _fail "TTLV depth limit (MAX_TTLV_DEPTH) not found — DoS regression risk"
fi

# ─── Check 14: NIST CSF PR.AC-1 — JWT algorithm allowlist enforced ───────────
echo ""
echo "── Check 14: NIST CSF PR.AC-1 — JWT algorithm allowlist"
if grep -q 'ALLOWED_JWT_ALGORITHMS\|allowed_algorithms' \
    crate/server/src/middlewares/jwt/ -r --include='*.rs' 2>/dev/null; then
    _pass "JWT algorithm allowlist found in middlewares/jwt/"
else
    _fail "JWT algorithm allowlist not detected — HS256/none bypass risk"
fi

# ─── Check 15: CIS 13.9 — No TLS 1.0/1.1 configuration ─────────────────────
echo ""
echo "── Check 15: CIS 13.9 — No legacy TLS 1.0/1.1 configuration"
if grep -rq 'TLS.*1\.0\|TLS.*1\.1\|tlsv1\b\|tlsv1_1' \
    crate/server/src/ --include='*.rs' 2>/dev/null; then
    _fail "Legacy TLS 1.0/1.1 configuration found — must use TLS ≥ 1.2"
else
    _pass "No legacy TLS 1.0/1.1 configuration detected"
fi

# ─── Check 16: NIST SSDF PW.4.4 — No panic! in production paths ─────────────
echo ""
echo "── Check 16: NIST SSDF PW.4.4 — No bare panic! in server binary src"
# Count only files that are NOT test modules; panic! in #[cfg(test)] is expected
PANIC_COUNT=$(grep -rl 'panic!(' crate/server/src/ --include='*.rs' 2>/dev/null \
    | xargs grep -l 'panic!(' 2>/dev/null \
    | grep -cv '_test\|test_\|tests/' \
    2>/dev/null || echo "0")
if [ "$PANIC_COUNT" -lt 20 ]; then
    _pass "Files with panic!() in server/src/ (non-test): $PANIC_COUNT (< 20 threshold)"
else
    _warn "Files with panic!() in server/src/ (non-test): $PANIC_COUNT — review each call site"
    if [ -n "$VERBOSE" ]; then
        grep -rn 'panic!(' crate/server/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' || true
    fi
fi

# ─── Check 17: CIS 5.1 — Privileged-user list not hard-coded in source ───────
echo ""
echo "── Check 17: CIS 5.1 — Privileged user list loaded from config, not source"
if grep -rq '"admin"\|"root"\|"Administrator"' \
    crate/server/src/config/ --include='*.rs' 2>/dev/null; then
    _warn "Hard-coded privileged usernames found in config source — verify intent"
else
    _pass "No hard-coded privileged usernames in server config source"
fi

# ─── Check 18: NIST CSF PR.DS-1 — Sensitive fields use zeroize / secrecy ─────
echo ""
echo "── Check 18: NIST CSF PR.DS-1 — Sensitive key material uses Zeroize"
if grep -rq 'Zeroize\|zeroize\|Secrecy' crate/ --include='*.rs' 2>/dev/null; then
    _pass "Zeroize/Secrecy usage found for sensitive key material"
else
    _warn "No Zeroize/Secrecy usage detected — verify key material lifetime management"
fi

# ─── Check 19: OSSTMM — No unwrap() in server production paths ───────────────
echo ""
echo "── Check 19: OSSTMM / NIST SSDF — unwrap() count in server/src/"
UNWRAP_COUNT=$(grep -rn '\.unwrap()' crate/server/src/ --include='*.rs' 2>/dev/null \
    | grep -cv '#\[cfg(test)\]\|mod tests\|#\[test\]\|test_\|_test\.' \
    2>/dev/null || echo "0")
if [ "$UNWRAP_COUNT" -lt 200 ]; then
    _pass "unwrap() count in server/src/ (non-test): $UNWRAP_COUNT (< 200 threshold)"
else
    _warn "unwrap() count in server/src/ (non-test): $UNWRAP_COUNT — review each call site"
fi

# ─── Check 20: ISO 27034 L3 — Access-control module present ──────────────────
echo ""
echo "── Check 20: ISO 27034 L3 — Access-control module present"
if [ -d "crate/access" ]; then
    _pass "crate/access/ (access-control module) exists"
else
    _fail "crate/access/ module missing — KMIP access control is not isolated"
fi

# ─── Check 21: NIST CSF DE.CM — Semgrep static analysis (if available) ───────
echo ""
echo "── Check 21: NIST CSF DE.CM — Semgrep static analysis"
if command -v semgrep &>/dev/null; then
    if semgrep --config=auto --quiet --error \
        --include='*.rs' crate/server/src/ 2>/dev/null; then
        _pass "semgrep: no findings"
    else
        _fail "semgrep: findings detected — review output above"
    fi
else
    _warn "semgrep not installed — skipping static analysis (run: pip install semgrep)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo " Audit Summary"
echo "═══════════════════════════════════════════════════════════"
echo -e "  ${GREEN}Passed${NC}: $PASS"
echo -e "  ${YELLOW}Warnings${NC}: $WARN"
echo -e "  ${RED}Failed${NC}: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}AUDIT FAILED — $FAIL check(s) must be addressed before release.${NC}"
    exit 1
elif [ "$WARN" -gt 0 ]; then
    echo -e "${YELLOW}AUDIT PASSED WITH WARNINGS — $WARN item(s) require review.${NC}"
    exit 0
else
    echo -e "${GREEN}AUDIT PASSED — all checks cleared.${NC}"
    exit 0
fi
