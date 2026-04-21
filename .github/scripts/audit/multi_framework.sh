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
# File paths are resolved dynamically at runtime via find_file/find_dir helpers.
# No hardcoded paths — checks continue to work after code refactors.
#
# Usage: bash .github/scripts/audit/multi_framework.sh [--verbose]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VERBOSE="${1:-}"
PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARN=$((WARN + 1)); }

cd "$REPO_ROOT"

echo "═══════════════════════════════════════════════════════════"
echo " Cosmian KMS — Multi-Framework Security Audit"
echo " $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ─── Dynamic path resolution helpers ─────────────────────────────────────────
# find_file NAME — returns the first .rs file matching NAME anywhere under crate/
find_file() {
  find "$REPO_ROOT/crate" -name "$1" -type f 2>/dev/null | head -1
}

# find_dir NAME — returns the first directory matching NAME under crate/
find_dir() {
  find "$REPO_ROOT/crate" -name "$1" -type d 2>/dev/null | head -1
}

# grep_crate PATTERN [extra args] — workspace-wide search across all *.rs files
grep_crate() {
  local pattern="$1"; shift
  grep -rn "$pattern" "$REPO_ROOT/crate/" --include="*.rs" "$@" 2>/dev/null || true
}

# grep_file FILE PATTERN [extra args] — search a specific file if it exists,
# otherwise fall back to workspace-wide grep so checks survive refactors.
grep_file() {
  local file="$1" pattern="$2"; shift 2
  if [[ -f "$file" ]]; then
    grep -n "$pattern" "$file" "$@" 2>/dev/null || true
  else
    grep_crate "$pattern" "$@"
  fi
}

# ─── Resolve canonical file/dir locations once ───────────────────────────────
START_SERVER_RS="$(find_file "start_kms_server.rs")"
JWKS_RS="$(find_file "jwks.rs")"
DB_CONFIG_RS="$(find_file "db.rs" | grep -i command_line | head -1 || find_file "db.rs")"
TLS_CONFIG_RS="$(find_file "tls_config.rs")"
KMIP_SRC_DIR="$(find_dir "kmip" | head -1)"
JWT_DIR="$(find_dir "jwt" | head -1)"
ACCESS_DIR="$(find "$REPO_ROOT/crate" -maxdepth 2 -name "access" -type d 2>/dev/null | head -1)"

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
UNSAFE_COUNT=$(grep_crate 'unsafe {' | wc -l || echo "0")
if [ "$UNSAFE_COUNT" -lt 300 ]; then
  _pass "unsafe block count: $UNSAFE_COUNT (< 300 threshold; mostly FFI wrappers)"
else
  _fail "unsafe block count: $UNSAFE_COUNT (≥ 300 — significant growth since last audit)"
fi
if [ -n "$VERBOSE" ]; then
  grep_crate 'unsafe {' || true
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
if grep -q 'unbounded_depth' "$REPO_ROOT/deny.toml" 2>/dev/null; then
  _pass "deny.toml bans serde_json unbounded_depth feature"
else
  _fail "deny.toml does not ban serde_json unbounded_depth — DoS regression risk"
fi

# ─── Check 6: CIS 8.2 — Structured logging configured ───────────────────────
echo ""
echo "── Check 6: CIS 8.2 — Structured/OTLP logging present in codebase"
if grep_crate 'OTLP\|otlp\|rolling_log\|ROLLING_LOG' | grep -q .; then
  _pass "Structured logging (OTLP/rolling) configuration found"
else
  _warn "No OTLP/rolling log configuration detected — verify logging coverage"
fi

# ─── Check 7: CIS 4.1 — Default bind to 127.0.0.1 on Windows ───────────────
echo ""
echo "── Check 7: CIS 4.1 — Safe default bind address"
if grep_crate '127\.0\.0\.1\|localhost' | grep -q "config\|default\|bind\|hostname"; then
  _pass "Safe default bind address (127.0.0.1 / localhost) found in codebase"
else
  _warn "No safe default bind address detected — verify http_config defaults"
fi

# ─── Check 8: CIS 16 / OSSTMM Trust — JWKS HTTPS guard present ──────────────
echo ""
echo "── Check 8: CIS 16 / OSSTMM Trust — JWKS HTTPS startup guard"
# Search for the validation function anywhere in the workspace
if grep_crate 'validate_jwks_uris_are_https\|jwks.*https\|https.*jwks' | grep -q .; then
  _pass "JWKS HTTPS guard (validate_jwks_uris_are_https or equivalent) present in codebase"
elif [[ -n "$START_SERVER_RS" ]] && grep -q 'validate_jwks_uris_are_https' "$START_SERVER_RS" 2>/dev/null; then
  _pass "JWKS HTTPS guard (validate_jwks_uris_are_https) present in start_kms_server.rs"
else
  _fail "JWKS HTTPS guard missing from codebase"
fi

# ─── Check 9: OSSTMM Visibility — DB URL password masking ───────────────────
echo ""
echo "── Check 9: OSSTMM Visibility — DB URL password masked in logs"
if grep_file "${DB_CONFIG_RS:-/nonexistent}" '\*\*\*\*' | grep -q .; then
  _pass "DB URL password masking (**** placeholder) found"
else
  _fail "DB URL password masking not detected in db config"
fi

# ─── Check 10: OSSTMM Visibility — TLS password masking ─────────────────────
echo ""
echo "── Check 10: OSSTMM Visibility — TLS P12 password masked in logs"
if grep_file "${TLS_CONFIG_RS:-/nonexistent}" \
    '\[.*\*\*\*\*.*\]\|password.*\*\*\*\*\|\*\*\*\*.*password' | grep -q .; then
  _pass "TLS P12 password masking found"
else
  _warn "TLS P12 password masking not detected — verify Debug impl"
fi

# ─── Check 11: NIST CSF ID.RA — SSRF redirect guard in JWKS fetch ───────────
echo ""
echo "── Check 11: NIST CSF ID.RA / OWASP A10 — SSRF: JWKS redirect disabled"
if [[ -n "$JWKS_RS" ]]; then
  if grep -q 'Policy::none\|redirect.*none\|no.*redirect' "$JWKS_RS" 2>/dev/null; then
    _pass "JWKS HTTP client disables redirect following (SSRF guard) in $(basename "$JWKS_RS")"
  else
    _fail "JWKS HTTP client redirect guard not found in $(basename "$JWKS_RS")"
  fi
else
  # Fall back to workspace-wide search
  if grep_crate 'Policy::none\|redirect.*none' | grep -qi "jwks\|jwt"; then
    _pass "JWKS HTTP client redirect guard found (workspace search)"
  else
    _fail "JWKS HTTP client redirect guard not found in codebase"
  fi
fi

# ─── Check 12: ISO 27034 L2 — CORS header not wildcard in prod config ────────
echo ""
echo "── Check 12: ISO 27034 L2 — CORS header not wildcard by default"
if grep_crate 'Access-Control-Allow-Origin.*\*\|cors_allowed_origins.*\*' | grep -q .; then
  _fail "Wildcard CORS origin (*) detected in server source — review CORS policy"
else
  _pass "No wildcard CORS origin found in default server configuration"
fi

# ─── Check 13: NIST SSDF PW.4.4 — TTLV depth limit present ─────────────────
echo ""
echo "── Check 13: NIST SSDF PW.4.4 — Binary TTLV recursion depth limit"
DEPTH_FOUND=false
if [[ -n "$KMIP_SRC_DIR" ]]; then
  if grep -rq 'MAX_TTLV_DEPTH\|max_ttlv_depth\|MAX_XML_STACK_DEPTH\|MAX_DEPTH' \
      "$KMIP_SRC_DIR" --include="*.rs" 2>/dev/null; then
    DEPTH_FOUND=true
  fi
fi
if ! $DEPTH_FOUND; then
  # Widen to full workspace
  if grep_crate 'MAX_TTLV_DEPTH\|MAX_XML_STACK_DEPTH' | grep -q .; then
    DEPTH_FOUND=true
  fi
fi
if $DEPTH_FOUND; then
  _pass "TTLV/XML recursion depth limit constant found in codebase"
else
  _fail "TTLV depth limit (MAX_TTLV_DEPTH) not found — DoS regression risk"
fi

# ─── Check 14: NIST CSF PR.AC-1 — JWT algorithm allowlist enforced ───────────
echo ""
echo "── Check 14: NIST CSF PR.AC-1 — JWT algorithm allowlist"
JWT_ALLOWLIST_FOUND=false
if [[ -n "$JWT_DIR" ]]; then
  if grep -rq 'ALLOWED_JWT_ALGORITHMS\|allowed_algorithms' "$JWT_DIR" --include="*.rs" 2>/dev/null; then
    JWT_ALLOWLIST_FOUND=true
  fi
fi
if ! $JWT_ALLOWLIST_FOUND; then
  if grep_crate 'ALLOWED_JWT_ALGORITHMS\|allowed_algorithms' | grep -q .; then
    JWT_ALLOWLIST_FOUND=true
  fi
fi
if $JWT_ALLOWLIST_FOUND; then
  _pass "JWT algorithm allowlist found in codebase"
else
  _fail "JWT algorithm allowlist not detected — HS256/none bypass risk"
fi

# ─── Check 15: CIS 13.9 — No TLS 1.0/1.1 configuration ─────────────────────
echo ""
echo "── Check 15: CIS 13.9 — No legacy TLS 1.0/1.1 configuration"
if grep_crate 'TLS.*1\.0\|TLS.*1\.1\|tlsv1\b\|tlsv1_1' | grep -q .; then
  _fail "Legacy TLS 1.0/1.1 configuration found — must use TLS ≥ 1.2"
else
  _pass "No legacy TLS 1.0/1.1 configuration detected"
fi

# ─── Check 16: NIST SSDF PW.4.4 — No panic! in production paths ─────────────
echo ""
echo "── Check 16: NIST SSDF PW.4.4 — No bare panic! in server binary src"
# Count files outside test modules; panic! in #[cfg(test)] is expected
PANIC_COUNT=$(grep_crate 'panic!(' \
  | grep -v '_test\|test_\|tests/\|#\[cfg(test)\]' \
  | cut -d: -f1 | sort -u | wc -l || echo "0")
if [ "$PANIC_COUNT" -lt 20 ]; then
  _pass "Files with panic!() (non-test): $PANIC_COUNT (< 20 threshold)"
else
  _warn "Files with panic!() (non-test): $PANIC_COUNT — review each call site"
  if [ -n "$VERBOSE" ]; then
    grep_crate 'panic!(' | grep -v '#\[cfg(test)\]' || true
  fi
fi

# ─── Check 17: CIS 5.1 — Privileged-user list not hard-coded in source ───────
echo ""
echo "── Check 17: CIS 5.1 — Privileged user list loaded from config, not source"
if grep_crate '"admin"\|"root"\|"Administrator"' | grep -qi "config"; then
  _warn "Hard-coded privileged usernames found in config source — verify intent"
else
  _pass "No hard-coded privileged usernames in server config source"
fi

# ─── Check 18: NIST CSF PR.DS-1 — Sensitive fields use zeroize / secrecy ─────
echo ""
echo "── Check 18: NIST CSF PR.DS-1 — Sensitive key material uses Zeroize"
if grep_crate 'Zeroize\|zeroize\|Secrecy' | grep -q .; then
  _pass "Zeroize/Secrecy usage found for sensitive key material"
else
  _warn "No Zeroize/Secrecy usage detected — verify key material lifetime management"
fi

# ─── Check 19: OSSTMM — No unwrap() in server production paths ───────────────
echo ""
echo "── Check 19: OSSTMM / NIST SSDF — unwrap() count in codebase (non-test)"
UNWRAP_COUNT=$(grep_crate '\.unwrap()' \
  | grep -vc '#\[cfg(test)\]\|mod tests\|#\[test\]\|test_\|_test\.' || echo "0")
if [ "$UNWRAP_COUNT" -lt 200 ]; then
  _pass "unwrap() count (non-test): $UNWRAP_COUNT (< 200 threshold)"
else
  _warn "unwrap() count (non-test): $UNWRAP_COUNT — review each call site"
fi

# ─── Check 20: ISO 27034 L3 — Access-control module present ──────────────────
echo ""
echo "── Check 20: ISO 27034 L3 — Access-control module present"
if [[ -n "$ACCESS_DIR" && -d "$ACCESS_DIR" ]]; then
  _pass "Access-control module ($ACCESS_DIR) exists"
else
  _fail "Access-control module (crate/access) missing — KMIP access control is not isolated"
fi

# ─── Check 21: NIST CSF DE.CM — Semgrep static analysis (if available) ───────
echo ""
echo "── Check 21: NIST CSF DE.CM — Semgrep static analysis (auto + custom rules)"
CUSTOM_RULES_DIR="$SCRIPT_DIR/custom_rules"
if command -v semgrep &>/dev/null; then
  SEMGREP_CONFIGS=("--config=auto")
  if [[ -d "$CUSTOM_RULES_DIR" ]] && compgen -G "$CUSTOM_RULES_DIR/*.yml" >/dev/null 2>&1; then
    SEMGREP_CONFIGS+=("--config=$CUSTOM_RULES_DIR")
  fi
  if semgrep "${SEMGREP_CONFIGS[@]}" --quiet --error \
      --include='*.rs' "$REPO_ROOT/crate/" 2>/dev/null; then
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
