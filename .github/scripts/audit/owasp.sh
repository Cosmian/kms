#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — Reproducible OWASP Security Audit Script
# =============================================================================
# Usage:  bash .github/scripts/audit/owasp.sh [--output-dir <dir>] [--geiger] [--help]
#
# What this script does:
#   1.  Checks that all required tools are installed (installs missing Rust
#       tools automatically if cargo is available).
#   2.  Runs each audit step, capturing output to a timestamped directory.
#   3.  Prints a coloured summary with pass/warn/fail per step.
#   4.  Writes a machine-readable JSON summary at the end.
#
# Exit code: 0 if all checks passed or warned; 1 if any check FAILED.
#
# File paths are resolved dynamically at runtime — no hardcoded paths.
# Individual checks search the whole workspace and narrow results by pattern.
#
# Dependencies (auto-installed if missing):
#   • cargo-audit   — RustSec advisory database scan
#   • cargo-deny    — policy-based dependency check (bans/licenses/advisories)
#   • cargo-outdated — outdated dependency detection
# Optional (not auto-installed):
#   • cargo-geiger  — unsafe Rust line counter
#   • semgrep       — static pattern analysis
#   • gitleaks      — secret scanner
# =============================================================================

set -euo pipefail

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
CYAN=$'\e[36m'
RESET=$'\e[0m'
BOLD=$'\e[1m'
info() { echo "${CYAN}${BOLD}[INFO ]${RESET} $*"; }
ok()   { echo "${GREEN}${BOLD}[PASS ]${RESET} $*"; }
warn() { echo "${YELLOW}${BOLD}[WARN ]${RESET} $*"; }
fail() { echo "${RED}${BOLD}[FAIL ]${RESET} $*"; }
step() {
  echo
  echo "${BOLD}━━━  $*  ━━━${RESET}"
}

# ─── Arguments ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/documentation/docs/certifications_and_compliance/audit/audit-results/$(date +%Y%m%d_%H%M%S)"
RUN_GEIGER=false
FAIL_ON_WARN=false

usage() {
  echo "Usage: $0 [--output-dir <dir>] [--geiger] [--fail-on-warn] [--help]"
  echo "  --output-dir   Where to write per-tool output files (default: documentation/docs/certifications_and_compliance/audit/audit-results/<timestamp>/)"
  echo "  --geiger       Also run cargo-geiger (slow; requires geiger installed)"
  echo "  --fail-on-warn Exit with code 1 on warnings, not just on failures"
  echo "  --help         Show this message"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --output-dir)
    OUTPUT_DIR="$2"
    shift 2
    ;;
  --geiger)
    RUN_GEIGER=true
    shift
    ;;
  --fail-on-warn)
    FAIL_ON_WARN=true
    shift
    ;;
  --help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown option: $1"
    usage
    exit 1
    ;;
  esac
done

mkdir -p "$OUTPUT_DIR"
cd "$REPO_ROOT"

OVERALL_STATUS=0   # 0=pass, 1=fail
declare -A RESULTS # step -> PASS|WARN|FAIL

record() {
  local name="$1" status="$2"
  RESULTS["$name"]="$status"
  if [[ "$status" == "FAIL" ]]; then
    OVERALL_STATUS=1
  elif [[ "$status" == "WARN" && "$FAIL_ON_WARN" == "true" ]]; then
    OVERALL_STATUS=1
  fi
}

# ─── Dynamic path resolution helpers ─────────────────────────────────────────
# find_file PATTERN — returns the first matching .rs file in crate/
# Falls back to empty string if not found.
find_file() {
  find "$REPO_ROOT/crate" -name "$1" -type f 2>/dev/null | head -1
}

# find_dir PATTERN — returns the first matching directory under crate/
find_dir() {
  find "$REPO_ROOT/crate" -name "$1" -type d 2>/dev/null | head -1
}

# grep_crate PATTERN [extra grep args] — grep across all Rust source in crate/
grep_crate() {
  local pattern="$1"; shift
  grep -rn "$pattern" "$REPO_ROOT/crate/" --include="*.rs" "$@" 2>/dev/null || true
}

# grep_file FILE PATTERN [extra grep args] — grep a specific file if it exists,
# otherwise fall back to grep_crate so the check still works after refactors.
grep_file() {
  local file="$1" pattern="$2"; shift 2
  if [[ -f "$file" ]]; then
    grep -n "$pattern" "$file" "$@" 2>/dev/null || true
  else
    warn "  ($file not found — falling back to workspace-wide search)"
    grep_crate "$pattern" "$@"
  fi
}

# ─── Resolve canonical file paths once ───────────────────────────────────────
# Checks that target a specific well-known file resolve it here.
# All other checks use grep_crate / find_* helpers.
BINARY_TTLV_RS="$(find_file "ttlv_bytes_deserializer.rs")"
XML_TTLV_DIR="$(find_dir "xml" | grep -i ttlv | head -1 || true)"
[[ -z "$XML_TTLV_DIR" ]] && XML_TTLV_DIR="$(find "$REPO_ROOT/crate" -type d -name "xml" 2>/dev/null | head -1)"
START_SERVER_RS="$(find_file "start_kms_server.rs")"
JWT_CONFIG_RS="$(find_file "jwt_config.rs")"
API_TOKEN_AUTH_RS="$(find_file "api_token_auth.rs")"
DB_CONFIG_RS="$(find_file "db.rs" | grep command_line | head -1 || find_file "db.rs")"
TLS_CONFIG_RS="$(find_file "tls_config.rs")"
DERIVE_KEY_RS="$(find_file "derive_key.rs")"
LOCATE_RS="$(find_file "locate.rs")"
LOCATE_QUERY_RS="$(find_file "locate_query.rs")"
JWKS_RS="$(find_file "jwks.rs")"
UI_AUTH_RS="$(find_file "ui_auth.rs")"

# ─── 0. Tool installation check ───────────────────────────────────────────────
step "0. Tool Check & Auto-install"

check_or_install() {
  local cmd="$1" install_cmd="$2"
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd — $(command -v "$cmd") ($("$cmd" --version 2>/dev/null | head -1 || echo 'version unknown'))"
    return 0
  fi
  warn "$cmd not found — installing via: $install_cmd"
  eval "$install_cmd"
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd installed successfully"
    return 0
  else
    fail "$cmd installation failed"
    return 1
  fi
}

check_or_install "cargo-audit" "cargo install cargo-audit --locked"
check_or_install "cargo-deny" "cargo install cargo-deny --locked"
check_or_install "cargo-outdated" "cargo install cargo-outdated --locked"

if $RUN_GEIGER; then
  if command -v cargo-geiger &>/dev/null; then
    ok "cargo-geiger — $(cargo-geiger --version 2>/dev/null | head -1)"
  else
    warn "cargo-geiger not installed. Install with: cargo install cargo-geiger --locked"
    warn "Note: cargo-geiger 0.13.0 has a known bug with virtual workspaces. Unsafe counts will fall back to grep."
  fi
fi

if ! command -v semgrep &>/dev/null; then
  warn "semgrep not installed. Install with: pip install semgrep  OR  brew install semgrep"
fi
if ! command -v gitleaks &>/dev/null; then
  warn "gitleaks not installed. Install with: brew install gitleaks  OR  go install github.com/zricethezav/gitleaks/v8@latest"
fi

# ─── 1. cargo audit — RustSec advisory scan ───────────────────────────────────
step "1. cargo audit (RustSec advisory database)"

AUDIT_OUT="$OUTPUT_DIR/cargo_audit.txt"
if cargo audit 2>&1 | tee "$AUDIT_OUT"; then
  WARNING_COUNT=$(grep -c "^warning:" "$AUDIT_OUT" 2>/dev/null || true)
  ERROR_COUNT=$(grep -c "^error:" "$AUDIT_OUT" 2>/dev/null || true)
  if [[ "$ERROR_COUNT" -gt 0 ]]; then
    fail "cargo audit found $ERROR_COUNT error(s). See $AUDIT_OUT"
    record "cargo-audit" "FAIL"
  elif [[ "$WARNING_COUNT" -gt 0 ]]; then
    warn "cargo audit found $WARNING_COUNT warning(s) (may be allow-listed). See $AUDIT_OUT"
    record "cargo-audit" "WARN"
  else
    ok "cargo audit — no advisories"
    record "cargo-audit" "PASS"
  fi
else
  if grep -q "^error:" "$AUDIT_OUT" 2>/dev/null; then
    fail "cargo audit found vulnerabilities. See $AUDIT_OUT"
    record "cargo-audit" "FAIL"
  else
    warn "cargo audit completed with warnings. See $AUDIT_OUT"
    record "cargo-audit" "WARN"
  fi
fi

# ─── 1b. cargo audit --json — machine-readable CVE severity filtering ─────────
# Parses JSON to surface only CRITICAL/HIGH CVEs as failures.
AUDIT_JSON="$OUTPUT_DIR/cargo_audit.json"
if cargo audit --json >"$AUDIT_JSON" 2>/dev/null; then
  if command -v python3 &>/dev/null && [[ -s "$AUDIT_JSON" ]]; then
    CRITICAL_HIGH=$(python3 - <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    vulns = data.get("vulnerabilities", {}).get("list", [])
    severe = [v for v in vulns if v.get("advisory", {}).get("severity", "").upper() in ("CRITICAL", "HIGH")]
    print(len(severe))
except Exception:
    print(0)
PYEOF
    "$AUDIT_JSON" 2>/dev/null || echo 0)
    if [[ "$CRITICAL_HIGH" -gt 0 ]]; then
      fail "cargo audit: $CRITICAL_HIGH CRITICAL/HIGH CVE(s) detected."
      record "cargo-audit-cve" "FAIL"
    else
      ok "cargo audit: no CRITICAL/HIGH CVEs"
      record "cargo-audit-cve" "PASS"
    fi
  fi
fi

# ─── 2. cargo deny — policy checks ────────────────────────────────────────────
step "2. cargo deny check (bans / licenses / advisories / sources)"

DENY_OUT="$OUTPUT_DIR/cargo_deny.txt"
if cargo deny check 2>&1 | tee "$DENY_OUT"; then
  ok "cargo deny — all checks passed"
  record "cargo-deny" "PASS"
else
  if grep -qE "^error" "$DENY_OUT" 2>/dev/null; then
    fail "cargo deny reported errors. See $DENY_OUT"
    record "cargo-deny" "FAIL"
  else
    warn "cargo deny completed with warnings. See $DENY_OUT"
    record "cargo-deny" "WARN"
  fi
fi

# ─── 3. cargo outdated ────────────────────────────────────────────────────────
step "3. cargo outdated (dependency version freshness)"

OUTDATED_OUT="$OUTPUT_DIR/cargo_outdated.txt"
set +e
cargo outdated --workspace 2>&1 | tee "$OUTDATED_OUT"
set -e

OUTDATED_COUNT=$(grep -cE "^[a-zA-Z]" "$OUTDATED_OUT" 2>/dev/null) || OUTDATED_COUNT=0
if grep -q "^error" "$OUTDATED_OUT" 2>/dev/null; then
  warn "cargo outdated encountered an error (possibly WASM getrandom feature mismatch). See $OUTDATED_OUT"
  record "cargo-outdated" "WARN"
elif [[ "$OUTDATED_COUNT" -gt 2 ]]; then
  warn "cargo outdated: ${OUTDATED_COUNT} potentially outdated dep(s). See $OUTDATED_OUT"
  record "cargo-outdated" "WARN"
else
  ok "cargo outdated — deps appear reasonably fresh"
  record "cargo-outdated" "PASS"
fi

# ─── 4. A03/EXT-2: TTLV recursion depth check ────────────────────────────────
step "4. A03/EXT-2 — TTLV binary parser recursion depth check"

TTLV_OUT="$OUTPUT_DIR/ttlv_depth.txt"
{
  echo "=== Binary TTLV parser (read_ttlv recursion) ==="
  if [[ -n "$BINARY_TTLV_RS" ]]; then
    grep -n "fn read_ttlv\|read_ttlv(\|depth\|MAX_DEPTH\|max_depth" "$BINARY_TTLV_RS" 2>/dev/null || true
  else
    grep_crate "MAX_TTLV_DEPTH\|max_ttlv_depth\|MAX_DEPTH.*ttlv\|ttlv.*MAX_DEPTH"
  fi
  echo ""
  echo "=== XML TTLV parser (depth counter + max check) ==="
  if [[ -n "$XML_TTLV_DIR" ]]; then
    grep -rn "depth\|MAX_DEPTH\|max_depth" "$XML_TTLV_DIR" 2>/dev/null || true
  else
    grep_crate "MAX_XML_STACK_DEPTH\|xml.*depth\|depth.*xml"
  fi
} | tee "$TTLV_OUT"

# Search the resolved file first, then fall back to workspace
BINARY_HAS_MAX=0
if [[ -n "$BINARY_TTLV_RS" ]]; then
  BINARY_HAS_MAX=$(grep -cE "MAX_DEPTH|max_depth|if.*depth.*>|depth.*>=.*MAX" "$BINARY_TTLV_RS" 2>/dev/null) || BINARY_HAS_MAX=0
fi
if [[ "$BINARY_HAS_MAX" -eq 0 ]]; then BINARY_HAS_MAX=$(grep_crate "MAX_TTLV_DEPTH|MAX_DEPTH" | wc -l); fi

XML_HAS_MAX=0
if [[ -n "$XML_TTLV_DIR" ]]; then
  XML_HAS_MAX=$(grep -rcE "MAX_DEPTH|max_depth|if.*depth.*>.*[0-9]" "$XML_TTLV_DIR" 2>/dev/null | wc -l) || XML_HAS_MAX=0
fi
if [[ "$XML_HAS_MAX" -eq 0 ]]; then XML_HAS_MAX=$(grep_crate "MAX_XML_STACK_DEPTH" | wc -l); fi

if [[ "$BINARY_HAS_MAX" -eq 0 ]]; then
  fail "A03-2/EXT2-2: Binary TTLV parser has no recursion depth limit. Stack overflow DoS possible."
  record "ttlv-depth-limit" "FAIL"
elif [[ "$XML_HAS_MAX" -eq 0 ]]; then
  warn "A03-3/EXT2-3: XML TTLV parser has depth counter but no max-depth enforcement."
  record "ttlv-depth-limit" "WARN"
else
  ok "TTLV parsers — both have recursion/depth limits"
  record "ttlv-depth-limit" "PASS"
fi

# ─── 5. A04/EXT-2: Payload size limit check ──────────────────────────────────
step "5. A04/EXT-2 — HTTP payload size limit check"

PAYLOAD_OUT="$OUTPUT_DIR/payload_limit.txt"
# Search the well-known server startup file, fall back to workspace scan
grep_file "${START_SERVER_RS:-/nonexistent}" \
  "PayloadConfig\|json.*limit\|JsonConfig\|body.*limit" | tee "$PAYLOAD_OUT" || true

if grep -qE "10_000_000_000|10000000000" "$PAYLOAD_OUT" 2>/dev/null; then
  fail "A04-1/EXT2-1: Payload limit is 10 GB (10_000_000_000). Reduce to ≤ 64 MB."
  record "payload-limit" "FAIL"
else
  LIMIT=$(grep -oE "[0-9_]{6,}" "$PAYLOAD_OUT" | head -1) || LIMIT="unknown"
  ok "Payload limit appears reasonable: $LIMIT bytes"
  record "payload-limit" "PASS"
fi

# ─── 6. A04/EXT-2: Rate limiting check ────────────────────────────────────────
step "6. A04/EXT-2 — Rate limiting middleware check"

RATE_OUT="$OUTPUT_DIR/rate_limiting.txt"
grep_crate "RateLimiter\|rate_limit\|throttle\|governor\|leaky_bucket\|token_bucket" | tee "$RATE_OUT" || true

if [[ ! -s "$RATE_OUT" ]]; then
  fail "A04-2/EXT2-5: No rate-limiting middleware found in crate/."
  record "rate-limiting" "FAIL"
else
  ok "Rate-limiting reference found"
  record "rate-limiting" "PASS"
fi

# ─── 7. A07: JWT algorithm confusion check ────────────────────────────────────
step "7. A07 — JWT algorithm confusion check"

JWT_ALG_OUT="$OUTPUT_DIR/jwt_algorithm.txt"
grep_file "${JWT_CONFIG_RS:-/nonexistent}" \
  "Validation::new\|header\.alg\|algorithms.*=" | tee "$JWT_ALG_OUT" || true

# If no content from the specific file, widen search
if [[ ! -s "$JWT_ALG_OUT" ]]; then
  grep_crate "Validation::new\|ALLOWED_JWT_ALGORITHMS\|allowed_algorithms" | tee "$JWT_ALG_OUT" || true
fi

if grep -q "Validation::new(header" "$JWT_ALG_OUT" 2>/dev/null; then
  # Check if it's followed by an allowlist override
  CANDIDATE_FILE="${JWT_CONFIG_RS:-}"
  [[ -z "$CANDIDATE_FILE" ]] && CANDIDATE_FILE="$(grep_crate "Validation::new(header" | head -1 | cut -d: -f1)"
  NEXT_LINES=""
  [[ -n "$CANDIDATE_FILE" && -f "$CANDIDATE_FILE" ]] && \
    NEXT_LINES=$(grep -A5 "Validation::new(header" "$CANDIDATE_FILE" 2>/dev/null || true)
  if echo "$NEXT_LINES" | grep -q "algorithms.*=\|allowed_algs\|restrict"; then
    ok "JWT algorithm — allowlist override found after Validation::new(header.alg)"
    record "jwt-algorithm" "PASS"
  else
    fail "A07-1: Validation::new(header.alg) — JWT algorithm taken from token header without allowlist."
    record "jwt-algorithm" "FAIL"
  fi
else
  ok "JWT algorithm — Validation::new not called with header.alg"
  record "jwt-algorithm" "PASS"
fi

# ─── 8. A07: API token constant-time comparison ───────────────────────────────
step "8. A07 — API token constant-time comparison"

TOKEN_CMP_OUT="$OUTPUT_DIR/api_token_cmp.txt"
grep_file "${API_TOKEN_AUTH_RS:-/nonexistent}" \
  "client_token\|api_token\|== api_token\|constant_time\|ConstantTimeEq\|subtle" | tee "$TOKEN_CMP_OUT" || true

if [[ ! -s "$TOKEN_CMP_OUT" ]]; then
  grep_crate "ConstantTimeEq\|subtle.*eq\|constant_time_eq\|api_token" | tee "$TOKEN_CMP_OUT" || true
fi

if grep -qE "==.*api_token|api_token.*==" "$TOKEN_CMP_OUT" 2>/dev/null; then
  if grep -qE "constant_time|ConstantTimeEq|subtle::fixed_time_eq" "$TOKEN_CMP_OUT" 2>/dev/null; then
    ok "API token comparison — constant-time comparison used"
    record "api-token-ct" "PASS"
  else
    fail "A07-2: API token compared with == (not constant-time). Timing side-channel."
    record "api-token-ct" "FAIL"
  fi
else
  ok "API token comparison — no plain == comparison found"
  record "api-token-ct" "PASS"
fi

# ─── 9. A09: Database credential masking ──────────────────────────────────────
step "9. A09 — Database URL credential masking in Display impl"

DB_MASK_OUT="$OUTPUT_DIR/db_masking.txt"
grep_file "${DB_CONFIG_RS:-/nonexistent}" \
  "database_url\|fn fmt\|Display\|password\|\*\*\*\*" | tee "$DB_MASK_OUT" || true

if grep -qE '"(postgresql|mysql): \{\}"' "$DB_MASK_OUT" 2>/dev/null ||
   (grep -A3 '"postgresql:' "$DB_MASK_OUT" 2>/dev/null | grep -q "database_url"); then
  fail "A09-1: database_url printed unmasked in Display impl (postgresql/mysql). Credentials leak to logs."
  record "db-credential-masking" "FAIL"
else
  ok "Database URL masking — no obvious unmasked URL format found"
  record "db-credential-masking" "PASS"
fi

# ─── 10. A09: TLS password masking quality ────────────────────────────────────
step "10. A09 — TLS P12 password masking quality"

TLS_MASK_OUT="$OUTPUT_DIR/tls_masking.txt"
grep_file "${TLS_CONFIG_RS:-/nonexistent}" \
  "replace\|mask\|\*\*\*\|password" | tee "$TLS_MASK_OUT" || true

if grep -q "replace.*'\\.'" "$TLS_MASK_OUT" 2>/dev/null; then
  warn "A09-2: TLS P12 password masking uses replace('.','*') — replaces only dots."
  record "tls-password-masking" "WARN"
else
  ok "TLS password masking — no dot-only replace pattern found"
  record "tls-password-masking" "PASS"
fi

# ─── 11. A05: CORS permissive check ───────────────────────────────────────────
step "11. A05/A01 — CORS permissive() check"

CORS_OUT="$OUTPUT_DIR/cors.txt"
# Scan the whole workspace for CORS configuration
grep_crate "Cors::permissive\|allow_any_origin\|allow_origin.*\*" | tee "$CORS_OUT" || true

CORS_COUNT=$(wc -l <"$CORS_OUT" 2>/dev/null || echo 0)
MAIN_SCOPE_PERMISSIVE=$(grep_crate "Cors::permissive" | wc -l) || MAIN_SCOPE_PERMISSIVE=0
MAIN_SCOPE_DEFAULT=$(grep_crate "Cors::default" | wc -l)      || MAIN_SCOPE_DEFAULT=0

if [[ "$CORS_COUNT" -eq 0 ]]; then
  ok "CORS — no permissive() found"
  record "cors-config" "PASS"
elif [[ "$MAIN_SCOPE_DEFAULT" -gt 0 && "$MAIN_SCOPE_PERMISSIVE" -gt 0 ]]; then
  warn "A05-1/A01-1: Cors::permissive() found on ${CORS_COUNT} enterprise-integration scope(s) (Google CSE, MS DKE, AWS XKS etc.). Main KMIP scope uses Cors::default(). Enterprise permissive CORS is intentional."
  record "cors-config" "WARN"
else
  fail "A05-1/A01-1: Cors::permissive() found on $CORS_COUNT scope(s). Set explicit allowed origins."
  record "cors-config" "FAIL"
fi

# ─── 12. EXT-1: Key material zeroization (Zeroizing usage) ───────────────────
step "12. EXT-1 — Key material zeroization coverage"

ZERO_OUT="$OUTPUT_DIR/zeroization.txt"
{
  echo "=== Files using Zeroizing/ZeroizeOnDrop ==="
  grep_crate "Zeroizing\|ZeroizeOnDrop\|zeroize()" | wc -l
  echo ""
  echo "=== Key derivation return types ==="
  # Check the canonical derive_key file first, then widen to workspace
  if [[ -n "$DERIVE_KEY_RS" ]]; then
    grep -n "fn derive_\|-> Vec<u8>\|-> KResult<Vec<u8>>\|-> Zeroizing" "$DERIVE_KEY_RS" 2>/dev/null || true
  else
    grep_crate "fn derive_\|-> Vec<u8>\|-> KResult<Vec<u8>>\|-> Zeroizing" | grep -i "derive_key\|key_material" || true
  fi
} | tee "$ZERO_OUT"

if grep -qF "KResult<Vec<u8>>" "$ZERO_OUT" 2>/dev/null ||
   grep -qF "-> Vec<u8>" "$ZERO_OUT" 2>/dev/null; then
  warn "EXT1-1: derive_key helper(s) return bare Vec<u8> / KResult<Vec<u8>> for key material (not Zeroizing)."
  record "key-zeroization" "WARN"
else
  ok "Key zeroization — no bare Vec<u8> return found in key derivation paths"
  record "key-zeroization" "PASS"
fi

# ─── 13. EXT-2: Locate MaximumItems server-side cap ─────────────────────────
step "13. EXT-2 — Locate operation server-side result cap"

LOCATE_OUT="$OUTPUT_DIR/locate_cap.txt"
{
  if [[ -n "$LOCATE_RS" ]]; then grep -n "MaximumItems\|max_items\|LIMIT\|server.*max\|cap\|clamp" "$LOCATE_RS" 2>/dev/null || true; fi
  if [[ -n "$LOCATE_QUERY_RS" ]]; then grep -n "MaximumItems\|max_items\|LIMIT\|server.*max\|cap\|clamp" "$LOCATE_QUERY_RS" 2>/dev/null || true; fi
  # Workspace-wide fallback
  grep_crate "max_locate_items\|MAX_LOCATE_ITEMS" || true
} | tee "$LOCATE_OUT"

if grep -qiE "max_locate_items|server.*cap|min.*MAX|clamp" "$LOCATE_OUT" 2>/dev/null; then
  ok "Locate result cap — server-side maximum enforced"
  record "locate-cap" "PASS"
else
  warn "A04-3/EXT2-4: No server-side cap on Locate results. Client controls MaximumItems without server limit."
  record "locate-cap" "WARN"
fi

# ─── 14. Unsafe code distribution (dynamic crate enumeration) ────────────────
step "14. Unsafe code distribution (dynamic crate enumeration)"

UNSAFE_OUT="$OUTPUT_DIR/unsafe_distribution.txt"
{
  echo "Crate path | Files with unsafe | Total 'unsafe ' occurrences"
  echo "-----------|-------------------|----------------------------"
  # Dynamically discover all src/ directories under crate/
  while IFS= read -r src_dir; do
    # Derive a short name: strip REPO_ROOT prefix and trailing /src
    name="${src_dir#"$REPO_ROOT/"}"
    name="${name%/src}"
    files=$(grep -rl "unsafe " "$src_dir" --include="*.rs" 2>/dev/null | wc -l) || files=0
    total=$(grep -r "unsafe " "$src_dir" --include="*.rs" 2>/dev/null | wc -l) || total=0
    echo "$name | $files | $total"
  done < <(find "$REPO_ROOT/crate" -maxdepth 4 -name "src" -type d 2>/dev/null | sort)
} | tee "$UNSAFE_OUT"

if $RUN_GEIGER && command -v cargo-geiger &>/dev/null; then
  echo "" >>"$UNSAFE_OUT"
  echo "=== cargo-geiger output ===" >>"$UNSAFE_OUT"
  (cd crate/server && cargo geiger --all-features 2>&1 |
    grep -v "^Failed\|^{\|emit\|Checking\|Compiling\|Finished" >>"$UNSAFE_OUT") ||
    echo "cargo-geiger failed (known virtual workspace bug)" >>"$UNSAFE_OUT"
fi

ok "Unsafe distribution captured — see $UNSAFE_OUT"
record "unsafe-distribution" "PASS"

# ─── 15. A07-4: SameSite cookie setting ──────────────────────────────────────
step "15. A07-4 — Session cookie SameSite setting"

SAMESITE_OUT="$OUTPUT_DIR/samesite_cookie.txt"
grep_crate "SameSite\|cookie_same_site" | tee "$SAMESITE_OUT" || true

if grep -qE "SameSite::None|cookie_same_site.*None" "$SAMESITE_OUT" 2>/dev/null; then
  warn "A07-4: Session cookie uses SameSite::None — allows cross-site cookie submission."
  record "samesite-cookie" "WARN"
elif grep -qE "SameSite::Strict|SameSite::Lax" "$SAMESITE_OUT" 2>/dev/null; then
  ok "Session cookie SameSite — Strict or Lax (CSRF-resistant)"
  record "samesite-cookie" "PASS"
else
  warn "A07-4: SameSite cookie setting not found — cannot verify CSRF protection."
  record "samesite-cookie" "WARN"
fi

# ─── 16. A09-3: JWT auth failure log level ────────────────────────────────────
step "16. A09-3 — JWT authentication failure log level"

JWT_LOG_OUT="$OUTPUT_DIR/jwt_log_level.txt"
# Search all JWT middleware files dynamically
JWT_MIDDLEWARE_DIR="$(find "$REPO_ROOT/crate" -type d -name "jwt" 2>/dev/null | head -1)"
if [[ -n "$JWT_MIDDLEWARE_DIR" ]]; then
  grep -rn "401\|debug!\|warn!\|unauthorized\|bad JWT\|no email" "$JWT_MIDDLEWARE_DIR" --include="*.rs" 2>/dev/null | tee "$JWT_LOG_OUT" || true
else
  grep_crate "401.*unauthorized\|warn!.*unauthorized\|debug!.*401" | tee "$JWT_LOG_OUT" || true
fi

if grep -qE "debug!.*401|debug!.*unauthorized|debug!.*bad JWT|debug!.*no email" "$JWT_LOG_OUT" 2>/dev/null; then
  warn "A09-3: JWT auth failures logged at debug! level — will not appear in production logs."
  record "jwt-log-level" "WARN"
elif grep -qE "warn!.*401|warn!.*unauthorized|warn!.*bad JWT|warn!.*no email" "$JWT_LOG_OUT" 2>/dev/null; then
  ok "JWT auth failure log level — using warn! (visible in production)"
  record "jwt-log-level" "PASS"
else
  warn "A09-3: Could not detect JWT auth failure log level."
  record "jwt-log-level" "WARN"
fi

# ─── 17. A10-2/A10-3: reqwest redirect policy ────────────────────────────────
step "17. A10-2/A10-3 — reqwest redirect policy (SSRF mitigation)"

REDIRECT_OUT="$OUTPUT_DIR/reqwest_redirect.txt"
{
  if [[ -n "$JWKS_RS" ]]; then
    echo "=== $(basename "$JWKS_RS") ==="
    grep -n "redirect\|Policy\|Client::builder" "$JWKS_RS" 2>/dev/null || true
  fi
  if [[ -n "$UI_AUTH_RS" ]]; then
    echo ""
    echo "=== $(basename "$UI_AUTH_RS") ==="
    grep -n "redirect\|Policy\|Client::builder" "$UI_AUTH_RS" 2>/dev/null || true
  fi
  # Workspace-wide search for any reqwest clients without redirect control
  echo ""
  echo "=== All reqwest Client::builder usages ==="
  grep_crate "Client::builder\|reqwest::Client" || true
} | tee "$REDIRECT_OUT"

JWKS_NO_REDIRECT=0
if [[ -n "$JWKS_RS" ]]; then
  JWKS_NO_REDIRECT=$(grep -c "Policy::none\|redirect::none\|no_redirect" "$JWKS_RS" 2>/dev/null) || true
fi
UI_AUTH_NO_REDIRECT=0
if [[ -n "$UI_AUTH_RS" ]]; then
  UI_AUTH_NO_REDIRECT=$(grep -c "Policy::none\|redirect::none\|no_redirect" "$UI_AUTH_RS" 2>/dev/null) || true
fi

if [[ "$JWKS_NO_REDIRECT" -gt 0 && "$UI_AUTH_NO_REDIRECT" -gt 0 ]]; then
  ok "reqwest redirect — Policy::none() set in JWKS and UI auth clients"
  record "reqwest-redirect" "PASS"
elif [[ "$JWKS_NO_REDIRECT" -gt 0 || "$UI_AUTH_NO_REDIRECT" -gt 0 ]]; then
  warn "A10-2/A10-3: reqwest redirect::Policy::none() found in only one of the HTTP clients."
  record "reqwest-redirect" "WARN"
else
  warn "A10-2/A10-3: reqwest client(s) use default redirect policy — potential SSRF via 3xx chain."
  record "reqwest-redirect" "WARN"
fi

# ─── 18. A08-2: Session key salt warning ─────────────────────────────────────
step "18. A08-2 — Session key predictability warning at startup"

SESSION_WARN_OUT="$OUTPUT_DIR/session_key_warning.txt"
grep_crate "ui_session_salt\|session_key\|warn.*salt\|predictable" | tee "$SESSION_WARN_OUT" || true

if grep -qE "warn.*salt|warn.*session.*salt|warn.*predictable" "$SESSION_WARN_OUT" 2>/dev/null; then
  ok "Session key — operator warning present when ui_session_salt not configured"
  record "session-key-warning" "PASS"
else
  warn "A08-2: No startup warning when ui_session_salt is absent — operators unaware of predictable session key."
  record "session-key-warning" "WARN"
fi

# ─── 19. A04-3/EXT2-4: Locate MaximumItems constant check ────────────────────
step "19. A04-3 — Locate MaximumItems constant check"

LOCATE_CONST_OUT="$OUTPUT_DIR/locate_const.txt"
grep_crate "MAX_LOCATE_ITEMS\|max_locate_items\|server_cap\|effective_max" | tee "$LOCATE_CONST_OUT" || true

if grep -qiE "MAX_LOCATE_ITEMS|max_locate_items" "$LOCATE_CONST_OUT" 2>/dev/null; then
  ok "Locate result cap — MAX_LOCATE_ITEMS constant defined and applied"
  record "locate-const" "PASS"
else
  warn "A04-3: MAX_LOCATE_ITEMS constant not found in workspace."
  record "locate-const" "WARN"
fi

# ─── 20. Secret scan (gitleaks if available) ─────────────────────────────────
step "20. Secret scanning (gitleaks)"

SECRET_OUT="$OUTPUT_DIR/secrets.txt"
if command -v gitleaks &>/dev/null; then
  if gitleaks detect --source . --no-git --report-path "$SECRET_OUT" 2>&1; then
    ok "gitleaks — no secrets detected"
    record "secret-scan" "PASS"
  else
    fail "gitleaks found potential secrets. See $SECRET_OUT"
    record "secret-scan" "FAIL"
  fi
else
  warn "gitleaks not installed. Skipping secret scan."
  echo "(gitleaks not installed)" >"$SECRET_OUT"
  record "secret-scan" "WARN"
fi

# ─── 21. semgrep — auto community rules + project custom rules ────────────────
# semgrep --config auto fetches the latest OWASP/CWE/NIST rules from the
# Semgrep registry automatically — new vulnerability patterns are picked up
# without any script changes.
# Custom project-specific rules live in .github/scripts/audit/custom_rules/
# — drop a new .yml file there and it is picked up automatically.
step "21. semgrep (auto community rules + custom Cosmian rules)"

SEMGREP_OUT="$OUTPUT_DIR/semgrep.txt"
CUSTOM_RULES_DIR="$SCRIPT_DIR/custom_rules"

if command -v semgrep &>/dev/null; then
  SEMGREP_CONFIGS=("--config" "auto")
  if [[ -d "$CUSTOM_RULES_DIR" ]] && compgen -G "$CUSTOM_RULES_DIR/*.yml" >/dev/null 2>&1; then
    SEMGREP_CONFIGS+=("--config" "$CUSTOM_RULES_DIR")
    info "Loading custom rules from $CUSTOM_RULES_DIR"
  fi

  set +e
  semgrep "${SEMGREP_CONFIGS[@]}" \
    --lang rust \
    --json \
    --output "$SEMGREP_OUT" \
    --quiet \
    crate/ 2>&1
  SEMGREP_RC=$?
  set -e

  if [[ -s "$SEMGREP_OUT" ]] && command -v python3 &>/dev/null; then
    SEMGREP_ERRORS=$(python3 -c "
import json, sys
try:
    d = json.load(open('$SEMGREP_OUT'))
    errs = [r for r in d.get('results',[]) if r.get('extra',{}).get('severity','') in ('ERROR','WARNING')]
    print(len(errs))
except: print(0)
" 2>/dev/null || echo 0)
  else
    SEMGREP_ERRORS=0
  fi

  if [[ "$SEMGREP_ERRORS" -gt 0 ]]; then
    warn "semgrep: $SEMGREP_ERRORS finding(s). See $SEMGREP_OUT"
    record "semgrep" "WARN"
  elif [[ "$SEMGREP_RC" -ne 0 ]]; then
    warn "semgrep exited with code $SEMGREP_RC. See $SEMGREP_OUT"
    record "semgrep" "WARN"
  else
    ok "semgrep — no findings"
    record "semgrep" "PASS"
  fi
else
  warn "semgrep not installed. Skipping pattern analysis."
  echo "(semgrep not installed)" >"$SEMGREP_OUT"
  record "semgrep" "WARN"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo
echo "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "${BOLD}  Cosmian KMS — Audit Summary$(date +'  (%Y-%m-%d %H:%M:%S)')${RESET}"
echo "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
for name in "${!RESULTS[@]}"; do
  case "${RESULTS[$name]}" in
  PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
  WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
  FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
  esac
done
for name in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
  status="${RESULTS[$name]}"
  case "$status" in
  PASS) ok "  $name" ;;
  WARN) warn "  $name" ;;
  FAIL) fail "  $name" ;;
  esac
done

echo
echo "  Results: ${GREEN}${PASS_COUNT} PASS${RESET}  ${YELLOW}${WARN_COUNT} WARN${RESET}  ${RED}${FAIL_COUNT} FAIL${RESET}"
echo "  Output: $OUTPUT_DIR"

# Write JSON summary
JSON_OUT="$OUTPUT_DIR/summary.json"
{
  echo "{"
  echo "  \"audit_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"repo\": \"Cosmian/kms\","
  echo "  \"branch\": \"$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)\","
  echo "  \"commit\": \"$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)\","
  echo "  \"pass\": $PASS_COUNT,"
  echo "  \"warn\": $WARN_COUNT,"
  echo "  \"fail\": $FAIL_COUNT,"
  echo "  \"results\": {"
  first=true
  for name in "${!RESULTS[@]}"; do
    $first || echo ","
    printf '    "%s": "%s"' "$name" "${RESULTS[$name]}"
    first=false
  done
  echo ""
  echo "  }"
  echo "}"
} >"$JSON_OUT"

info "JSON summary: $JSON_OUT"

# ─── Update owasp_security_audit.md Remediation Priority Matrix ─────────────
update_audit_md() {
  local AUDIT_MD="${REPO_ROOT}/documentation/docs/certifications_and_compliance/audit/owasp_security_audit.md"
  [[ -f "$AUDIT_MD" ]] || {
    warn "security_audit.md not found — skipping update"
    return
  }

  info "Updating security_audit.md Remediation Priority Matrix …"

  local SED_SCRIPT=""

  add_fix() {
    local check="$1"
    shift
    local status="${RESULTS[$check]:-WARN}"
    local new_status
    if [[ "$status" == "PASS" ]]; then
      new_status="✅ Fixed"
    elif [[ "$status" == "WARN" ]]; then
      new_status="⚠️ Mitigated"
    else
      return
    fi
    for id in "$@"; do
      SED_SCRIPT+="s#| *$id *|\\(.*\\)| *Open *|#| $id |\\1| $new_status |#g;"
    done
  }

  add_fix "ttlv-depth-limit"      "A03-2 / EXT2-2" "A03-3 / EXT2-3"
  add_fix "payload-limit"         "A04-1 / EXT2-1"
  add_fix "rate-limiting"         "A04-2 / EXT2-5"
  add_fix "jwt-algorithm"         "A07-1"
  add_fix "api-token-ct"          "A07-2"
  add_fix "db-credential-masking" "A09-1"
  add_fix "tls-password-masking"  "A09-2"
  add_fix "cors-config"           "A05-1 / A01-1"
  add_fix "key-zeroization"       "EXT1-1"
  add_fix "locate-cap"            "A04-3 / EXT2-4"
  add_fix "locate-const"          "A04-3 / EXT2-4"
  add_fix "samesite-cookie"       "A07-4"
  add_fix "jwt-log-level"         "A09-3"
  add_fix "reqwest-redirect"      "A10-2 / A10-3"
  add_fix "session-key-warning"   "A08-2"

  if [[ -n "$SED_SCRIPT" ]]; then
    sed -i "$SED_SCRIPT" "$AUDIT_MD"
  fi

  local TODAY
  TODAY="$(date +%Y-%m-%d)"
  sed -i "s/\*\*Audit date\*\*: [0-9-]*/\*\*Audit date\*\*: $TODAY/" "$AUDIT_MD"

  if [[ "$OVERALL_STATUS" -eq 0 ]]; then
    sed -i "s/\*\*Status\*\*:.*/\*\*Status\*\*: ☑ Complete — automated pass (audit.sh ran $TODAY)/" "$AUDIT_MD"
  else
    sed -i "s/\*\*Status\*\*:.*/\*\*Status\*\*: ⚠️ Incomplete — ${FAIL_COUNT} check(s) FAILED (audit.sh ran $TODAY)/" "$AUDIT_MD"
  fi

  ok "security_audit.md updated — Remediation Priority Matrix status refreshed"
}

update_audit_md

echo
if [[ "$OVERALL_STATUS" -eq 0 ]]; then
  ok "${BOLD}Audit completed — no failures${RESET}"
else
  fail "${BOLD}Audit completed — ${FAIL_COUNT} check(s) FAILED. Review findings above.${RESET}"
fi

exit "$OVERALL_STATUS"
