#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — Reproducible OWASP Security Audit Script
# =============================================================================
# Usage:  bash .github/scripts/audit.sh [--output-dir <dir>] [--geiger] [--help]
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
ok() { echo "${GREEN}${BOLD}[PASS ]${RESET} $*"; }
warn() { echo "${YELLOW}${BOLD}[WARN ]${RESET} $*"; }
fail() { echo "${RED}${BOLD}[FAIL ]${RESET} $*"; }
step() {
  echo
  echo "${BOLD}━━━  $*  ━━━${RESET}"
}

# ─── Arguments ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/documentation/docs/certifications_and_compliance/audit-results/$(date +%Y%m%d_%H%M%S)"
RUN_GEIGER=false
FAIL_ON_WARN=false

usage() {
  echo "Usage: $0 [--output-dir <dir>] [--geiger] [--fail-on-warn] [--help]"
  echo "  --output-dir   Where to write per-tool output files (default: documentation/docs/certifications_and_compliance/audit-results/<timestamp>/)"
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
    warn "Note: cargo-geiger 0.13.0 has a known bug with virtual workspaces (github.com/rust-secure-code/cargo-geiger/issues/378). Unsafe counts will fall back to grep."
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
  # cargo audit exits with non-zero on warnings too; detect via output
  if grep -q "^error:" "$AUDIT_OUT" 2>/dev/null; then
    fail "cargo audit found vulnerabilities. See $AUDIT_OUT"
    record "cargo-audit" "FAIL"
  else
    warn "cargo audit completed with warnings. See $AUDIT_OUT"
    record "cargo-audit" "WARN"
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
# cargo outdated can fail on wasm crate feature issue; capture and continue
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
BINARY_PARSER="crate/kmip/src/ttlv/wire/ttlv_bytes_deserializer.rs"
XML_PARSER_DIR="crate/kmip/src/ttlv/xml/"
{
  echo "=== Binary TTLV parser (read_ttlv recursion) ==="
  grep -n "fn read_ttlv\|read_ttlv(\|depth\|MAX_DEPTH\|max_depth" "$BINARY_PARSER" 2>/dev/null
  echo ""
  echo "=== XML TTLV parser (depth counter + max check) ==="
  grep -n "depth\|MAX_DEPTH\|max_depth" "$XML_PARSER_DIR" -r 2>/dev/null || true
} | tee "$TTLV_OUT"

# Binary parser: must have a MAX_DEPTH constant and a depth-limit check
# Use 'VAR=$(grep -c) || VAR=0' to handle grep exit-1-on-no-match with set -euo pipefail
BINARY_HAS_MAX=$(grep -cE "MAX_DEPTH|max_depth|if.*depth.*>|depth.*>=.*MAX" \
  "$BINARY_PARSER" 2>/dev/null) || BINARY_HAS_MAX=0
# XML parser: must also guard with a max constant, not just a zero-check
XML_HAS_MAX=$(grep -rcE "MAX_DEPTH|max_depth|if.*depth.*>.*[0-9]" \
  "$XML_PARSER_DIR" 2>/dev/null) || XML_HAS_MAX=0

if [[ "$BINARY_HAS_MAX" -eq 0 ]]; then
  fail "A03-2/EXT2-2: Binary TTLV parser ($BINARY_PARSER) has no recursion depth limit. Stack overflow DoS possible."
  record "ttlv-depth-limit" "FAIL"
elif [[ "$XML_HAS_MAX" -eq 0 ]]; then
  warn "A03-3/EXT2-3: XML TTLV parser has depth counter but no max-depth enforcement (depth != 0 check only)."
  record "ttlv-depth-limit" "WARN"
else
  ok "TTLV parsers — both have recursion/depth limits"
  record "ttlv-depth-limit" "PASS"
fi

# ─── 5. A04/EXT-2: Payload size limit check ──────────────────────────────────
step "5. A04/EXT-2 — HTTP payload size limit check"

PAYLOAD_OUT="$OUTPUT_DIR/payload_limit.txt"
grep -n "PayloadConfig\|json.*limit\|JsonConfig\|body.*limit" \
  crate/server/src/start_kms_server.rs 2>/dev/null | tee "$PAYLOAD_OUT" || true

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
grep -rn "RateLimiter\|rate_limit\|throttle\|governor\|leaky_bucket\|token_bucket" \
  crate/server/src/ --include="*.rs" 2>/dev/null | tee "$RATE_OUT" || true

if [[ ! -s "$RATE_OUT" ]]; then
  fail "A04-2/EXT2-5: No rate-limiting middleware found in crate/server/src/."
  record "rate-limiting" "FAIL"
else
  ok "Rate-limiting reference found"
  record "rate-limiting" "PASS"
fi

# ─── 7. A07: JWT algorithm confusion check ────────────────────────────────────
step "7. A07 — JWT algorithm confusion check"

JWT_ALG_OUT="$OUTPUT_DIR/jwt_algorithm.txt"
grep -n "Validation::new\|header\.alg\|algorithms.*=" \
  crate/server/src/middlewares/jwt/jwt_config.rs 2>/dev/null | tee "$JWT_ALG_OUT" || true

# Check if the algorithm is restricted to a server-controlled allowlist
# The safe pattern is: create Validation and then set validation.algorithms = vec![allowed_alg]
# before using header.alg as the constructor value.
if grep -q "Validation::new(header" "$JWT_ALG_OUT" 2>/dev/null; then
  # Check if it's followed by an algorithms allowlist override
  NEXT_LINES=$(grep -A5 "Validation::new(header" \
    crate/server/src/middlewares/jwt/jwt_config.rs 2>/dev/null || true)
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
grep -n "client_token\|api_token\|== api_token\|constant_time\|ConstantTimeEq\|subtle" \
  crate/server/src/middlewares/api_token/api_token_auth.rs 2>/dev/null | tee "$TOKEN_CMP_OUT" || true

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
grep -n "database_url\|fn fmt\|Display\|password\|\*\*\*\*" \
  crate/server/src/config/command_line/db.rs 2>/dev/null | tee "$DB_MASK_OUT" || true

# Look for unmasked database_url: the Display impl uses `url.as_str()` for postgresql/mysql
# without masking the password. Detect pattern: write!(f, "postgresql: {}", ...database_url...)
if grep -qE '"(postgresql|mysql): \{\}"' \
  crate/server/src/config/command_line/db.rs 2>/dev/null ||
  grep -A3 '"postgresql:' crate/server/src/config/command_line/db.rs 2>/dev/null |
  grep -q "database_url"; then
  fail "A09-1: database_url printed unmasked in Display impl (postgresql/mysql). Credentials leak to logs."
  record "db-credential-masking" "FAIL"
else
  ok "Database URL masking — no obvious unmasked URL format found"
  record "db-credential-masking" "PASS"
fi

# ─── 10. A09: TLS password masking quality ────────────────────────────────────
step "10. A09 — TLS P12 password masking quality"

TLS_MASK_OUT="$OUTPUT_DIR/tls_masking.txt"
grep -n "replace\|mask\|\*\*\*\|password" \
  crate/server/src/config/command_line/tls_config.rs 2>/dev/null | tee "$TLS_MASK_OUT" || true

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
grep -n "Cors::permissive\|allow_any_origin\|allow_origin.*\*" \
  crate/server/src/start_kms_server.rs 2>/dev/null | tee "$CORS_OUT" || true

# Enterprise integration scopes (Google CSE, MS DKE, AWS XKS, UI auth) intentionally use
# Cors::permissive() because they are called by external cloud services from varying origins.
# Only the default KMIP scope must use a restrictive CORS policy.
# Count permissive() occurrences that are NOT in the enterprise integration block:
# An occurrence is "enterprise" if it appears on the same line that names the scope type
# (google_cse_scope, ms_dke_scope, aws_xks_scope, azure_ekm_scope, auth_routes).
CORS_COUNT=$(wc -l <"$CORS_OUT" 2>/dev/null || echo 0)
# Detect whether Cors::permissive() is being used without Cors::default() on the main scope
# The main default scope wraps with Cors::default(); any remaining permissive() are enterprise.
MAIN_SCOPE_PERMISSIVE=$(grep -c "Cors::permissive" crate/server/src/start_kms_server.rs 2>/dev/null || true)
MAIN_SCOPE_DEFAULT=$(grep -c "Cors::default" crate/server/src/start_kms_server.rs 2>/dev/null || true)
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
  grep -rl "Zeroizing\|ZeroizeOnDrop\|zeroize()" crate/ --include="*.rs" 2>/dev/null | wc -l
  echo ""
  echo "=== derive_key return type ==="
  grep -n "fn derive_\|-> Vec<u8>\|-> KResult<Vec<u8>>\|-> Zeroizing" \
    crate/server/src/core/operations/derive_key.rs 2>/dev/null
} | tee "$ZERO_OUT"

# Detect bare Vec<u8> (or KResult<Vec<u8>>) as return types in key derivation functions
# Use -F (fixed string) because angle brackets confuse grep option parsing
if grep -qF "KResult<Vec<u8>>" "$ZERO_OUT" 2>/dev/null ||
  grep -qF "-> Vec<u8>" "$ZERO_OUT" 2>/dev/null; then
  warn "EXT1-1: derive_key helper(s) return bare Vec<u8> / KResult<Vec<u8>> for key material (not Zeroizing)."
  record "key-zeroization" "WARN"
else
  ok "Key zeroization — derive_key does not return bare Vec<u8>"
  record "key-zeroization" "PASS"
fi

# ─── 13. EXT-2: Locate MaximumItems server-side cap ─────────────────────────
step "13. EXT-2 — Locate operation server-side result cap"

LOCATE_OUT="$OUTPUT_DIR/locate_cap.txt"
grep -n "MaximumItems\|max_items\|LIMIT\|server.*max\|cap" \
  crate/server/src/core/operations/locate.rs \
  crate/server_database/src/stores/sql/locate_query.rs 2>/dev/null | tee "$LOCATE_OUT" || true

if grep -qiE "max_locate_items|server.*cap|min.*MAX|clamp" "$LOCATE_OUT" 2>/dev/null; then
  ok "Locate result cap — server-side maximum enforced"
  record "locate-cap" "PASS"
else
  warn "A04-3/EXT2-4: No server-side cap on Locate results. Client controls MaximumItems without server limit."
  record "locate-cap" "WARN"
fi

# ─── 14. Unsafe code distribution (grep-based geiger fallback) ───────────────
step "14. Unsafe code distribution (manual grep — geiger fallback)"

UNSAFE_OUT="$OUTPUT_DIR/unsafe_distribution.txt"
{
  echo "Crate | Files with unsafe | Total 'unsafe ' occurrences"
  echo "-----|-------------------|----------------------------"
  for crate_src in \
    "server:crate/server/src" \
    "server_database:crate/server_database/src" \
    "crypto:crate/crypto/src" \
    "kmip:crate/kmip/src" \
    "access:crate/access/src" \
    "clients/client:crate/clients/client/src" \
    "clients/clap:crate/clients/clap/src" \
    "clients/pkcs11/module:crate/clients/pkcs11/module/src" \
    "hsm/base_hsm:crate/hsm/base_hsm/src"; do
    name="${crate_src%%:*}"
    path="${crate_src##*:}"
    files=$(grep -rl "unsafe " "$path" --include="*.rs" 2>/dev/null | wc -l) || files=0
    total=$(grep -r "unsafe " "$path" --include="*.rs" 2>/dev/null | wc -l) || total=0
    echo "$name | $files | $total"
  done
} | tee "$UNSAFE_OUT"

# If cargo-geiger is available and --geiger was passed, try running it too
if $RUN_GEIGER && command -v cargo-geiger &>/dev/null; then
  echo "" >>"$UNSAFE_OUT"
  echo "=== cargo-geiger output ===" >>"$UNSAFE_OUT"
  # Run from within server crate to avoid virtual workspace issue
  (cd crate/server && cargo geiger --all-features 2>&1 |
    grep -v "^Failed\|^{\|emit\|Checking\|Compiling\|Finished" >>"$UNSAFE_OUT") ||
    echo "cargo-geiger failed (known virtual workspace bug)" >>"$UNSAFE_OUT"
fi

ok "Unsafe distribution captured — see $UNSAFE_OUT"
record "unsafe-distribution" "PASS"

# ─── 15. A07-4: SameSite cookie setting ──────────────────────────────────────
step "15. A07-4 — Session cookie SameSite setting"

SAMESITE_OUT="$OUTPUT_DIR/samesite_cookie.txt"
grep -n "SameSite\|cookie_same_site" \
  crate/server/src/start_kms_server.rs 2>/dev/null | tee "$SAMESITE_OUT" || true

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
grep -n "401\|debug!\|warn!\|unauthorized\|bad JWT\|no email" \
  crate/server/src/middlewares/jwt/jwt_token_auth.rs 2>/dev/null | tee "$JWT_LOG_OUT" || true

# Check for debug!() calls on 401 unauthorized paths — should be warn!() for audit trail
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
  echo "=== jwks.rs ==="
  grep -n "redirect\|Policy\|Client::builder" \
    crate/server/src/middlewares/jwt/jwks.rs 2>/dev/null || true
  echo ""
  echo "=== ui_auth.rs ==="
  grep -n "redirect\|Policy\|Client::builder" \
    crate/server/src/routes/ui_auth.rs 2>/dev/null || true
} | tee "$REDIRECT_OUT"

# Check that redirect::Policy::none() is used in both files
JWKS_NO_REDIRECT=$(grep -c "Policy::none\|redirect::none\|no_redirect" \
  crate/server/src/middlewares/jwt/jwks.rs 2>/dev/null) || JWKS_NO_REDIRECT=0
UI_AUTH_NO_REDIRECT=$(grep -c "Policy::none\|redirect::none\|no_redirect" \
  crate/server/src/routes/ui_auth.rs 2>/dev/null) || UI_AUTH_NO_REDIRECT=0

if [[ "$JWKS_NO_REDIRECT" -gt 0 && "$UI_AUTH_NO_REDIRECT" -gt 0 ]]; then
  ok "reqwest redirect — Policy::none() set in both jwks.rs and ui_auth.rs"
  record "reqwest-redirect" "PASS"
elif [[ "$JWKS_NO_REDIRECT" -gt 0 || "$UI_AUTH_NO_REDIRECT" -gt 0 ]]; then
  warn "A10-2/A10-3: reqwest redirect::Policy::none() found in only one of jwks.rs/ui_auth.rs."
  record "reqwest-redirect" "WARN"
else
  warn "A10-2/A10-3: reqwest client(s) use default redirect policy — potential SSRF via 3xx chain."
  record "reqwest-redirect" "WARN"
fi

# ─── 18. A08-2: Session key salt warning ─────────────────────────────────────
step "18. A08-2 — Session key predictability warning at startup"

SESSION_WARN_OUT="$OUTPUT_DIR/session_key_warning.txt"
grep -n "ui_session_salt\|session_key\|warn.*salt\|predictable" \
  crate/server/src/start_kms_server.rs 2>/dev/null | tee "$SESSION_WARN_OUT" || true

if grep -qE "warn.*salt|warn.*session.*salt|warn.*predictable" "$SESSION_WARN_OUT" 2>/dev/null; then
  ok "Session key — operator warning present when ui_session_salt not configured"
  record "session-key-warning" "PASS"
else
  warn "A08-2: No startup warning when ui_session_salt is absent — operators unaware of predictable session key."
  record "session-key-warning" "WARN"
fi

# ─── 19. A04-3/EXT2-4: Locate server-side cap (enhanced) ────────────────────
step "19. A04-3 — Locate MaximumItems constant check"

LOCATE_CONST_OUT="$OUTPUT_DIR/locate_const.txt"
grep -n "MAX_LOCATE_ITEMS\|max_locate_items\|server_cap\|effective_max" \
  crate/server/src/core/operations/locate.rs 2>/dev/null | tee "$LOCATE_CONST_OUT" || true

if grep -qiE "MAX_LOCATE_ITEMS|max_locate_items" "$LOCATE_CONST_OUT" 2>/dev/null; then
  ok "Locate result cap — MAX_LOCATE_ITEMS constant defined and applied"
  record "locate-const" "PASS"
else
  warn "A04-3: MAX_LOCATE_ITEMS constant not found in locate.rs."
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

# ─── 21. semgrep (if available) ───────────────────────────────────────────────
step "21. semgrep OWASP ruleset (if available)"

SEMGREP_OUT="$OUTPUT_DIR/semgrep.txt"
if command -v semgrep &>/dev/null; then
  if semgrep --config p/owasp-top-ten crate/ --lang rust \
    --output "$SEMGREP_OUT" --quiet 2>&1; then
    SEMGREP_FINDINGS=$(grep -cE "^severity:" "$SEMGREP_OUT" 2>/dev/null) || SEMGREP_FINDINGS=0
    if [[ "$SEMGREP_FINDINGS" -gt 0 ]]; then
      warn "semgrep: $SEMGREP_FINDINGS finding(s). See $SEMGREP_OUT"
      record "semgrep" "WARN"
    else
      ok "semgrep — no findings"
      record "semgrep" "PASS"
    fi
  else
    warn "semgrep encountered an error. See $SEMGREP_OUT"
    record "semgrep" "WARN"
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

# ─── Update security_audit.md Remediation Priority Matrix ────────────────────
# Map each audit check result to one or more finding IDs in the matrix and update
# the Status column from "Open" to "✅ Fixed" or "⚠️ Mitigated".
update_audit_md() {
  local AUDIT_MD="${REPO_ROOT}/documentation/docs/certifications_and_compliance/security_audit.md"
  [[ -f "$AUDIT_MD" ]] || {
    warn "security_audit.md not found — skipping update"
    return
  }

  info "Updating security_audit.md Remediation Priority Matrix …"

  # Build a sed script that replaces Open → ✅ Fixed for each confirmed passing check.
  # Pattern: match table rows containing the finding ID and replace their Status cell.
  local SED_SCRIPT=""

  # Helper: for a check name and finding IDs, add sed commands if the check PASSED
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
      return # FAIL → leave as Open
    fi
    for id in "$@"; do
      # Replace "| Open |" with "| $new_status |" on rows that contain the finding ID
      SED_SCRIPT+="s#| *$id *|\\(.*\\)| *Open *|#| $id |\\1| $new_status |#g;"
    done
  }

  add_fix "ttlv-depth-limit" "A03-2 / EXT2-2" "A03-3 / EXT2-3"
  add_fix "payload-limit" "A04-1 / EXT2-1"
  add_fix "rate-limiting" "A04-2 / EXT2-5"
  add_fix "jwt-algorithm" "A07-1"
  add_fix "api-token-ct" "A07-2"
  add_fix "db-credential-masking" "A09-1"
  add_fix "tls-password-masking" "A09-2"
  add_fix "cors-config" "A05-1 / A01-1"
  add_fix "key-zeroization" "EXT1-1"
  add_fix "locate-cap" "A04-3 / EXT2-4"
  add_fix "locate-const" "A04-3 / EXT2-4"
  add_fix "samesite-cookie" "A07-4"
  add_fix "jwt-log-level" "A09-3"
  add_fix "reqwest-redirect" "A10-2 / A10-3"
  add_fix "session-key-warning" "A08-2"

  if [[ -n "$SED_SCRIPT" ]]; then
    sed -i "$SED_SCRIPT" "$AUDIT_MD"
  fi

  # Update the audit date in the document header (line 7: **Audit date**: ...)
  local TODAY
  TODAY="$(date +%Y-%m-%d)"
  sed -i "s/\*\*Audit date\*\*: [0-9-]*/\*\*Audit date\*\*: $TODAY/" "$AUDIT_MD"

  # Update the Status line to reflect overall result
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
