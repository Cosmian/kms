#!/usr/bin/env bash
# =============================================================================
# Cryptographic Inventory Sensor
# =============================================================================
# Lightweight sensor that discovers and inventories all cryptographic assets
# in a Rust codebase: algorithms, libraries, key sizes, deprecated primitives,
# PQC coverage, TLS configuration, and CVE exposure.
#
# Open-source components used (not reinvented):
#   • scan_source.py   — custom Rust/TOML source scanner (this repo)
#   • risk_score.py    — custom risk scorer and Markdown report generator
#   • cargo audit      — RustSec CVE database (https://rustsec.org)
#   • cdxgen           — OWASP CycloneDX CBOM generator (optional)
#   • testssl.sh       — TLS/certificate scanner (optional, needs --server-url)
#   • gitleaks         — secret scanner (optional)
#
# Usage:
#   bash .github/scripts/audit/crypto_sensor.sh [OPTIONS]
#
# Options:
#   --repo-root    <path>   Repo root (default: three levels above this script)
#   --scan-dirs    <dirs>   Comma-separated source dirs relative to repo root
#                           (default: "crate" — passed to scan_source.py)
#   --output-dir   <path>   Output directory (default: cbom/sensor/ — overwritten on each run)
#   --docs-output  <path>   Path to write the crypto_inventory.md MkDocs page
#   --project-name <name>   Project name used in reports (default: auto-detected
#                           from Cargo.toml or repo directory name)
#   --server-url   <url>    Live server URL for TLS scan (e.g. https://localhost:9998)
#   --update-cbom           Merge findings into cbom/cbom.cdx.json
#   --quick                 Source scan + risk scoring only (skips cargo audit,
#                           cdxgen, TLS scan, and CBOM update — fast, no network)
#   --help                  Show this message
#
# Exit code: 0 if no unmitigated CRITICAL findings; 1 otherwise.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/cbom/sensor"
DOCS_PAGE="${REPO_ROOT}/documentation/docs/certifications_and_compliance/audit/crypto_inventory.md"
SERVER_URL=""
UPDATE_CBOM=false
SCAN_DIRS="crate"
PROJECT_NAME=""
QUICK=false

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
CYAN=$'\e[36m'
BOLD=$'\e[1m'
RESET=$'\e[0m'
info()  { echo "${CYAN}${BOLD}[SENSOR]${RESET} $*"; }
ok()    { echo "${GREEN}${BOLD}[  OK  ]${RESET} $*"; }
warn()  { echo "${YELLOW}${BOLD}[ WARN ]${RESET} $*"; }
fail()  { echo "${RED}${BOLD}[ FAIL ]${RESET} $*"; }
banner(){ echo; echo "${BOLD}═════════════════════════════════════════════��════${RESET}"; echo "${BOLD}  $*${RESET}"; echo "${BOLD}══════════════════════════════════════════════════${RESET}"; }

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --repo-root    <path>  Repository root directory (default: auto-detected)
  --scan-dirs    <dirs>  Comma-separated source directories to scan (default: "crate")
#   --output-dir   <path>  Where to write sensor output (default: cbom/sensor/ — overwritten)
  --docs-output  <path>  Path to write the crypto_inventory.md MkDocs page
  --project-name <name>  Project name for reports (default: auto-detected)
  --server-url   <url>   Live server URL for TLS scan (optional)
  --update-cbom          Merge findings timestamp into cbom/cbom.cdx.json
  --quick                Source scan + risk scoring only (no network, fast)
  --help                 Show this help message
EOF
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
  --repo-root)    REPO_ROOT="$2"; shift 2 ;;
  --scan-dirs)    SCAN_DIRS="$2"; shift 2 ;;
  --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
  --docs-output)  DOCS_PAGE="$2"; shift 2 ;;
  --project-name) PROJECT_NAME="$2"; shift 2 ;;
  --server-url)   SERVER_URL="$2"; shift 2 ;;
  --quick)        QUICK=true; shift ;;
  --update-cbom)  UPDATE_CBOM=true; shift ;;
  --help) usage; exit 0 ;;
  *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# Auto-detect project name from Cargo.toml if not provided
if [[ -z "$PROJECT_NAME" ]]; then
  if [[ -f "${REPO_ROOT}/Cargo.toml" ]]; then
    PROJECT_NAME=$(python3 -c "
import re, sys
text = open('${REPO_ROOT}/Cargo.toml').read()
m = re.search(r'^\s*name\s*=\s*[\"\'](.*)[\"\']', text, re.MULTILINE)
print(m.group(1) if m else "")
" 2>/dev/null || true)
  fi
  [[ -z "$PROJECT_NAME" ]] && PROJECT_NAME="$(basename "$REPO_ROOT")"
fi

mkdir -p "$OUTPUT_DIR"
OVERALL_EXIT=0

banner "$PROJECT_NAME — Cryptographic Inventory Sensor"
info "Project   : $PROJECT_NAME"
info "Repo root : $REPO_ROOT"
info "Output    : $OUTPUT_DIR"
[[ -n "$SERVER_URL" ]] && info "TLS target: $SERVER_URL"
echo

# ─── Step 1: Source code scan ─────────────────────────────────────────────────
banner "1/5 — Source code cryptographic scan"

FINDINGS_JSON="$OUTPUT_DIR/findings.json"
set +e
python3 "$SCRIPT_DIR/scan_source.py" \
    --repo-root "$REPO_ROOT" \
    --scan-dirs "$SCAN_DIRS" \
    --output "$FINDINGS_JSON"
SCAN_EXIT=$?
set -e
if [[ "$SCAN_EXIT" -eq 0 ]]; then
  ok "Source scan complete → $FINDINGS_JSON"
elif [[ "$SCAN_EXIT" -eq 1 ]]; then
  # exit 1 = CRITICAL findings present; let risk_score.py decide based on mitigations
  warn "Source scan: CRITICAL findings present — risk scorer will evaluate mitigations"
else
  fail "Source scan failed (exit $SCAN_EXIT)"
  OVERALL_EXIT=1
fi

# ─── Step 2: CVE scan (cargo audit --json) ────────────────────────────��──────
# Pre-define AUDIT_JSON so set -u does not fire when --quick skips this step
AUDIT_JSON=""
if [[ "$QUICK" == false ]]; then
banner "2/5 — CVE scan (cargo audit)"

AUDIT_JSON="$OUTPUT_DIR/cargo_audit.json"
AUDIT_ARGS="--json"
set +e
cargo audit $AUDIT_ARGS 2>/dev/null >"$AUDIT_JSON"
AUDIT_EXIT=$?
set -e

if [[ "$AUDIT_EXIT" -eq 0 ]]; then
  ok "cargo audit — no advisories"
else
  CRITICAL_HIGH=0
  if command -v python3 &>/dev/null && [[ -s "$AUDIT_JSON" ]]; then
    CRITICAL_HIGH=$(python3 -c "
import json, sys
try:
    d = json.load(open('$AUDIT_JSON'))
    vulns = d.get('vulnerabilities', {}).get('list', [])
    print(sum(1 for v in vulns
              if v.get('advisory',{}).get('severity','').upper() in ('CRITICAL','HIGH')))
except Exception:
    print(0)
" 2>/dev/null || echo 0)
  fi
  if [[ "$CRITICAL_HIGH" -gt 0 ]]; then
    fail "cargo audit: $CRITICAL_HIGH CRITICAL/HIGH CVE(s). See $AUDIT_JSON"
    OVERALL_EXIT=1
  else
    warn "cargo audit: advisories found (non-CRITICAL). See $AUDIT_JSON"
  fi
fi

# ─── Step 3: Risk scoring and Markdown report ────────────────────────────────
fi  # end --quick skip: CVE scan

banner "3/5 — Risk scoring"

RISK_JSON="$OUTPUT_DIR/risk_report.json"
REPORT_MD="$OUTPUT_DIR/crypto_report.md"

RISK_ARGS=(--input "$FINDINGS_JSON" --output-json "$RISK_JSON" --output-md "$REPORT_MD" --project-name "$PROJECT_NAME")
[[ -s "$AUDIT_JSON" ]] && RISK_ARGS+=(--audit-json "$AUDIT_JSON")

# Pass --docs-output when the DOCS_PAGE parent directory exists.
# In --quick (pre-commit) mode, skip docs update to avoid pre-commit stash conflicts
# caused by the regenerated timestamp. Docs are updated in full/CI runs only.
if [[ "$QUICK" == false ]] && [[ -n "$DOCS_PAGE" ]] && [[ -d "$(dirname "$DOCS_PAGE")" ]]; then
  RISK_ARGS+=(--docs-output "$DOCS_PAGE")
fi

if python3 "$SCRIPT_DIR/risk_score.py" "${RISK_ARGS[@]}"; then
  ok "Risk report → $RISK_JSON"
  ok "Markdown   → $REPORT_MD"
  [[ -f "$DOCS_PAGE" ]] && ok "MkDocs page → $DOCS_PAGE"
else
  RISK_EXIT=$?
  if [[ "$RISK_EXIT" -eq 1 ]]; then
    fail "Risk scorer: CRITICAL findings in report"
    OVERALL_EXIT=1
  fi
fi

# ─── Step 4: Dependency-level CBOM (cdxgen, optional) ────────────────────────
if [[ "$QUICK" == false ]]; then
banner "4/5 — Dependency CBOM (cdxgen)"

DEP_CBOM="$OUTPUT_DIR/dep_cbom.json"
if command -v cdxgen &>/dev/null; then
  info "Running cdxgen for Cargo.lock → CycloneDX CBOM …"
  if cdxgen \
      --type rust \
      --output "$DEP_CBOM" \
      --spec-version 1.6 \
      "$REPO_ROOT" 2>/dev/null; then
    ok "cdxgen CBOM → $DEP_CBOM"
  else
    warn "cdxgen exited non-zero. Partial CBOM may exist at $DEP_CBOM"
  fi
else
  warn "cdxgen not installed — skipping dependency-level CBOM."
  warn "Install: npm install -g @cyclonedx/cdxgen"
  echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"note":"cdxgen not available"}' >"$DEP_CBOM"
fi

# ─── Step 5: Live TLS scan (testssl.sh, optional) ────────────────────────────
fi  # end --quick skip: cdxgen

if [[ "$QUICK" == false ]]; then
banner "5/5 — Live TLS scan"

TLS_OUT="$OUTPUT_DIR/tls_report.txt"
if [[ -n "$SERVER_URL" ]]; then
  if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
    TESTSSL_CMD="testssl.sh"
    command -v testssl &>/dev/null && TESTSSL_CMD="testssl"
    info "Scanning TLS on $SERVER_URL …"
    set +e
    "$TESTSSL_CMD" --quiet --color 0 --logfile "$TLS_OUT" "$SERVER_URL" 2>&1
    set -e
    ok "TLS scan complete → $TLS_OUT"

    # Flag critical TLS weaknesses
    if grep -qiE "VULNERABLE|CRITICAL|SSLv[23]|TLSv1\.0|TLSv1\.1|RC4|DES|NULL" "$TLS_OUT" 2>/dev/null; then
      warn "TLS scan flagged weaknesses. Review $TLS_OUT"
    else
      ok "TLS scan — no critical weaknesses detected"
    fi
  else
    warn "testssl.sh not installed — skipping live TLS scan."
    warn "Install: https://testssl.sh"
    echo "(testssl.sh not available)" >"$TLS_OUT"
  fi
elif command -v gitleaks &>/dev/null; then
  # Use the step for gitleaks if no server URL given
  info "Running gitleaks secret scan …"
  GITLEAKS_OUT="$OUTPUT_DIR/secrets.txt"
  if gitleaks detect --source "$REPO_ROOT" --no-git --report-path "$GITLEAKS_OUT" 2>&1; then
    ok "gitleaks — no secrets detected"
  else
    fail "gitleaks found potential secrets. See $GITLEAKS_OUT"
    OVERALL_EXIT=1
  fi
else
  info "No --server-url provided and gitleaks not installed — skipping step 5."
  echo "(step skipped)" >"$TLS_OUT"
fi

fi  # end --quick skip: TLS scan

# ─── Update cbom/cbom.cdx.json timestamp ─────────────────────────────────────
if $UPDATE_CBOM; then
  CBOM_FILE="$REPO_ROOT/cbom/cbom.cdx.json"
  if [[ -f "$CBOM_FILE" ]] && command -v python3 &>/dev/null; then
    info "Updating cbom/cbom.cdx.json metadata timestamp …"
    python3 - <<PYEOF
import json, sys
from datetime import datetime, timezone
from pathlib import Path

p = Path("$CBOM_FILE")
try:
    cbom = json.loads(p.read_text(encoding="utf-8"))
    cbom["metadata"]["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Record the sensor run in metadata properties
    props = cbom["metadata"].setdefault("properties", [])
    props = [x for x in props if x.get("name") != "${PROJECT_NAME}:sensor_run"]
    from datetime import datetime, timezone as _tz
    props.append({"name": "${PROJECT_NAME}:sensor_run", "value": datetime.now(_tz.utc).isoformat()})
    cbom["metadata"]["properties"] = props
    p.write_text(json.dumps(cbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("cbom/cbom.cdx.json updated.")
except Exception as e:
    print(f"WARNING: could not update CBOM: {e}", file=sys.stderr)
PYEOF
    ok "cbom/cbom.cdx.json timestamp updated"
  else
    warn "cbom/cbom.cdx.json not found or python3 unavailable — skipping CBOM update"
  fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
banner "Sensor Summary"

if [[ -s "$RISK_JSON" ]] && command -v python3 &>/dev/null; then
  python3 - <<PYEOF
import json, sys
from pathlib import Path

EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
try:
    r = json.loads(Path("$RISK_JSON").read_text())
    s = r.get("by_severity", {})
    sc = r.get("scores", {})
    total = r.get("total", 0)
    print(f"  Total findings  : {total}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        print(f"  {EMOJI[sev]} {sev:8s}: {s.get(sev, 0)}")
    print()
    print(f"  PQC Readiness   : {sc.get('pqc_readiness_pct', '?')}%")
    print(f"  FIPS Coverage   : {sc.get('fips_coverage_pct', '?')}%")
    print(f"  Zeroize refs    : {sc.get('zeroize_references', '?')}")
except Exception as e:
    print(f"(could not parse risk report: {e})", file=sys.stderr)
PYEOF
fi

echo
echo "  Output directory: $OUTPUT_DIR"
echo "  Files:"
echo "    findings.json    — raw source scanner output"
echo "    risk_report.json — risk-scored findings + CVEs"
echo "    crypto_report.md — Markdown report (same as MkDocs page)"
echo "    cargo_audit.json — CVE advisory data"
echo "    dep_cbom.json    — dependency-level CBOM (cdxgen)"
echo "    tls_report.txt   — TLS scan (if applicable)"
echo
if [[ -f "$DOCS_PAGE" ]]; then
  echo "  Live docs page updated:"
  echo "    $DOCS_PAGE"
  echo
fi

if [[ "$OVERALL_EXIT" -eq 0 ]]; then
  ok "${BOLD}Sensor run complete — no CRITICAL findings${RESET}"
else
  fail "${BOLD}Sensor run complete — CRITICAL findings require attention${RESET}"
fi

exit "$OVERALL_EXIT"
