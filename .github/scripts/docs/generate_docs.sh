#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — Documentation generator (master script)
# =============================================================================
# Regenerates ALL auto-generated documentation pages in one shot.
# This is the single entry point used by release.yml and the pre-commit hook.
#
# Steps (each may be selectively skipped via flags):
#   1. server-docs     — server --help → server_cli.md
#                        server --print-default-config → server_configuration_file.md
#                        kms_template.toml, pkg/kms.toml
#   2. ckms-docs       — ckms markdown → cli_documentation/docs/cli/main_commands.md
#                        ckms --help   → cli_documentation/docs/usage.md
#   3. kmip-tables     — scan KMIP operations, update README.md KMIP table
#   4. crypto-inventory— scan Rust source → crypto_inventory.md (CBOM sensor)
#   5. cbom            — generate cbom/cbom.cdx.json (CycloneDX 1.6)
#
# Usage:
#   bash .github/scripts/docs/generate_docs.sh [OPTIONS]
#
# Options:
#   --skip-server       Skip step 1 (server docs — requires cargo build)
#   --skip-ckms         Skip step 2 (ckms docs — requires cargo build)
#   --skip-kmip-tables  Skip step 3 (KMIP table update — no build needed)
#   --skip-crypto       Skip step 4 (crypto inventory — no build needed)
#   --skip-cbom         Skip step 5 (CBOM generation — requires cdxgen)
#   --quick             Alias for --skip-server --skip-ckms (no Rust build needed)
#   --help              Show this message
#
# Exit code: 0 on success; non-zero on the first failed step.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# ─── Color helpers ───────────────────────────────────────────────────────────
GREEN=$'\e[32m\e[1m'
CYAN=$'\e[36m\e[1m'
YELLOW=$'\e[33m\e[1m'
RED=$'\e[31m\e[1m'
RESET=$'\e[0m'
info()   { echo "${CYAN}[DOCS]${RESET} $*"; }
ok()     { echo "${GREEN}[ OK ]${RESET} $*"; }
warn()   { echo "${YELLOW}[WARN]${RESET} $*"; }
fail()   { echo "${RED}[FAIL]${RESET} $*" >&2; }
banner() { echo; echo "${GREEN}━━━ $* ━━━${RESET}"; }

# ─── Parse options ────────────────────────────────────────────────────────────
SKIP_SERVER=false
SKIP_CKMS=false
SKIP_KMIP=false
SKIP_CRYPTO=false
SKIP_CBOM=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-server)       SKIP_SERVER=true; shift ;;
    --skip-ckms)         SKIP_CKMS=true; shift ;;
    --skip-kmip-tables)  SKIP_KMIP=true; shift ;;
    --skip-crypto)       SKIP_CRYPTO=true; shift ;;
    --skip-cbom)         SKIP_CBOM=true; shift ;;
    --quick)             SKIP_SERVER=true; SKIP_CKMS=true; SKIP_CBOM=true; shift ;;
    --help|-h)
      sed -n '/^# Usage:/,/^# =\+/p' "$0" | head -n -1 | sed 's/^# \?//'
      exit 0 ;;
    *) fail "Unknown option: $1"; exit 1 ;;
  esac
done

cd "$REPO_ROOT"
ERRORS=0

# ─── Step 1: Server docs ──────────────────────────────────────────────────────
if [[ "$SKIP_SERVER" == false ]]; then
  banner "1/5 — Server docs (server_cli.md + server_configuration_file.md)"
  if bash "$SCRIPT_DIR/renew_server_doc.sh"; then
    ok "Server docs regenerated"
  else
    fail "renew_server_doc.sh failed"
    ERRORS=$((ERRORS + 1))
  fi
else
  warn "Step 1/5 skipped (--skip-server)"
fi

# ─── Step 2: ckms CLI docs ────────────────────────────────────────────────────
if [[ "$SKIP_CKMS" == false ]]; then
  banner "2/5 — ckms CLI docs (main_commands.md + usage.md)"
  if bash "$SCRIPT_DIR/renew_ckms_markdown.sh"; then
    ok "ckms CLI docs regenerated"
  else
    fail "renew_ckms_markdown.sh failed"
    ERRORS=$((ERRORS + 1))
  fi
else
  warn "Step 2/5 skipped (--skip-ckms)"
fi

# ─── Step 3: KMIP support table ───────────────────────────────────────────────
if [[ "$SKIP_KMIP" == false ]]; then
  banner "3/5 — KMIP support tables (README.md + kmip_support/support.md)"
  if python3 "$SCRIPT_DIR/update_readme_kmip.py"; then
    ok "KMIP support tables updated"
  else
    fail "update_readme_kmip.py failed"
    ERRORS=$((ERRORS + 1))
  fi
else
  warn "Step 3/5 skipped (--skip-kmip-tables)"
fi

# ─── Step 4: Cryptographic inventory (CBOM sensor) ───────────────────────────
if [[ "$SKIP_CRYPTO" == false ]]; then
  banner "4/5 — Cryptographic inventory (crypto_inventory.md)"
  if bash "$REPO_ROOT/.github/scripts/audit/crypto_sensor.sh" \
      --repo-root "$REPO_ROOT" \
      --quick; then
    ok "Cryptographic inventory regenerated"
  else
    fail "crypto_sensor.sh failed"
    ERRORS=$((ERRORS + 1))
  fi
else
  warn "Step 4/5 skipped (--skip-crypto)"
fi

# ─── Step 5: CBOM ─────────────────────────────────────────────────────────────
if [[ "$SKIP_CBOM" == false ]]; then
  banner "5/5 — CBOM (cbom/cbom.cdx.json)"
  if bash "$REPO_ROOT/.github/scripts/release/generate_cbom.sh"; then
    ok "CBOM regenerated"
  else
    fail "generate_cbom.sh failed"
    ERRORS=$((ERRORS + 1))
  fi
else
  warn "Step 5/5 skipped (--skip-cbom)"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo
if [[ "$ERRORS" -eq 0 ]]; then
  ok "All documentation steps completed successfully."
else
  fail "$ERRORS step(s) failed — check output above."
  exit 1
fi
