#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — CBOM generator
# =============================================================================
# Generates cbom/cbom.cdx.json (CycloneDX 1.6 Cryptographic Bill of Materials).
#
# Pipeline:
#   1. cdxgen  — scans Cargo.lock → CycloneDX SBOM with library versions + PURLs
#                (authoritative, OWASP standard; used instead of cargo metadata)
#   2. generate_cbom.py — merges cdxgen library data with the cryptographic-asset
#                         catalog (algorithms, OIDs, FIPS/PQC metadata, security
#                         levels) that cdxgen cannot produce
#   3. validate_cbom.py — verifies the output against the CycloneDX 1.6 JSON schema
#
# Why both cdxgen AND generate_cbom.py?
#   cdxgen excels at dependency SBOM (library components from Cargo.lock with
#   correct PURLs). generate_cbom.py adds the CBOM-specific "cryptographic-asset"
#   components (63 algorithm entries with primitive, mode, certificationLevel,
#   nistQuantumSecurityLevel, OIDs …) that cdxgen does not discover.
#
# Usage:
#   bash .github/scripts/release/generate_cbom.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SBOM_SCRIPTS="$SCRIPT_DIR/../sbom"

VERSION="$("$SCRIPT_DIR/get_version.sh")"
OUTPUT="$REPO_ROOT/cbom/cbom.cdx.json"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

# ─── Colour helpers ───────────────────────────────────────────────────────────
GREEN=$'\e[32m\e[1m'
YELLOW=$'\e[33m\e[1m'
CYAN=$'\e[36m\e[1m'
RED=$'\e[31m\e[1m'
RESET=$'\e[0m'
info()  { echo "${CYAN}[CBOM]${RESET} $*"; }
ok()    { echo "${GREEN}[ OK ]${RESET} $*"; }
warn()  { echo "${YELLOW}[WARN]${RESET} $*"; }
fail()  { echo "${RED}[FAIL]${RESET} $*" >&2; }

info "KMS version : $VERSION"
info "Output      : $OUTPUT"

# ─── Step 1: cdxgen — library SBOM from Cargo.lock ───────────────────────────
DEP_SBOM="$TEMP_DIR/dep_sbom.json"
LIB_ARGS=()

if command -v cdxgen &>/dev/null; then
  info "Running cdxgen for Cargo.lock → CycloneDX library SBOM …"
  if cdxgen \
      --type rust \
      --output "$DEP_SBOM" \
      --spec-version 1.6 \
      "$REPO_ROOT" 2>/dev/null; then
    ok "cdxgen SBOM → $DEP_SBOM"
    LIB_ARGS=(--lib-input "$DEP_SBOM")
  else
    warn "cdxgen exited non-zero — falling back to cargo metadata for library versions."
  fi
else
  warn "cdxgen not installed — falling back to cargo metadata for library versions."
  warn "Install: npm install -g @cyclonedx/cdxgen"
fi

# ─── Step 2: generate_cbom.py — merge library data + algorithm catalog ────────
info "Building CBOM (algorithm catalog + library versions) …"
python3 "$SBOM_SCRIPTS/generate_cbom.py" \
  --output "$OUTPUT" \
  --kms-version "$VERSION" \
  "${LIB_ARGS[@]}"
ok "CBOM written → $OUTPUT"

# ─── Step 3: validate against CycloneDX 1.6 ──────────────────────────────────
info "Validating CBOM against CycloneDX 1.6 schema …"
if python3 "$SBOM_SCRIPTS/validate_cbom.py" "$OUTPUT"; then
  ok "CycloneDX 1.6 validation passed"
else
  fail "CBOM validation failed — see errors above."
  exit 1
fi
