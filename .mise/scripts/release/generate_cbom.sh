#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — CBOM generator wrapper
# =============================================================================
# Generates cbom/cbom.cdx.json (CycloneDX 1.6) by running the Python script
# .mise/scripts/sbom/generate_cbom.py.
#
# Optional: if cyclonedx-bom / cdxgen has previously produced an SBOM JSON
# at sbom/sbom.cdx.json, it is passed as --lib-input so library versions are
# read from it instead of running `cargo metadata`.
#
# Usage:
#   bash .mise/scripts/release/generate_cbom.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

CBOM_PY="$REPO_ROOT/.mise/scripts/sbom/generate_cbom.py"
OUTPUT="$REPO_ROOT/cbom/cbom.cdx.json"

# Use cdxgen/cyclonedx SBOM as library-version source if available.
LIB_INPUT=""
if [[ -f "$REPO_ROOT/sbom/sbom.cdx.json" && -s "$REPO_ROOT/sbom/sbom.cdx.json" ]]; then
  LIB_INPUT="$REPO_ROOT/sbom/sbom.cdx.json"
fi

ARGS=(--output "$OUTPUT")
if [[ -n "$LIB_INPUT" ]]; then
  ARGS+=(--lib-input "$LIB_INPUT")
fi

python3 "$CBOM_PY" "${ARGS[@]}"
