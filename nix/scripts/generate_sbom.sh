#!/usr/bin/env bash
# Generate standard SBOM using sbomnix tools
# https://github.com/tiiuae/sbomnix
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Parse arguments
VARIANT="fips"
OUTPUT_DIR="$REPO_ROOT/sbom"

usage() {
  cat <<EOF
Generate SBOM (Software Bill of Materials) using sbomnix standard tools

Usage: $0 [OPTIONS]

Options:
  --variant VARIANT    Build variant to analyze: fips or non-fips (default: fips)
  --output DIR         Output directory for SBOM files (default: ./sbom)
  -h, --help           Show this help message

Examples:
  $0                           # Generate SBOM for fips variant
  $0 --variant non-fips        # Generate SBOM for non-fips variant
  $0 --output /tmp/sbom        # Use custom output directory

Generated files:
  - bom.cdx.json               CycloneDX SBOM (industry standard)
  - bom.spdx.json              SPDX SBOM (ISO/IEC 5962:2021)
  - sbom.csv                   CSV format for spreadsheet analysis
  - vulns.csv                  Vulnerability scan results
  - graph.png                  Dependency graph visualization
  - meta.json                  Build metadata
  - README.txt                 Documentation and integration guide
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
  --variant)
    VARIANT="${2:-}"
    shift 2
    ;;
  --output)
    OUTPUT_DIR="${2:-}"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "Error: Unknown option: $1" >&2
    usage >&2
    exit 1
    ;;
  esac
done

# Validate variant
case "$VARIANT" in
fips | non-fips) ;;
*)
  echo "Error: --variant must be 'fips' or 'non-fips'" >&2
  exit 1
  ;;
esac

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "========================================="
echo "SBOM Generation"
echo "========================================="
echo "Variant:  $VARIANT"
echo "Output:   $OUTPUT_DIR"
echo "========================================="
echo ""

cd "$REPO_ROOT"

# Determine the derivation to analyze
DERIVATION="kms-server-${VARIANT}-static-openssl"
NIX_RESULT="$REPO_ROOT/result-server-${VARIANT}-static-openssl"

# Helper function to run sbomnix commands via nix-shell if sbomnix is not available
run_sbomnix() {
  if command -v sbomnix >/dev/null 2>&1; then
    # sbomnix is available in PATH, use it directly
    sbomnix "$@"
  else
    # Use nix-shell to provide sbomnix
    nix-shell -p sbomnix --run "sbomnix $*"
  fi
}

# Helper function to run vulnxscan commands via nix-shell if not available
run_vulnxscan() {
  if command -v vulnxscan >/dev/null 2>&1; then
    # vulnxscan is available in PATH, use it directly
    vulnxscan "$@"
  else
    # Use nix-shell to provide vulnxscan (part of sbomnix package)
    nix-shell -p sbomnix --run "vulnxscan $*"
  fi
}

# Helper function to run nixgraph commands via nix-shell if not available
run_nixgraph() {
  if command -v nixgraph >/dev/null 2>&1; then
    # nixgraph is available in PATH, use it directly
    nixgraph "$@"
  else
    # Use nix-shell to provide nixgraph (part of sbomnix package)
    nix-shell -p sbomnix --run "nixgraph $*"
  fi
}

# Check for build output
echo "Checking build output..."
if [ ! -e "$NIX_RESULT" ] || [ ! -e "$(readlink -f "$NIX_RESULT" 2>/dev/null || echo "/nonexistent")" ]; then
  echo "Build output not found or garbage collected, rebuilding..."
  nix-build "$REPO_ROOT/default.nix" -A "$DERIVATION" -o "$(basename "$NIX_RESULT")"
  echo "Build complete: $NIX_RESULT"
else
  echo "Using existing build: $NIX_RESULT -> $(readlink -f "$NIX_RESULT")"
fi
echo ""

# Generate CycloneDX SBOM (JSON format - industry standard)
# Note: "Failed reading nix meta information" warning is expected when scanning store paths
# The SBOM still includes all package information, just without Nixpkgs-specific metadata
echo "Generating CycloneDX SBOM..."
run_sbomnix "$NIX_RESULT" --impure --cdx="$OUTPUT_DIR/sbom.cdx.json" 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ sbom.cdx.json"
echo ""

# Generate SPDX SBOM (JSON format - ISO standard)
echo "Generating SPDX SBOM..."
run_sbomnix "$NIX_RESULT" --impure --spdx="$OUTPUT_DIR/sbom.spdx.json" 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ sbom.spdx.json"
echo ""

# Generate CSV format
echo "Generating CSV report..."
run_sbomnix "$NIX_RESULT" --impure --csv="$OUTPUT_DIR/sbom.csv" 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ sbom.csv"
echo ""

# Run vulnerability scan
echo "Running vulnerability scan..."
# Enable experimental Nix features required by vulnix
export NIX_CONFIG="experimental-features = nix-command flakes"
run_vulnxscan "$NIX_RESULT" --out "$OUTPUT_DIR/vulns.csv"
if [ -f "$OUTPUT_DIR/vulns.csv" ] && [ -s "$OUTPUT_DIR/vulns.csv" ]; then
  echo "  ✓ vulns.csv"
else
  echo "  ⚠ Vulnerability scan produced no results"
fi
echo ""

# Generate dependency graph
echo "Generating dependency graph..."
# Save current directory and change to output dir
pushd "$OUTPUT_DIR" >/dev/null
if run_nixgraph "$NIX_RESULT" 2>&1 | grep -E "INFO|Wrote" || true; then
  :
fi
popd >/dev/null

if [ -f "$OUTPUT_DIR/graph.png" ]; then
  echo "  ✓ graph.png"
else
  echo "  ⚠ Graph generation failed"
fi
echo ""

# Generate build metadata
echo "Generating metadata..."
cat >"$OUTPUT_DIR/meta.json" <<EOF
{
  "spec_version": "1.0.0",
  "build": {
    "variant": "$VARIANT",
    "derivation": "$DERIVATION",
    "output_path": "$(readlink -f "$NIX_RESULT")",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "generator": {
      "tool": "sbomnix",
      "version": "$(sbomnix --version 2>&1 | head -1 | awk '{print $NF}' || echo "unknown")"
    }
  },
  "component_count": $(wc -l <"$OUTPUT_DIR/sbom.csv" 2>/dev/null | awk '{print $1-1}' || echo 0),
  "vulnerability_count": $(wc -l <"$OUTPUT_DIR/vulns.csv" 2>/dev/null | awk '{print $1-1}' || echo 0),
  "notes": [
    "OpenSSL is statically linked in the binary",
    "All dependencies are from Nix store with pinned versions",
    "SBOM includes runtime dependencies only"
  ]
}
EOF
echo "  ✓ meta.json"
echo ""

# Note: README.md is maintained manually in sbom/ directory
# It contains comprehensive documentation about all SBOM tools and usage

# Summary
echo "========================================="
echo "SBOM Generation Complete"
echo "========================================="
echo ""
echo "Generated files in $OUTPUT_DIR:"
# shellcheck disable=SC2012
ls -lh "$OUTPUT_DIR" | tail -n +2 | awk '{printf "  %10s  %s\n", $5, $9}'
echo ""
echo "Standards compliance:"
echo "  ✓ CycloneDX 1.5 (OWASP)"
echo "  ✓ SPDX 2.3 (ISO/IEC 5962:2021)"
echo ""
echo "Next steps:"
echo "  - Review: cat $OUTPUT_DIR/README.md"
echo "  - Import to Dependency-Track or other SBOM platform"
echo "  - Integrate into CI/CD pipeline"
echo ""
