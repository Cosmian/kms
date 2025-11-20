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
DERIVATION="kms-server-${VARIANT}"
NIX_RESULT="$REPO_ROOT/result-server-${VARIANT}"

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
echo "Generating CycloneDX SBOM..."
sbomnix "$NIX_RESULT" --cdx="$OUTPUT_DIR/bom.cdx.json"
echo "  ✓ bom.cdx.json"
echo ""

# Generate SPDX SBOM (JSON format - ISO standard)
echo "Generating SPDX SBOM..."
sbomnix "$NIX_RESULT" --spdx="$OUTPUT_DIR/bom.spdx.json"
echo "  ✓ bom.spdx.json"
echo ""

# Generate CSV format
echo "Generating CSV report..."
sbomnix "$NIX_RESULT" --csv="$OUTPUT_DIR/sbom.csv"
echo "  ✓ sbom.csv"
echo ""

# Run vulnerability scan
echo "Running vulnerability scan..."
if command -v vulnxscan >/dev/null 2>&1; then
  vulnxscan "$NIX_RESULT" --out "$OUTPUT_DIR/vulns.csv" 2>&1 | grep -v "WARNING" || true

  if [ -f "$OUTPUT_DIR/vulns.csv" ] && [ -s "$OUTPUT_DIR/vulns.csv" ]; then
    echo "  ✓ vulns.csv"
  else
    echo "  ⚠ Vulnerability scan produced no results"
  fi
else
  echo "  ⚠ vulnxscan not available (install: nix-env -iA nixpkgs.sbomnix)"
fi
echo ""

# Generate dependency graph
echo "Generating dependency graph..."
if command -v nixgraph >/dev/null 2>&1; then
  # Save current directory and change to output dir
  pushd "$OUTPUT_DIR" >/dev/null
  nixgraph "$NIX_RESULT" 2>&1 | grep -E "INFO|Wrote" || true
  popd >/dev/null

  if [ -f "$OUTPUT_DIR/graph.png" ]; then
    echo "  ✓ graph.png"
  else
    echo "  ⚠ Graph generation failed"
  fi
else
  echo "  ⚠ nixgraph not available (install: nix-env -iA nixpkgs.sbomnix)"
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

# Generate README
echo "Generating documentation..."
cat >"$OUTPUT_DIR/README.txt" <<'EOF'
SBOM (Software Bill of Materials)
==================================

This directory contains a complete Software Bill of Materials generated using
sbomnix tools from the Nix build output.

Generated Files
---------------

bom.cdx.json       CycloneDX 1.5 SBOM (JSON)
                   Industry-standard SBOM format
                   Compatible with: Dependency-Track, OWASP tools
                   Spec: https://cyclonedx.org/

bom.spdx.json      SPDX 2.3 SBOM (JSON)
                   ISO/IEC 5962:2021 standard format
                   Compatible with: SPDX analyzers, compliance tools
                   Spec: https://spdx.dev/

sbom.csv           Component list (CSV)
                   Simple tabular format for spreadsheet analysis
                   Columns: name, version, license, CPE, PURL, store path

vulns.csv          Vulnerability scan results (CSV)
                   CVE database cross-reference
                   Columns: CVE ID, URL, package, version, CVSS score
                   Sources: NVD (NIST), OSV (Google)

graph.png          Dependency graph visualization
                   Runtime dependency relationships

meta.json          Build metadata
                   Build variant, timestamp, component count

Usage Examples
--------------

Import to Dependency-Track:

    curl -X POST "https://dtrack.example.com/api/v1/bom" \
      -H "X-Api-Key: ${API_KEY}" \
      -H "Content-Type: multipart/form-data" \
      -F "project=${PROJECT_UUID}" \
      -F "bom=@bom.cdx.json"

Validate SPDX:

    spdx-tools validate bom.spdx.json

Analyze in spreadsheet:

    libreoffice --calc sbom.csv

Query with jq:

    # List all components
    jq '.components[] | {name, version}' bom.cdx.json

    # Find specific package
    jq '.packages[] | select(.name | contains("openssl"))' bom.spdx.json

    # Count components by license
    jq '[.components[].licenses[].license.id] | group_by(.) |
        map({license: .[0], count: length})' bom.cdx.json

Notes
-----

- OpenSSL is statically linked in the binary
- All dependencies are from Nix store with pinned versions
- SBOM includes runtime dependencies only (build-time dependencies excluded)
- Vulnerability data is point-in-time; re-run regularly for updates

Tools
-----

Generate SBOM:     nix/scripts/generate_sbom.sh
sbomnix docs:      https://github.com/tiiuae/sbomnix
CycloneDX spec:    https://cyclonedx.org/specification/overview/
SPDX spec:         https://spdx.github.io/spdx-spec/
EOF
echo "  ✓ README.txt"
echo ""

# Summary
echo "========================================="
echo "SBOM Generation Complete"
echo "========================================="
echo ""
echo "Generated files in $OUTPUT_DIR:"
ls -lh "$OUTPUT_DIR" | tail -n +2 | awk '{printf "  %10s  %s\n", $5, $9}'
echo ""
echo "Standards compliance:"
echo "  ✓ CycloneDX 1.5 (OWASP)"
echo "  ✓ SPDX 2.3 (ISO/IEC 5962:2021)"
echo ""
echo "Next steps:"
echo "  - Review: cat $OUTPUT_DIR/README.txt"
echo "  - Import to Dependency-Track or other SBOM platform"
echo "  - Integrate into CI/CD pipeline"
echo ""
