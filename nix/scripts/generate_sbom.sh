#!/usr/bin/env bash
# Generate standard SBOM using sbomnix tools
# https://github.com/tiiuae/sbomnix
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Parse arguments
# Target: what to generate SBOM for. Supported: 'openssl' or 'server'.
# - openssl: scans the OpenSSL 3.1.2 derivation from nix/openssl.nix
# - server:  scans the KMS server derivation
TARGET="openssl"
# Variant and link are only relevant for 'server' target
VARIANT="fips" # fips | non-fips
LINK="static"  # static | dynamic (static by default)
OUTPUT_DIR="$REPO_ROOT/sbom"

usage() {
  cat <<EOF
Generate SBOM (Software Bill of Materials) using sbomnix standard tools

Usage: $0 [OPTIONS]

Options:
  --target TARGET      One of: openssl | server (default: openssl)
  --variant VARIANT    One of: fips | non-fips (server target only; default: fips)
  --link LINK          One of: static | dynamic (server target only; default: static)
  --output DIR         Output directory for SBOM files (default:
                       - openssl: ./sbom/openssl
                       - server:  ./sbom/server/<variant>/<link>)
  -h, --help           Show this help message

Examples:
  $0                           # Generate SBOM for OpenSSL (default)
  $0 --target openssl          # Explicitly target OpenSSL 3.1.2
  $0 --target server           # Target KMS server (fips, static OpenSSL)
  $0 --target server --variant non-fips    # Target KMS server (non-fips)
  $0 --target server --link dynamic        # Target KMS server (dynamic link, if available)
  $0 --output /tmp/sbom        # Use custom output directory

Generated files:
  - bom.cdx.json               CycloneDX SBOM (industry standard)
  - bom.spdx.json              SPDX SBOM (ISO/IEC 5962:2021)
  - sbom.csv                   CSV format for spreadsheet analysis
  - vulns.csv                  Vulnerability scan results
  - graph.png                  Dependency graph visualization
  - meta.json                  Build metadata
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
  --target)
    TARGET="${2:-}"
    shift 2
    ;;
  --variant)
    VARIANT="${2:-}"
    shift 2
    ;;
  --link)
    LINK="${2:-}"
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

# Determine the derivation to analyze based on target
case "$TARGET" in
openssl)
  DERIVATION="openssl312"
  NIX_RESULT="$REPO_ROOT/result-openssl-312"
  ;;
server)
  # Validate variant/link values
  case "$VARIANT" in
  fips | non-fips) : ;;
  *)
    echo "Error: --variant must be 'fips' or 'non-fips'" >&2
    exit 1
    ;;
  esac
  case "$LINK" in
  static | dynamic) : ;;
  *)
    echo "Error: --link must be 'static' or 'dynamic'" >&2
    exit 1
    ;;
  esac

  # Scan the exact server derivation (build chain) to verify toolchain CVEs
  if [ "$LINK" = "dynamic" ]; then
    DERIVATION="kms-server-${VARIANT}-dynamic-openssl"
    NIX_RESULT="$REPO_ROOT/result-server-${VARIANT}-dynamic-openssl"
  else
    DERIVATION="kms-server-${VARIANT}-static-openssl"
    NIX_RESULT="$REPO_ROOT/result-server-${VARIANT}-static-openssl"
  fi
  ;;
*)
  echo "Error: Unknown --target '$TARGET'. Use 'openssl' or 'server'." >&2
  exit 1
  ;;
esac

# Adjust default output directory to include target/variant/link structure
if [ "$OUTPUT_DIR" = "$REPO_ROOT/sbom" ]; then
  case "$TARGET" in
  server)
    OUTPUT_DIR="$REPO_ROOT/sbom/server/$VARIANT/$LINK"
    ;;
  openssl)
    OUTPUT_DIR="$REPO_ROOT/sbom/openssl"
    ;;
  esac
fi

# Create output directory (after adjusting default path)
mkdir -p "$OUTPUT_DIR"

# sbomnix may emit default output files (sbom.csv/sbom.cdx.json/sbom.spdx.json)
# into the current working directory, even when explicit output paths are
# provided. To ensure this script only updates the requested OUTPUT_DIR,
# run sbomnix/vulnxscan from an isolated temporary work directory.
SBOM_WORKDIR="$(mktemp -d -t cosmian-kms-sbom.XXXXXX)"
cleanup() {
  rm -rf "$SBOM_WORKDIR" || true
}
trap cleanup EXIT

# Keep the output directory clean: remove previously generated derived
# artifacts (older runs may have created extra post-processed reports).
rm -f \
  "$OUTPUT_DIR/sbom.runtime.csv" \
  "$OUTPUT_DIR/vulns.runtime.csv" \
  "$OUTPUT_DIR/vulns.pc.deb-ubu-rocky.csv" \
  "$OUTPUT_DIR/vulns.runtime.pc.deb-ubu-rocky.csv" \
  "$OUTPUT_DIR/cves.pc.deb-ubu-rocky.txt" \
  "$OUTPUT_DIR/cves.runtime.pc.deb-ubu-rocky.txt" \
  || true

echo "========================================="
echo "SBOM Generation"
echo "========================================="
echo "Target:   $TARGET"
echo "Variant:  $VARIANT"
echo "Link:     $LINK"
echo "Output:   $OUTPUT_DIR"
echo "========================================="
echo ""

cd "$REPO_ROOT"

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
(cd "$SBOM_WORKDIR" && run_sbomnix "$NIX_RESULT" --impure --include-vulns --cdx="$OUTPUT_DIR/bom.cdx.json") 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ bom.cdx.json"
echo ""

# Generate SPDX SBOM (JSON format - ISO standard)
echo "Generating SPDX SBOM..."
(cd "$SBOM_WORKDIR" && run_sbomnix "$NIX_RESULT" --impure --include-vulns --spdx="$OUTPUT_DIR/bom.spdx.json") 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ bom.spdx.json"
echo ""

# Generate CSV format
echo "Generating CSV report..."
(cd "$SBOM_WORKDIR" && run_sbomnix "$NIX_RESULT" --impure --include-vulns --csv="$OUTPUT_DIR/sbom.csv") 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ sbom.csv"
echo ""

# Run vulnerability scan
echo "Running vulnerability scan..."
# Enable experimental Nix features required by vulnix
export NIX_CONFIG="experimental-features = nix-command flakes"
VULNXSCAN_LOG="$SBOM_WORKDIR/vulnxscan.log"
# vulnxscan writes a large console report to stderr. Keep output quiet on success,
# but show the log if the scan fails.
if ! (cd "$SBOM_WORKDIR" && run_vulnxscan "$NIX_RESULT" --out "$OUTPUT_DIR/vulns.csv") \
  >/dev/null 2>"$VULNXSCAN_LOG"; then
  echo "Error: vulnerability scan failed" >&2
  if [ -s "$VULNXSCAN_LOG" ]; then
    echo "--- vulnxscan log ---" >&2
    cat "$VULNXSCAN_LOG" >&2
    echo "---------------------" >&2
  fi
  exit 1
fi
if [ -f "$OUTPUT_DIR/vulns.csv" ] && [ -s "$OUTPUT_DIR/vulns.csv" ]; then
  echo "  ✓ vulns.csv"

  # Deduplicate CVE-like rows in-place so the final output stays a single CSV.
  # This removes duplicates like DEBIAN-CVE-YYYY-NNNN / UBUNTU-CVE-YYYY-NNNN / CVE-YYYY-NNNN.
  if command -v python3 >/dev/null 2>&1 && [ -f "$REPO_ROOT/nix/scripts/dedup_cves.py" ]; then
    echo "Deduplicating CVE rows in vulns.csv..."
    python3 "$REPO_ROOT/nix/scripts/dedup_cves.py" --csv "$OUTPUT_DIR/vulns.csv" --inplace --strategy debian || true
  fi
else
  echo "  ⚠ Vulnerability scan produced no results"
fi
echo ""

# Generate dependency graph
echo "Generating dependency graph..."
# Save current directory and change to output dir
pushd "$OUTPUT_DIR" >/dev/null
if run_nixgraph --depth 30 "$NIX_RESULT" 2>&1 | grep -E "INFO|Wrote" || true; then
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

OPENSSL_NOTE=""
if [ "$TARGET" = "server" ]; then
  if [ "$LINK" = "static" ]; then
    OPENSSL_NOTE="OpenSSL is statically linked in the binary"
  else
    OPENSSL_NOTE="OpenSSL is dynamically linked in the binary"
  fi
else
  OPENSSL_NOTE="SBOM targets the OpenSSL derivation itself"
fi

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
    "$OPENSSL_NOTE",
    "All dependencies are from Nix store with pinned versions",
    "SBOM reflects the exact Nix build output (derivation closure)"
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
echo "  - Review: cat $REPO_ROOT/sbom/README.md"
echo "  - Import to Dependency-Track or other SBOM platform"
echo "  - Integrate into CI/CD pipeline"
echo ""
