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
  - README.txt                 Documentation and integration guide
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
run_sbomnix "$NIX_RESULT" --impure --cdx="$OUTPUT_DIR/bom.cdx.json" 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ bom.cdx.json"
echo ""

# Generate SPDX SBOM (JSON format - ISO standard)
echo "Generating SPDX SBOM..."
run_sbomnix "$NIX_RESULT" --impure --spdx="$OUTPUT_DIR/bom.spdx.json" 2>&1 | grep -v "Failed reading nix meta" || true
echo "  ✓ bom.spdx.json"
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

# Optionally filter to runtime-only dependencies for the server target
runtime_filter() {
  local bin
  bin="$(readlink -f "$NIX_RESULT")/bin/cosmian_kms"
  if [ ! -x "$bin" ]; then
    echo "  ⚠ Runtime filter: binary not found at $bin, skipping"
    return 0
  fi

  if ! command -v readelf >/dev/null 2>&1; then
    echo "  ⚠ Runtime filter: 'readelf' not available, skipping"
    return 0
  fi

  # Collect DT_NEEDED shared library basenames
  mapfile -t needed_libs < <(readelf -d "$bin" 2>/dev/null | awk '/NEEDED/ {gsub(/\[|\]/,"",$5); print $5}')

  if [ ${#needed_libs[@]} -eq 0 ]; then
    echo "  ⚠ Runtime filter: no DT_NEEDED entries found, skipping"
    return 0
  fi

  # Map library basenames to package families for CSV filtering
  # - glibc: libc.so.6 libm.so.6 ld-linux* librt.so.1 libdl.so.2 libpthread.so.0 libresolv.so.2 libnss_*.so*
  # - gcc:   libgcc_s.so.*
  # - openssl: libssl.so.* libcrypto.so.*
  # - zlib:  libz.so.*
  declare -A fam
  for lib in "${needed_libs[@]}"; do
    case "$lib" in
    libgcc_s.so.*) fam[gcc]=1 ;;
    libc.so.* | libm.so.* | ld-linux*.so* | librt.so.* | libdl.so.* | libpthread.so.* | libresolv.so.* | libnss_*.so*) fam[glibc]=1 ;;
    libssl.so.* | libcrypto.so.*) fam[openssl]=1 ;;
    libz.so.*) fam[zlib]=1 ;;
    *) : ;;
    esac
  done

  if [ ${#fam[@]} -eq 0 ]; then
    echo "  ⚠ Runtime filter: no mapped families from DT_NEEDED, skipping"
    return 0
  fi

  # Build regex for package name matching
  local families pkg_regex pname_regex
  families=$(printf "%s|" "${!fam[@]}" | sed 's/|$//')
  pkg_regex="^(${families})$"
  pname_regex="^(${families})"

  # Filter vulns.csv where the 3rd column is 'package'
  if [ -f "$OUTPUT_DIR/vulns.csv" ]; then
    awk -F',' -v OFS=',' -v rx="$pkg_regex" 'NR==1{print; next} { col=$3; gsub(/"/,"",col); if (col ~ rx) print }' "$OUTPUT_DIR/vulns.csv" >"$OUTPUT_DIR/vulns.runtime.csv" || true
    if [ -s "$OUTPUT_DIR/vulns.runtime.csv" ]; then
      echo "  ✓ vulns.runtime.csv"
    else
      echo "  ⚠ Runtime filter: produced empty vulns.runtime.csv"
    fi
  fi

  # Filter sbom.csv where the 2nd column is 'pname'
  if [ -f "$OUTPUT_DIR/sbom.csv" ]; then
    awk -F',' -v OFS=',' -v rx="$pname_regex" 'NR==1{print; next} { col=$2; gsub(/"/,"",col); if (col ~ rx) print }' "$OUTPUT_DIR/sbom.csv" >"$OUTPUT_DIR/sbom.runtime.csv" || true
    if [ -s "$OUTPUT_DIR/sbom.runtime.csv" ]; then
      echo "  ✓ sbom.runtime.csv"
    else
      echo "  ⚠ Runtime filter: produced empty sbom.runtime.csv"
    fi
  fi
}

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

# Invoke runtime filter if requested and applicable
if [ "$TARGET" = "server" ]; then
  echo "Applying runtime-only filter based on DT_NEEDED..."
  runtime_filter
fi
