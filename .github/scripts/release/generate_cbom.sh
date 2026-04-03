#!/usr/bin/env bash
# Tolerate error
# set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VERSION=$("$SCRIPT_DIR/get_version.sh")

python3 "$SCRIPT_DIR/../sbom/generate_cbom.py" \
  --output cbom/cbom.cdx.json \
  --kms-version "$VERSION"
