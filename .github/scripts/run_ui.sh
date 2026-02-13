#!/usr/bin/env bash
set -euo pipefail

# cp ui/public/themes/example/branding.json ui/public/branding.json
cp ui/public/themes/cosmian/branding.json ui/public/branding.json

pnpm -C ui build

export COSMIAN_UI_DIST_PATH="ui/dist/"
cargo run -p cosmian_kms_server --features non-fips
