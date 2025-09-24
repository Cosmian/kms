#!/bin/bash

# Build the KMS UI in non-fips and fips mode
# This script:
# 1. Builds the WASM component
# 2. Builds the UI
# 3. Copies the built UI to the final location

# Exit on error, print commands
set -ex

bash ./.github/scripts/build_ui.sh
git add crate/server/ui

FEATURES=non-fips bash ./.github/scripts/build_ui.sh
git add crate/server/ui_non_fips
