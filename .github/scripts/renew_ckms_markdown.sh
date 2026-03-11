#!/bin/bash
# Regenerate cli_documentation/docs/cli/main_commands.md from the ckms binary.
# Builds ckms with --features non-fips so that the full (non-FIPS) command set
# is documented.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cargo build -p ckms --features non-fips
"${REPO_ROOT}/target/debug/ckms" markdown \
  "${REPO_ROOT}/cli_documentation/docs/cli/main_commands.md"
