#!/bin/bash
# Regenerate cli_documentation/docs/cli/main_commands.md from the ckms binary.
# Builds ckms with --features non-fips so that the full (non-FIPS) command set
# is documented.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

cargo build -p ckms --features non-fips

# Regenerate the detailed per-subcommand reference.
"${REPO_ROOT}/target/debug/ckms" markdown \
  "${REPO_ROOT}/cli_documentation/docs/cli/main_commands.md"

# Regenerate the top-level usage overview from `ckms --help`.
USAGE_MD="${REPO_ROOT}/cli_documentation/docs/usage.md"
{
  echo "# Usage"
  echo ""
  echo '```sh'
  "${REPO_ROOT}/target/debug/ckms" --help 2>&1 | sed 's/[[:space:]]*$//'
  echo '```'
} > "${USAGE_MD}"
echo "Markdown generated to ${USAGE_MD}"
