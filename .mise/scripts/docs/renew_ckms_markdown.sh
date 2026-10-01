#!/bin/bash
# Regenerate documentation/docs/kms_clients/cli/main_commands.md from the ckms binary.
# Builds ckms with --features non-fips so that the full (non-FIPS) command set
# is documented.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

cargo build -p ckms --features non-fips

# Regenerate the detailed per-subcommand reference.
"${REPO_ROOT}/target/debug/ckms" markdown \
  "${REPO_ROOT}/documentation/docs/kms_clients/cli/main_commands.md"

# Strip trailing whitespace the generator may emit for subcommands with an
# empty help string (e.g. `fpe keys create`), to keep the trailing-whitespace
# pre-commit hook idempotent.
sed -i.bak 's/[[:space:]]*$//' "${REPO_ROOT}/documentation/docs/kms_clients/cli/main_commands.md"
rm -f "${REPO_ROOT}/documentation/docs/kms_clients/cli/main_commands.md.bak"

# Regenerate the top-level usage overview from `ckms --help`.
USAGE_MD="${REPO_ROOT}/documentation/docs/kms_clients/usage.md"
{
  echo "# Usage"
  echo ""
  echo '```sh'
  "${REPO_ROOT}/target/debug/ckms" --help 2>&1 | sed 's/[[:space:]]*$//'
  echo '```'
} >"${USAGE_MD}"
echo "Markdown generated to ${USAGE_MD}"
