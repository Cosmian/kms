#!/bin/bash
# Regenerate two server documentation artefacts:
#   1. documentation/docs/server_cli.md          – from `cosmian_kms --help`
#   2. documentation/docs/server_configuration_file.md – from `--print-default-config`
# Also keeps pkg/kms.toml and crate/server/kms_template.toml in sync with the
# generated TOML.
#
# Merged from the former renew_server_doc.sh and renew_server_configuration_doc.sh.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET="${REPO_ROOT}/documentation/docs/server_configuration_file.md"
PKG_TOML="${REPO_ROOT}/pkg/kms.toml"
KMS_TEMPLATE="${REPO_ROOT}/crate/server/kms_template.toml"
TOML_TMP=$(mktemp /tmp/kms_default_config.XXXXXX.toml)
trap 'rm -f "${TOML_TMP}"' EXIT

# Build the server binary once (non-fips, debug)
cargo build -p cosmian_kms_server --features non-fips

# ── 1. Regenerate documentation/docs/server_cli.md ───────────────────────────
"${REPO_ROOT}/target/debug/cosmian_kms" --help | tail -n +2 | {
  printf '```text\n'
  cat
  printf '```\n'
} >"${REPO_ROOT}/documentation/docs/server_cli.md"
echo "Regenerated documentation/docs/server_cli.md from --help"

# ── 2. Regenerate server_configuration_file.md, pkg/kms.toml, kms_template.toml
"${REPO_ROOT}/target/debug/cosmian_kms" --print-default-config >"${TOML_TMP}"

python3 - "${TARGET}" "${TOML_TMP}" "${PKG_TOML}" "${KMS_TEMPLATE}" <<'PYEOF'
import sys, re

target_path, toml_path, pkg_toml_path, kms_template_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

with open(toml_path) as f:
    new_toml = f.read()

with open(target_path) as f:
    content = f.read()

new_content = re.sub(
    r'`{3}toml\n.*?\n`{3}$',
    lambda m: '```toml\n' + new_toml.rstrip('\n') + '\n```',
    content,
    count=1,
    flags=re.DOTALL | re.MULTILINE,
)

with open(target_path, "w") as f:
    f.write(new_content.rstrip() + '\n')

print(f"Regenerated {target_path} from `--print-default-config`")

toml_content = new_toml.rstrip('\n') + '\n'
for path in (pkg_toml_path, kms_template_path):
    with open(path, "w") as f:
        f.write(toml_content)
    print(f"Updated {path}")
PYEOF
