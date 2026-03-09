#!/bin/bash
# Regenerate the TOML configuration block in documentation/docs/server_configuration_file.md
# and keep pkg/kms.toml and crate/server/kms_template.toml identical to that block.
# All three are kept in sync by building the KMS server binary and calling --print-default-config.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET="${REPO_ROOT}/documentation/docs/server_configuration_file.md"
PKG_TOML="${REPO_ROOT}/pkg/kms.toml"
KMS_TEMPLATE="${REPO_ROOT}/crate/server/kms_template.toml"
TOML_TMP=$(mktemp /tmp/kms_default_config.XXXXXX.toml)
trap 'rm -f "${TOML_TMP}"' EXIT

# Build the server binary (non-fips, debug)
cargo build -p cosmian_kms_server --features non-fips

# Generate the default config TOML from the binary
"${REPO_ROOT}/target/debug/cosmian_kms" --print-default-config > "${TOML_TMP}"

# Update the documentation TOML block, pkg/kms.toml, and crate/server/kms_template.toml.
python3 - "${TARGET}" "${TOML_TMP}" "${PKG_TOML}" "${KMS_TEMPLATE}" << 'PYEOF'
import sys, re

target_path, toml_path, pkg_toml_path, kms_template_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

with open(toml_path) as f:
    new_toml = f.read()

# ── 1. Update the documentation TOML block ──────────────────────────────────────
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
    f.write(new_content)

print(f"Regenerated {target_path} from `--print-default-config`")

# ── 2. pkg/kms.toml and crate/server/kms_template.toml = generated output ───────
for path in (pkg_toml_path, kms_template_path):
    with open(path, "w") as f:
        f.write(new_toml)
    print(f"Updated {path}")
PYEOF
