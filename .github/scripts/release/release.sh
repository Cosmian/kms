#!/bin/bash

set -ex

OLD_VERSION="$1"
NEW_VERSION="$2"

# When --ci is passed as a third argument, skip the pre-commit hooks section.
# The CI workflow handles those checks (Nix hash updates, SBOM, UI build) as
# dedicated jobs with the appropriate environments.
CI_MODE=false
if [ "${3:-}" = "--ci" ]; then
  CI_MODE=true
fi

# Use SED_BINARY from environment if set, otherwise default to 'sed'
# On MacOS - install gnu-sed with brew
if command -v gsed >/dev/null 2>&1; then
  SED_BINARY="gsed"
  SED_IN_PLACE=(-i)
elif [[ "$OSTYPE" == "darwin"* ]]; then
  SED_BINARY="sed"
  SED_IN_PLACE=(-i "")
else
  SED_BINARY="sed"
  SED_IN_PLACE=(-i)
fi

${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" Cargo.toml
# Subcrates
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/access/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/clients/clap/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/clients/ckms/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/clients/pkcs11/module/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/clients/pkcs11/provider/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/clients/client_utils/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/crypto/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/base_hsm/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/crypt2pay/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/proteccio/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/smartcardhsm/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/softhsm2/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/utimaco/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/interfaces/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/kmip/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/clients/client/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/server/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/server_database/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/test_kms_server/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/clients/wasm/Cargo.toml

# Other files
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" .github/scripts/nix.sh
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" .github/scripts/windows/windows_ui.ps1

${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" nix/kms-server.nix
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" nix/ui.nix
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" nix/docker.nix
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" nix/signing-keys/README.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" nix/README.md

${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" ui/package.json
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/index.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation/installation_getting_started.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation/marketplace_guide.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/certifications_and_compliance/fips.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/integrations/databases/oracle_tde.md

# Update CLI documentation with new version
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" cli_documentation/docs/installation.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" cli_documentation/docs/index.md

${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" README.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" .github/copilot-instructions.md

# Skip all pre-commit hooks when running in CI mode.
# The workflow handles each concern as a dedicated job:
#   - Nix hash updates  : the `update-nix-hashes` CI job
#   - SBOM / CBOM       : the `commit-sbom` CI job
#   - Full lint pass    : the regular CI pipeline that is already triggered
#                         by the branch push
if [ "$CI_MODE" = "true" ]; then
  echo "CI mode: skipping pre-commit hooks (handled by dedicated CI jobs)"
  exit 0
fi

# pre-commit run -a --hook-stage manual release-git-cliff
# Regenerate all docs (server CLI help, ckms markdown, KMIP tables, crypto inventory, CBOM)
bash .github/scripts/docs/generate_docs.sh || true

pre-commit run -a --hook-stage manual nix-build-all
pre-commit run -a --hook-stage manual release-docker-build-ui

pre-commit run -a
