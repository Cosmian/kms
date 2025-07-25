#!/bin/bash

set -ex

OLD_VERSION="$1"
NEW_VERSION="$2"

# Use SED_BINARY from environment if set, otherwise default to 'sed'
# On MacOS - install gnu-sed with brew
if command -v gsed >/dev/null 2>&1; then
  SED_BINARY="gsed"
  SED_IN_PLACE=(-i)
else
  SED_BINARY="sed"
  SED_IN_PLACE=(-i "")
fi

${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" Cargo.toml
# Subcrates
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/access/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/cli/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/client_utils/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/crypto/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/base_hsm/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/proteccio/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/hsm/utimaco/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/interfaces/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/kmip/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/kms_client/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/server/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/server_database/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/test_kms_server/Cargo.toml
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" crate/wasm/Cargo.toml

# Other files
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" Dockerfile
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" ui/package.json
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/index.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation/installation_getting_started.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation/marketplace_guide.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/fips.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" README.md
${SED_BINARY} "${SED_IN_PLACE[@]}" "s/$OLD_VERSION/$NEW_VERSION/g" version

cargo build
git cliff -u -p CHANGELOG.md -t "$NEW_VERSION"
