#!/bin/sh

set -ex

OLD_VERSION="$1"
NEW_VERSION="$2"

sed -i "s/$OLD_VERSION/$NEW_VERSION/g" Cargo.toml
# Subcrates
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" crate/access/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/cli/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/client_utils/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/crypto/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/hsm/base_hsm/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/hsm/proteccio/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/hsm/utimaco/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/interfaces/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/kmip/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/kms_client/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/server/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/server_database/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/test_kms_server/Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" kms/crate/wasm/Cargo.toml

# Other files
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" Dockerfile
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" ui/package.json
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/index.md
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation/installation_getting_started.md
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation/marketplace_guide.md
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/fips.md
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" README.md
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" version

cargo build
git cliff -u -p CHANGELOG.md -t "$NEW_VERSION"
