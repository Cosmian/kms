#!/bin/sh

set -ex

OLD_VERSION="$1"
NEW_VERSION="$2"

sed -i "s/$OLD_VERSION/$NEW_VERSION/g" Cargo.toml
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
