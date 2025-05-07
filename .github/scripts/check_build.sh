#!/bin/bash

set -e

# Install cargo deny if not already installed
# cargo install --version 0.18.2 cargo-deny --locked

find . -name "Cargo.toml" -not -path "./Cargo.toml" -not -path "./cli/Cargo.toml" -exec dirname {} \; | while read -r dir; do
  echo "Running cargo build in $dir"
  pushd "$dir"
  cargo build
  cargo test -- --nocapture --skip hsm --skip google_cse
  cargo clippy --all-targets -- -D warnings
  cargo deny check advisories
  popd
done

cargo hack build --all --feature-powerset
