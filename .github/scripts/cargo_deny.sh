#!/bin/bash

set -e


# Install cargo deny if not already installed
# cargo install --version 0.18.2 cargo-deny --locked

# Run cargo deny in each directory containing a Cargo.toml
find . -name "Cargo.toml" -exec dirname {} \; | while read -r dir; do
  echo "Running cargo deny check in $dir"
  (cd "$dir" && cargo deny check advisories)
done
