#!/bin/bash

set -ex -o pipefail

# Install rustup non-interactively and pin the toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
    sh -s -- -y --default-toolchain 1.90.0 --profile minimal --no-modify-path

# Source cargo environment from the chosen CARGO_HOME
. "$HOME/.cargo/env"

# Optionally add common components without interaction
rustup component add --toolchain 1.90.0 rustfmt clippy || true

export LD_LIBRARY_PATH=/lib

cargo build
