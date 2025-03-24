#!/bin/sh

# Prerequisites
# sudo apt update
# sudo apt install -y build-essential pkg-config libssl-dev
# curl https://sh.rustup.rs -sSf | sh
# cargo install --locked criterion-table cargo-criterion

cp BENCHMARKS.md BENCHMARKS.md.bak
cargo criterion --message-format=json | criterion-table >BENCHMARKS.md
sed -i 's/([^)]*)//g' BENCHMARKS.md
