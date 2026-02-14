#!/bin/bash
# Script to regenerate server CLI documentation
# This script is called by the pre-commit hook 'renew-server-doc'

set -e

cargo build -p cosmian_kms_server --features non-fips
./target/debug/cosmian_kms --help | tail -n +2 | {
  printf '```text\n'
  cat
  printf '```\n'
} >documentation/docs/server_cli.md
