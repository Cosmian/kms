#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose down -v
rm -rf tls jwt
echo "Stack removed, generated certs/keys cleaned up."
