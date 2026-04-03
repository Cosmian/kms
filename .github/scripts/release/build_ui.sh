#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

export DOCKER_IMAGE_NAME="ghcr.io/cosmian/kms:latest"

docker compose -f "$SCRIPT_DIR/../docker-compose.yml" up -d
bash "$SCRIPT_DIR/../build/build_ui.sh"
docker compose -f "$SCRIPT_DIR/../docker-compose.yml" down --remove-orphans
