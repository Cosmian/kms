#!/usr/bin/env bash
# upgrade-kms.sh — Pull and restart the Cosmian KMS container
#
# Usage: bash upgrade-kms.sh <TAG_ONLY>
#
# Runs entirely on the remote Oracle server (copied there via scp).
# Exits non-zero if the container fails to start within 60 seconds.

set -euo pipefail

TAG_ONLY="${1:?TAG_ONLY (arg 1) is required}"

cd /opt/cosmian-kms
sed -i "s|ghcr.io/cosmian/kms:.*|ghcr.io/cosmian/kms:${TAG_ONLY}|" docker-compose.yml
docker compose pull kms
docker compose up -d kms

deadline=$((SECONDS + 60))
until [ "$(docker inspect -f '{{.State.Running}}' cosmian-kms 2>/dev/null)" = "true" ]; do
  if [ $SECONDS -ge $deadline ]; then
    echo "Timed out waiting for cosmian-kms to start" >&2
    exit 1
  fi
  sleep 2
done
echo "cosmian-kms is running"
