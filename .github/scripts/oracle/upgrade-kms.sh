#!/usr/bin/env bash
# upgrade-kms.sh — Pull and restart the Cosmian KMS container, preserving SQLite data.
#
# Usage: bash upgrade-kms.sh <TAG_ONLY>
#
# The docker-compose.yml has a bug: the volume is mounted at /root/cosmian-kms/sqlite-data
# but KMS writes to /var/lib/cosmian-kms/sqlite-data, so data is lost on each container
# recreation. This script migrates the data to the correct volume path on every upgrade.

set -euo pipefail

TAG_ONLY="${1:?TAG_ONLY (arg 1) is required}"
COMPOSE_DIR=/opt/cosmian-kms
KMS_DATA_PATH=/var/lib/cosmian-kms/sqlite-data
BACKUP_DIR=/tmp/kms-data-backup

cd "${COMPOSE_DIR}"

# ── Step 1: Backup SQLite data from the running container (before it is recreated)
echo "Backing up KMS SQLite data from running container..."
rm -rf "${BACKUP_DIR}"
mkdir -p "${BACKUP_DIR}"
# Try both possible paths (old wrong path and correct path)
docker cp "cosmian-kms:${KMS_DATA_PATH}/." "${BACKUP_DIR}/" 2>/dev/null \
  || docker cp "cosmian-kms:/root/cosmian-kms/sqlite-data/." "${BACKUP_DIR}/" 2>/dev/null \
  || echo "No existing KMS data to migrate (fresh install)"

# ── Step 2: Fix docker-compose.yml — update image tag and volume path
sudo sed -i "s|ghcr.io/cosmian/kms:.*|ghcr.io/cosmian/kms:${TAG_ONLY}|" docker-compose.yml
sudo sed -i 's|kms-data:/root/cosmian-kms/sqlite-data|kms-data:/var/lib/cosmian-kms/sqlite-data|g' \
  docker-compose.yml

# ── Step 3: Pull new image and recreate container with correct volume path
docker compose pull kms
docker compose up -d kms

# ── Step 4: Wait for KMS to be ready
deadline=$((SECONDS + 60))
until curl -sf http://localhost:9998/version >/dev/null 2>&1; do
  if [ $SECONDS -ge $deadline ]; then
    echo "Timed out waiting for cosmian-kms to start" >&2
    exit 1
  fi
  sleep 2
done
echo "cosmian-kms is running: $(curl -sf http://localhost:9998/version)"

# ── Step 5: Restore SQLite data into the new volume — only if backup has real data
# SQLite uses WAL (Write-Ahead Logging): kms.db starts at 4096 bytes (header only)
# while actual data accumulates in kms.db-wal (can be hundreds of KB). Both files
# must be considered together to decide whether real data exists.
# Threshold: any real backup (kms.db + kms.db-wal) with at least one key is well above 50 KB.
backup_db="${BACKUP_DIR}/kms.db"
backup_wal="${BACKUP_DIR}/kms.db-wal"
backup_size=0
if [ -f "${backup_db}" ]; then
  db_size=$(stat -c%s "${backup_db}" 2>/dev/null || stat -f%z "${backup_db}" 2>/dev/null || echo 0)
  wal_size=0
  if [ -f "${backup_wal}" ]; then
    wal_size=$(stat -c%s "${backup_wal}" 2>/dev/null || stat -f%z "${backup_wal}" 2>/dev/null || echo 0)
  fi
  backup_size=$((db_size + wal_size))
fi

if [ "${backup_size}" -gt 51200 ]; then
  echo "Restoring KMS SQLite data into new volume (backup size: ${backup_size} bytes)..."
  docker cp "${BACKUP_DIR}/." "cosmian-kms:${KMS_DATA_PATH}/"
  # Restart KMS so it picks up the restored database
  docker compose restart kms
  deadline=$((SECONDS + 60))
  until curl -sf http://localhost:9998/version >/dev/null 2>&1; do
    if [ $SECONDS -ge $deadline ]; then
      echo "Timed out waiting for cosmian-kms after data restore" >&2
      exit 1
    fi
    sleep 2
  done
  echo "KMS data restored — $(curl -sf http://localhost:9998/version)"
else
  echo "Backup is empty or corrupt (${backup_size} bytes total < 50 KB threshold) — keeping fresh KMS database"
fi

rm -rf "${BACKUP_DIR}"
echo "Upgrade complete: ghcr.io/cosmian/kms:${TAG_ONLY}"

