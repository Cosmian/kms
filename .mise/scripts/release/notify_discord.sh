#!/usr/bin/env bash
# .mise/scripts/release/notify_discord.sh
#
# Post a Cosmian KMS release announcement embed to a Discord channel via an
# Incoming Webhook.
#
# Usage: notify_discord.sh <version> [notes_file]
#   version    — e.g. 5.24.0
#   notes_file — path to release notes file (default: /tmp/release_notes.md)
#
# Required env: DISCORD_WEBHOOK_URL

set -euo pipefail

VERSION="${1:?Usage: notify_discord.sh <version> [notes_file]}"
NOTES_FILE="${2:-/tmp/release_notes.md}"

: "${DISCORD_WEBHOOK_URL:?DISCORD_WEBHOOK_URL must be set}"

NOTES=$(cat "$NOTES_FILE")

# Discord embed description limit: 4096 characters.
# Cap at 3900 to leave room for the "read more" suffix.
MAX=3900
if [ "${#NOTES}" -gt "$MAX" ]; then
  NOTES="${NOTES:0:$MAX}"$'\n\n'"[… full notes](https://github.com/Cosmian/kms/releases/tag/$VERSION)"
fi

PAYLOAD=$(jq -n \
  --arg version "$VERSION" \
  --arg description "$NOTES" \
  --arg url "https://github.com/Cosmian/kms/releases/tag/$VERSION" \
  '{
    "embeds": [{
      "title": ("🚀 Cosmian KMS " + $version + " released"),
      "description": $description,
      "url": $url,
      "color": 3447003
    }]
  }')

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "$DISCORD_WEBHOOK_URL")

if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
  echo "[INFO] Discord notification sent for release $VERSION (HTTP $HTTP_STATUS)."
else
  echo "[ERROR] Discord webhook returned HTTP $HTTP_STATUS." >&2
  exit 1
fi
