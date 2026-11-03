#!/usr/bin/env bash
# Pre-push: run only the Playwright specs touched by the UI changes against a throwaway
# `pnpm dev` server. Most flow specs submit to a live KMS, so a KMS must already listen on
# KMS_URL (CI uses http://127.0.0.1:9998); without one the hook skips with a notice.
#
# Selected specs: changed spec files, plus every spec referencing a data-testid found in a
# changed ui/src file. shortcut: HSM/auth specs need their own harness; run
# `mise run test:ui` for those.
set -euo pipefail

BASE="${UI_E2E_BASE_REF:-origin/main}"
PORT="${UI_E2E_PORT:-5173}"
KMS_URL="${UI_E2E_KMS_URL:-http://127.0.0.1:9998}"
cd "$(git rev-parse --show-toplevel)"

git rev-parse --verify -q "$BASE" >/dev/null || {
  echo "  [ui-e2e] base ref '$BASE' not found; set UI_E2E_BASE_REF" >&2
  exit 1
}
CHANGED=$(git diff --name-only --diff-filter=ACMR "$BASE"...HEAD -- ui/src ui/tests/e2e)
[[ -z "$CHANGED" ]] && exit 0

SPECS=""
while IFS= read -r f; do
  case "$f" in
    ui/tests/e2e/*.spec.ts) SPECS+="${f#ui/}"$'\n' ;;
    ui/src/*.tsx)
      while IFS= read -r id; do
        SPECS+=$(grep -lF "$id" ui/tests/e2e/*.spec.ts 2>/dev/null | sed 's|^ui/||' || true)$'\n'
      done < <(grep -oE 'data-testid="[^"]+"' "$f" | cut -d'"' -f2 | sort -u)
      ;;
  esac
done <<<"$CHANGED"
SPECS=$(sort -u <<<"$SPECS" | sed '/^$/d')
[[ -z "$SPECS" ]] && exit 0

if ! curl -s -o /dev/null --noproxy '*' "$KMS_URL/version"; then
  echo "  [ui-e2e] no KMS at $KMS_URL; skipping. Start one (or run 'mise run test:ui') to check:" >&2
  echo "${SPECS//$'\n'/ }" >&2
  exit 0
fi
echo "  [ui-e2e] running: ${SPECS//$'\n'/ }"

cd ui
if ! curl -s -o /dev/null --noproxy '*' "http://127.0.0.1:${PORT}/ui/"; then
  VITE_KMS_URL="$KMS_URL" pnpm dev --port "$PORT" --host 127.0.0.1 --strictPort >/tmp/ui-e2e-vite.log 2>&1 &
  VITE_PID=$!
  trap 'kill "$VITE_PID" 2>/dev/null || true' EXIT
  for _ in $(seq 30); do
    curl -s -o /dev/null --noproxy '*' "http://127.0.0.1:${PORT}/ui/" && break
    sleep 1
  done
fi

# shellcheck disable=SC2086 # SPECS is a newline-separated list of paths without spaces
NO_PROXY=127.0.0.1,localhost PLAYWRIGHT_BASE_URL="http://127.0.0.1:${PORT}" \
  PLAYWRIGHT_WORKERS=2 pnpm exec playwright test --retries=0 $SPECS
