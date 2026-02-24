#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-.github/scripts/docker-compose.yml}"
RECREATE_NGINX="${RECREATE_NGINX:-1}"
LB_PORT="${LB_PORT:-8080}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf '%s\n' "$*"
}

dc() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

ensure_running() {
  # Prefer `start` (no-op if already running). If the service containers were
  # never created (e.g. running this script standalone), fall back to `up -d`.
  set +e
  dc start "$@"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    dc up -d "$@"
  fi
}

http_code() {
  # Prints just the HTTP status code, or 000 if curl fails.
  curl -sS -o /dev/null -w '%{http_code}' "$LB_URL" || printf '000'
}

http_status_line() {
  # Prints the HTTP status line (e.g., "HTTP/1.1 200 OK"), or "NO RESPONSE".
  curl -sS -D - -o /tmp/kms_lb_health_body.json "$LB_URL" 2>/dev/null | head -n 1 || echo 'NO RESPONSE'
}

print_body() {
  if [[ -f /tmp/kms_lb_health_body.json ]]; then
    cat /tmp/kms_lb_health_body.json
  fi
}

expect_code() {
  local label="$1"
  local want="$2"
  local got
  got="$(http_code)"

  log "=== ${label} ==="
  log "HTTP ${got}"
  print_body || true
  log

  if [[ "$got" != "$want" ]]; then
    log "FAIL: expected HTTP ${want}, got HTTP ${got}" >&2
    exit 1
  fi
  log "PASS"
  log
}

expect_code_one_of() {
  local label="$1"
  shift
  local got
  got="$(http_code)"

  log "=== ${label} ==="
  log "HTTP ${got}"
  print_body || true
  log

  local ok=1
  for want in "$@"; do
    if [[ "$got" == "$want" ]]; then
      ok=0
      break
    fi
  done

  if [[ $ok -ne 0 ]]; then
    log "FAIL: expected one of HTTP $*, got HTTP ${got}" >&2
    exit 1
  fi

  log "PASS"
  log
}

wait_for_code() {
  local label="$1"
  local want="$2"
  local timeout_s="$3"

  log "=== ${label} ==="
  log "Waiting up to ${timeout_s}s for HTTP ${want}"

  local start now elapsed got
  start="$(date +%s)"
  while true; do
    got="$(http_code)"
    if [[ "$got" == "$want" ]]; then
      log "PASS: got HTTP ${want}"
      log
      return 0
    fi

    now="$(date +%s)"
    elapsed=$((now - start))
    if ((elapsed >= timeout_s)); then
      log "FAIL: still not HTTP ${want} after ${elapsed}s (last: HTTP ${got})" >&2
      log "Last status line: $(http_status_line)" >&2
      exit 1
    fi

    sleep 1
  done
}

log "Using compose: ${COMPOSE_FILE}"
log

LB_URL="${LB_URL:-http://localhost:${LB_PORT}/health}"
log "Using /health: ${LB_URL}"
log

if [[ "$RECREATE_NGINX" == "1" ]]; then
  log "Recreating nginx-load-balancer to pick up nginx.conf"
  dc stop nginx-load-balancer || true
  dc rm -f nginx-load-balancer || true
  set +e
  dc create --force-recreate nginx-load-balancer
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    dc up -d --force-recreate nginx-load-balancer
  else
    dc start nginx-load-balancer
  fi
  log
fi

# Ensure the LB stack is up (no-op if already running)
ensure_running postgres kms1 kms2 kms3 nginx-load-balancer

expect_code "baseline" "200"

dc stop kms3
sleep 1
expect_code "after stopping kms3" "200"

dc stop kms2
sleep 1
expect_code "after stopping kms2" "200"

dc stop kms1
sleep 1
# With zero backends, Nginx usually returns 502; 504 is also possible depending on timing.
expect_code_one_of "after stopping kms1 (no backends)" "502" "504"

# Restore backends
log "Restoring kms1..3"
ensure_running kms1 kms2 kms3

# Wait for recovery (nginx resolver valid=10s in our config + peer recovery).
# In practice Nginx can briefly return 502 after all backends were down.
wait_for_code "after restoring kms1..3" "200" 20

log "All checks passed."
