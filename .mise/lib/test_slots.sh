#!/usr/bin/env bash
# .mise/lib/test_slots.sh — Port isolation for concurrent KMS test runs.
#
# When multiple KMS repository clones run tests on the same host, hardcoded
# Docker port mappings and container names collide.  This library introduces a
# single knob — KMS_TEST_SLOT (integer, default 0) — that deterministically
# shifts every host port by `slot × 1000` and prefixes Docker project names.
#
# Source this from any task or script file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/test_slots.sh"
#
# Then use the KMS_SLOT_* variables instead of hardcoded port numbers.
# Slot 0 produces identical values to the previous hardcoded defaults, so
# existing workflows are backward-compatible with no changes.
#
# Provides:
#   slot_init              — compute and export all KMS_SLOT_* variables
#   slot_check_ports_free  — verify none of the slot's ports are already bound
#   slot_info              — print a human-readable summary of the slot layout
#
# Exports (after slot_init):
#   COMPOSE_PROJECT_NAME          — "kms-slot-<N>"
#   KMS_SLOT_DATA_DIR             — "/tmp/kms-slot-<N>"
#
#   Database host ports:
#     KMS_SLOT_POSTGRES_PORT, KMS_SLOT_POSTGRES_MTLS_PORT
#     KMS_SLOT_MYSQL_PORT, KMS_SLOT_PERCONA_PORT, KMS_SLOT_MARIADB_PORT
#     KMS_SLOT_MYSQL_MTLS_PORT, KMS_SLOT_REDIS_PORT
#
#   KMS server host ports:
#     KMS_SLOT_HTTP_PORT, KMS_SLOT_TLS_PORT, KMS_SLOT_TLS13_PORT
#     KMS_SLOT_KMIP_PORT, KMS_SLOT_KMIP_TLS13_PORT
#     KMS_SLOT_LB_PORT
#     KMS_SLOT_KMS_CONF_PORT, KMS_SLOT_KMS_EXAMPLE_PORT
#     KMS_SLOT_KMS_ORACLE_PORT
#
#   Observability host ports:
#     KMS_SLOT_OTEL_GRPC_PORT, KMS_SLOT_OTEL_HTTP_PORT
#     KMS_SLOT_OTEL_METRICS_PORT, KMS_SLOT_JAEGER_PORT
#
#   Third-party host ports:
#     KMS_SLOT_ORACLE_PORT, KMS_SLOT_EDB_PORT
#     KMS_SLOT_IRIS_WEB_PORT, KMS_SLOT_IRIS_SUPER_PORT
#
#   Computed database URLs:
#     KMS_POSTGRES_URL, KMS_MYSQL_URL, KMS_MARIADB_URL
#     KMS_PERCONA_URL, KMS_REDIS_URL

# ── Guard against double-sourcing ─────────────────────────────────────────────
[ -n "${_MISE_TEST_SLOTS_SH_LOADED:-}" ] && return 0
_MISE_TEST_SLOTS_SH_LOADED=1

# ── Constants ─────────────────────────────────────────────────────────────────

# Stride between slots.  1000 gives each slot a full 1000-port range, avoiding
# any overlap between the many "variant" ports (e.g. 5432/5433, 3306/3307/3308).
# Supports up to ~5 concurrent slots before exceeding the 65535 port limit.
readonly _SLOT_STRIDE=1000

# ── Base ports (slot 0 values = previous hardcoded defaults) ──────────────────

# Database services (host-side ports; container-internal ports stay fixed)
readonly _BASE_POSTGRES_PORT=5432
readonly _BASE_POSTGRES_MTLS_PORT=5433
readonly _BASE_MYSQL_PORT=3306
readonly _BASE_PERCONA_PORT=3307
readonly _BASE_MARIADB_PORT=3308
readonly _BASE_MYSQL_MTLS_PORT=3309
readonly _BASE_REDIS_PORT=6379

# KMS HTTP/TLS server
readonly _BASE_HTTP_PORT=9998
readonly _BASE_TLS_PORT=9999
readonly _BASE_TLS13_PORT=10000

# KMIP socket server
readonly _BASE_KMIP_PORT=5696
readonly _BASE_KMIP_TLS13_PORT=5697

# Docker image test KMS instances
readonly _BASE_KMS_CONF_PORT=11098
readonly _BASE_KMS_EXAMPLE_PORT=12098
readonly _BASE_KMS_NO_CONF_PORT=13098
readonly _BASE_KMS_NONROOT_PORT=14098
readonly _BASE_KMS_TLS_NONROOT_PORT=15099

# Load balancer
readonly _BASE_LB_PORT=18080

# Oracle KMS
readonly _BASE_KMS_ORACLE_PORT=19998

# Observability
readonly _BASE_OTEL_GRPC_PORT=4317
readonly _BASE_OTEL_HTTP_PORT=4318
readonly _BASE_OTEL_METRICS_PORT=8889
readonly _BASE_JAEGER_PORT=16686

# Third-party services
readonly _BASE_ORACLE_PORT=1521
readonly _BASE_EDB_PORT=5444
readonly _BASE_IRIS_WEB_PORT=52773
readonly _BASE_IRIS_SUPER_PORT=1972
readonly _BASE_DB2_PORT=50000

# ── slot_init ─────────────────────────────────────────────────────────────────
# Compute and export all slot-aware variables.
# Call once, early in your script, after sourcing this file.
slot_init() {
  KMS_TEST_SLOT="${KMS_TEST_SLOT:-0}"
  export KMS_TEST_SLOT

  if ! [[ "$KMS_TEST_SLOT" =~ ^[0-9]+$ ]]; then
    echo "ERROR: KMS_TEST_SLOT must be a non-negative integer, got '${KMS_TEST_SLOT}'" >&2
    return 1
  fi

  local offset=$((KMS_TEST_SLOT * _SLOT_STRIDE))

  # ── Docker project isolation ──────────────────────────────────────────────
  export COMPOSE_PROJECT_NAME="kms-slot-${KMS_TEST_SLOT}"

  # ── File-system isolation ─────────────────────────────────────────────────
  export KMS_SLOT_DATA_DIR="/tmp/kms-slot-${KMS_TEST_SLOT}"
  mkdir -p "${KMS_SLOT_DATA_DIR}"

  # ── Database host ports ───────────────────────────────────────────────────
  export KMS_SLOT_POSTGRES_PORT=$((_BASE_POSTGRES_PORT + offset))
  export KMS_SLOT_POSTGRES_MTLS_PORT=$((_BASE_POSTGRES_MTLS_PORT + offset))
  export KMS_SLOT_MYSQL_PORT=$((_BASE_MYSQL_PORT + offset))
  export KMS_SLOT_PERCONA_PORT=$((_BASE_PERCONA_PORT + offset))
  export KMS_SLOT_MARIADB_PORT=$((_BASE_MARIADB_PORT + offset))
  export KMS_SLOT_MYSQL_MTLS_PORT=$((_BASE_MYSQL_MTLS_PORT + offset))
  export KMS_SLOT_REDIS_PORT=$((_BASE_REDIS_PORT + offset))

  # ── KMS server host ports ─────────────────────────────────────────────────
  export KMS_SLOT_HTTP_PORT=$((_BASE_HTTP_PORT + offset))
  export KMS_SLOT_TLS_PORT=$((_BASE_TLS_PORT + offset))
  export KMS_SLOT_TLS13_PORT=$((_BASE_TLS13_PORT + offset))
  export KMS_SLOT_KMIP_PORT=$((_BASE_KMIP_PORT + offset))
  export KMS_SLOT_KMIP_TLS13_PORT=$((_BASE_KMIP_TLS13_PORT + offset))
  export KMS_SLOT_KMS_CONF_PORT=$((_BASE_KMS_CONF_PORT + offset))
  export KMS_SLOT_KMS_EXAMPLE_PORT=$((_BASE_KMS_EXAMPLE_PORT + offset))
  export KMS_SLOT_KMS_NO_CONF_PORT=$((_BASE_KMS_NO_CONF_PORT + offset))
  export KMS_SLOT_KMS_NONROOT_PORT=$((_BASE_KMS_NONROOT_PORT + offset))
  export KMS_SLOT_KMS_TLS_NONROOT_PORT=$((_BASE_KMS_TLS_NONROOT_PORT + offset))
  export KMS_SLOT_LB_PORT=$((_BASE_LB_PORT + offset))
  export KMS_SLOT_KMS_ORACLE_PORT=$((_BASE_KMS_ORACLE_PORT + offset))

  # ── Observability host ports ──────────────────────────────────────────────
  export KMS_SLOT_OTEL_GRPC_PORT=$((_BASE_OTEL_GRPC_PORT + offset))
  export KMS_SLOT_OTEL_HTTP_PORT=$((_BASE_OTEL_HTTP_PORT + offset))
  export KMS_SLOT_OTEL_METRICS_PORT=$((_BASE_OTEL_METRICS_PORT + offset))
  export KMS_SLOT_JAEGER_PORT=$((_BASE_JAEGER_PORT + offset))

  # ── Third-party service host ports ────────────────────────────────────────
  export KMS_SLOT_ORACLE_PORT=$((_BASE_ORACLE_PORT + offset))
  export KMS_SLOT_EDB_PORT=$((_BASE_EDB_PORT + offset))
  export KMS_SLOT_IRIS_WEB_PORT=$((_BASE_IRIS_WEB_PORT + offset))
  export KMS_SLOT_IRIS_SUPER_PORT=$((_BASE_IRIS_SUPER_PORT + offset))
  export KMS_SLOT_DB2_PORT=$((_BASE_DB2_PORT + offset))

  # ── Computed database URLs (consumed by Rust tests and MISE tasks) ────────
  export KMS_POSTGRES_URL="postgresql://kms:kms@127.0.0.1:${KMS_SLOT_POSTGRES_PORT}/kms"
  export KMS_MYSQL_URL="mysql://kms:kms@127.0.0.1:${KMS_SLOT_MYSQL_PORT}/kms"
  export KMS_MARIADB_URL="mysql://kms:kms@127.0.0.1:${KMS_SLOT_MARIADB_PORT}/kms"
  export KMS_PERCONA_URL="mysql://kms:kms@127.0.0.1:${KMS_SLOT_PERCONA_PORT}/kms"
  export KMS_REDIS_URL="redis://127.0.0.1:${KMS_SLOT_REDIS_PORT}"

  # ── Validate port range ───────────────────────────────────────────────────
  # The highest base port is IRIS_WEB (52773).  Check it won't exceed 65535.
  local max_port=$((_BASE_IRIS_WEB_PORT + offset))
  if ((max_port > 65535)); then
    echo "ERROR: KMS_TEST_SLOT=${KMS_TEST_SLOT} produces ports above 65535 (max=${max_port})" >&2
    return 1
  fi
}

# ── slot_check_ports_free ─────────────────────────────────────────────────────
# Verify that none of the slot's critical ports are already bound.
# Returns 0 if all free, 1 if any are in use.  Best-effort: works with ss or
# lsof; silently succeeds if neither is available.
slot_check_ports_free() {
  local ports=(
    "$KMS_SLOT_POSTGRES_PORT" "$KMS_SLOT_MYSQL_PORT" "$KMS_SLOT_REDIS_PORT"
    "$KMS_SLOT_HTTP_PORT" "$KMS_SLOT_TLS_PORT" "$KMS_SLOT_KMIP_PORT"
    "$KMS_SLOT_LB_PORT" "$KMS_SLOT_OTEL_GRPC_PORT"
  )

  local check_cmd=""
  if command -v ss >/dev/null 2>&1; then
    check_cmd="ss"
  elif command -v lsof >/dev/null 2>&1; then
    check_cmd="lsof"
  else
    return 0
  fi

  local port failed=0
  for port in "${ports[@]}"; do
    local in_use=false
    if [ "$check_cmd" = "ss" ]; then
      if ss -tlnH 2>/dev/null | grep -q ":${port} "; then
        in_use=true
      fi
    else
      if lsof -iTCP:"${port}" -sTCP:LISTEN -t >/dev/null 2>&1; then
        in_use=true
      fi
    fi
    if [ "$in_use" = "true" ]; then
      echo "WARNING: Port ${port} is already in use (slot ${KMS_TEST_SLOT})" >&2
      failed=1
    fi
  done
  return $failed
}

# ── slot_info ─────────────────────────────────────────────────────────────────
# Print a human-readable summary of the current slot's port layout.
slot_info() {
  cat <<EOF
KMS Test Slot: ${KMS_TEST_SLOT}
  Project name:     ${COMPOSE_PROJECT_NAME}
  Data directory:   ${KMS_SLOT_DATA_DIR}

  Database ports:
    PostgreSQL:     ${KMS_SLOT_POSTGRES_PORT}
    PostgreSQL TLS: ${KMS_SLOT_POSTGRES_MTLS_PORT}
    MySQL:          ${KMS_SLOT_MYSQL_PORT}
    Percona:        ${KMS_SLOT_PERCONA_PORT}
    MariaDB:        ${KMS_SLOT_MARIADB_PORT}
    MySQL TLS:      ${KMS_SLOT_MYSQL_MTLS_PORT}
    Redis:          ${KMS_SLOT_REDIS_PORT}

  KMS server ports:
    HTTP:           ${KMS_SLOT_HTTP_PORT}
    TLS:            ${KMS_SLOT_TLS_PORT}
    TLS 1.3:        ${KMS_SLOT_TLS13_PORT}
    KMIP:           ${KMS_SLOT_KMIP_PORT}
    KMIP TLS 1.3:   ${KMS_SLOT_KMIP_TLS13_PORT}
    LB:             ${KMS_SLOT_LB_PORT}

  Database URLs:
    Postgres: ${KMS_POSTGRES_URL}
    MySQL:    ${KMS_MYSQL_URL}
    Redis:    ${KMS_REDIS_URL}
EOF
}

# ── Auto-init on source ──────────────────────────────────────────────────────
# Automatically compute the slot when this file is sourced, so callers only
# need `source test_slots.sh` without an explicit `slot_init` call.
slot_init
