#!/usr/bin/env bash
# .mise/lib/ckms.sh — Shared ckms CLI invocation helpers.
# shellcheck disable=SC2154 # ckms_bin/ckms_conf are set by the sourcing script
#
# Provides:
#   ckms_run_fail <args...> — run ckms and abort if it unexpectedly succeeds

[ -n "${_MISE_CKMS_SH_LOADED:-}" ] && return 0
_MISE_CKMS_SH_LOADED=1

_CKMS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  # shellcheck source=.mise/lib/common.sh
  source "${_CKMS_LIB_DIR}/common.sh"
fi

ckms_run_fail() {
  if "${ckms_bin}" --conf-path "${ckms_conf}" "$@" 2>/dev/null; then
    print_error "expected ckms command to fail: $*"
  fi
}
