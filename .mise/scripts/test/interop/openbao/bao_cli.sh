#!/usr/bin/env bash
# `bao` CLI wrapper (throw-away container, no host install). Sourced by test_openbao_kv.sh and
# .mise/tasks/test/interop/openbao-auth-verifier after .mise/lib/common.sh.
#
# Reads BAO_IMAGE, BAO_NETWORK (optional) and BAO_CACERT_HOST (may be empty); BAO_ADDR and BAO_TOKEN
# are passed by name so the token stays out of argv.

[ -n "${_BAO_CLI_SH_LOADED:-}" ] && return 0
_BAO_CLI_SH_LOADED=1

# Run the OpenBao CLI in a throw-away container.
bao() {
  local args=(run --rm -i --entrypoint bao -e BAO_ADDR -e BAO_TOKEN)
  if [[ -n "${BAO_NETWORK:-}" ]]; then
    args+=(--network "${BAO_NETWORK}")
  elif [[ "$(uname -s)" == "Linux" ]]; then
    args+=(--network host)
  else
    args+=(--add-host host.docker.internal:host-gateway)
  fi
  if [[ -n "${BAO_CACERT_HOST:-}" ]]; then
    args+=(-v "${BAO_CACERT_HOST}:/ca.crt:ro" -e BAO_CACERT=/ca.crt)
  fi
  docker "${args[@]}" "${BAO_IMAGE}" "$@"
}
