#!/usr/bin/env bash
# Throw-away OpenBao dev server used as the KMS `X-Vault-Token` verifier, reached through
# bao_lookup_proxy.py. Sourced by .mise/tasks/test/interop/openbao and test_secret_rotation.sh
# after .mise/lib/common.sh.
#
# Provides:
#   bao_verifier_start <container-name> <work-dir>  start both; sets BAO_VERIFIER_URL
#   bao_verifier_login <user>                        print a fresh userpass token for <user>
#   bao_verifier_stop                                remove the proxy and the container (idempotent)
#
# Ports are never picked then released: Docker publishes the container port on a host port it
# keeps (`-p 127.0.0.1::8200`) and the proxy reports the port of the listener it holds.

[ -n "${_BAO_VERIFIER_SH_LOADED:-}" ] && return 0
_BAO_VERIFIER_SH_LOADED=1

# BAO_IMAGE is resolved in bao_verifier_start: this file is sourced before the callers' Docker checks.
BAO_VERIFIER_NAME=""
BAO_VERIFIER_PROXY_PID=""
BAO_VERIFIER_URL=""
_BAO_VERIFIER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_bao_verifier_cli() {
  docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=verifier-root "${BAO_VERIFIER_NAME}" bao "$@"
}

# _bao_verifier_wait <seconds> <command...>: retry the command every 0.5 s until the deadline.
_bao_verifier_wait() {
  local tries=$(($1 * 2))
  shift
  for _ in $(seq 1 "${tries}"); do
    "$@" && return 0
    sleep 0.5
  done
  return 1
}

# Succeeds once the port file is written or the proxy has exited (the caller checks which).
_bao_verifier_proxy_settled() {
  [[ -s "$1" ]] || ! kill -0 "${BAO_VERIFIER_PROXY_PID}" 2>/dev/null
}

bao_verifier_start() {
  local host_port port_file="$2/bao-proxy.port" proxy_log="$2/bao-proxy.log" image="${BAO_IMAGE:-}"
  [[ -n "${image}" ]] || image="$(compose_image openbao)"
  BAO_VERIFIER_NAME="$1"
  docker run -d --name "${BAO_VERIFIER_NAME}" -p 127.0.0.1::8200 \
    -e BAO_DEV_ROOT_TOKEN_ID=verifier-root -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    "${image}" >/dev/null
  _bao_verifier_wait 30 _bao_verifier_cli status >/dev/null 2>&1 ||
    print_error "the OpenBao token verifier did not start: $(docker logs "${BAO_VERIFIER_NAME}" 2>&1 | tail -n 20)"
  host_port="$(docker port "${BAO_VERIFIER_NAME}" 8200/tcp)"
  host_port="${host_port%%$'\n'*}"
  host_port="${host_port##*:}"
  [[ "${host_port}" =~ ^[0-9]+$ ]] || print_error "Docker did not publish the OpenBao verifier port"
  _bao_verifier_cli auth enable userpass >/dev/null

  run_isolated python3 "${_BAO_VERIFIER_DIR}/bao_lookup_proxy.py" "${port_file}" \
    "http://127.0.0.1:${host_port}" >"${proxy_log}" 2>&1 &
  BAO_VERIFIER_PROXY_PID=$!
  # The proxy listens before it writes the file; an exited proxy ends the wait early.
  _bao_verifier_wait 15 _bao_verifier_proxy_settled "${port_file}" && [[ -s "${port_file}" ]] ||
    print_error "the token lookup proxy did not report its port: $(cat "${proxy_log}")"
  BAO_VERIFIER_URL="http://127.0.0.1:$(<"${port_file}")"
  print_status "OpenBao token verifier on 127.0.0.1:${host_port}, lookup proxy at ${BAO_VERIFIER_URL}"
}

bao_verifier_login() {
  _bao_verifier_cli write auth/userpass/users/"$1" password="$1-password" >/dev/null
  _bao_verifier_cli write -format=json auth/userpass/login/"$1" password="$1-password" |
    python3 -c "import sys, json; print(json.load(sys.stdin)['auth']['client_token'])"
}

bao_verifier_stop() {
  if [[ -n "${BAO_VERIFIER_PROXY_PID}" ]]; then kill "${BAO_VERIFIER_PROXY_PID}" 2>/dev/null || true; fi
  if [[ -n "${BAO_VERIFIER_NAME}" ]]; then docker rm -f "${BAO_VERIFIER_NAME}" >/dev/null 2>&1 || true; fi
  BAO_VERIFIER_PROXY_PID=""
  BAO_VERIFIER_NAME=""
}
