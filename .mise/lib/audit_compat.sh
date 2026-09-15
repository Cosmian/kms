#!/usr/bin/env bash
# Shared helpers for the OpenSearch/Splunk audit JSONL compatibility mise tasks
# (test:audit-compat-opensearch, test:audit-compat-splunk). Keeps the container
# lifecycle and Python setup boilerplate in one place instead of duplicated per backend.

[ -n "${_MISE_AUDIT_COMPAT_SH_LOADED:-}" ] && return 0
_MISE_AUDIT_COMPAT_SH_LOADED=1

_AUDIT_COMPAT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  # shellcheck source=.mise/lib/common.sh
  source "${_AUDIT_COMPAT_LIB_DIR}/common.sh"
fi

# require_cmd docker/python3/curl, common to both backends.
# Usage: audit_compat_require_common_cmds "OpenSearch"
audit_compat_require_common_cmds() {
  require_cmd docker "Docker is required to run the ephemeral $1 container."
  require_cmd python3
  require_cmd curl
}

# Registers an EXIT trap that force-removes the named ephemeral container.
# Usage: audit_compat_container_cleanup_trap "${CONTAINER_NAME}"
audit_compat_container_cleanup_trap() {
  local container_name="$1"
  # shellcheck disable=SC2064  # intentional immediate expansion of container_name
  trap "print_status 'Removing container ${container_name}'; docker rm -f '${container_name}' >/dev/null 2>&1 || true" EXIT
}

# Installs the shared Python requirements into an isolated, reusable venv under
# target/ (never the system python3, see review feedback on PR #1131), and
# prints the venv's python3 executable path on stdout.
# Usage: PYTHON_BIN=$(audit_compat_python "${REPO_ROOT}")
audit_compat_python() {
  local repo_root="$1"
  local venv_dir="${repo_root}/target/audit-compat-venv"
  if [ ! -x "${venv_dir}/bin/python3" ]; then
    python3 -m venv "${venv_dir}" >&2
  fi
  "${venv_dir}/bin/python3" -m pip install --quiet -r "${repo_root}/.mise/scripts/test/requirements-audit-compat.txt" >&2
  echo "${venv_dir}/bin/python3"
}
