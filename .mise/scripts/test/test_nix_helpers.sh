#!/usr/bin/env bash
set -euo pipefail

# Exercise real Bash re-entry with a local nix-shell transport, without downloading/building Nix.
REPO_ROOT="$(git rev-parse --show-toplevel)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR:?}"' EXIT
mkdir -p "${WORK_DIR}/bin"

cat >"${WORK_DIR}/bin/nix-shell" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  if [[ "$arg" == *"${EXPECTED_TEST_PASSWORD}"* ]]; then
    echo "Credential exposed in nix-shell arguments" >&2
    exit 1
  fi
done
while [[ $# -gt 0 ]]; do
  if [[ "$1" == --run ]]; then
    exec bash -c "$2"
  fi
  shift
done
echo "Missing nix-shell run command" >&2
exit 1
EOF
chmod 700 "${WORK_DIR}/bin/nix-shell"

cat >"${WORK_DIR}/task with spaces.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${IN_NIX_SHELL:-0}" == 1 ]]; then
  [[ "${HSM_USER_PASSWORD}" == "${EXPECTED_TEST_PASSWORD}" ]] || exit 1
  [[ $# == 2 && "$1" == "first arg with spaces" && "$2" == "${EXPECTED_TEST_ARGUMENT}" ]] || exit 1
  printf 'Re-entry preserved credential and literal arguments\n'
  exit 0
fi
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/nix_helpers.sh"
# A non-exported credential must still survive re-entry, without being placed in argv.
HSM_USER_PASSWORD="${EXPECTED_TEST_PASSWORD}"
ensure_nix_shell fips "$@"
EOF

export PATH="${WORK_DIR}/bin:${PATH}"
export MISE_CONFIG_ROOT="${REPO_ROOT}"
export EXPECTED_TEST_PASSWORD="test-only-password'with-quotes-and-\$metacharacters"
export EXPECTED_TEST_ARGUMENT="literal; touch ${WORK_DIR}/injected"
unset IN_NIX_SHELL HSM_USER_PASSWORD
bash "${WORK_DIR}/task with spaces.sh" "first arg with spaces" "${EXPECTED_TEST_ARGUMENT}"
[[ ! -e "${WORK_DIR}/injected" ]]
printf 'Nix helper regression: no credential in argv; no shell injection\n'
