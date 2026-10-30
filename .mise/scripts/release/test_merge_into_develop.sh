#!/usr/bin/env bash
set -euo pipefail

# Exercise only disposable repositories: no remotes, protected branches or tags.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR:?}"' EXIT
BASE_HASH="sha256-$(printf '%032d' 0 | base64 | tr -d '\n')"
DEVELOP_HASH="sha256-$(printf '%032d' 1 | base64 | tr -d '\n')"
RELEASE_HASH="sha256-$(printf '%032d' 2 | base64 | tr -d '\n')"
HASH_FILES=(
  server.vendor.static.sha256 server.vendor.dynamic.sha256
  cli.vendor.linux.sha256 cli.vendor.static.darwin.sha256
  cli.vendor.dynamic.darwin.sha256 ui.vendor.fips.sha256
  ui.vendor.non-fips.sha256 ui.pnpm.linux.sha256
)

# Each case has the same eight divergent generated hashes as the failed release.
setup_case() {
  local scenario="$1" file
  mkdir "${WORK_DIR}/${scenario}"
  cd "${WORK_DIR}/${scenario}"
  git init -q -b develop
  git config user.name 'Release merge test'
  git config user.email 'release-merge-test@example.invalid'
  git config commit.gpgsign false
  mkdir -p nix/expected-hashes
  for file in "${HASH_FILES[@]}"; do
    printf '%s\n' "${BASE_HASH}" >"nix/expected-hashes/${file}"
  done
  printf '%s\n' "${BASE_HASH}" >nix/expected-hashes/server.vendor.musl-fips.sha256
  printf 'base source\n' >source.txt
  printf 'old lockfile\n' >Cargo.lock
  git add .
  git commit -qm base
  git branch release/test
  for file in "${HASH_FILES[@]}"; do
    printf '%s\n' "${DEVELOP_HASH}" >"nix/expected-hashes/${file}"
  done
  printf '%s\n' "${DEVELOP_HASH}" >nix/expected-hashes/server.vendor.musl-fips.sha256
  if [[ "${scenario}" == source-conflict ]]; then
    printf 'develop source\n' >source.txt
  elif [[ "${scenario}" == mixed-inputs ]]; then
    printf 'develop-only source\n' >new-source.txt
  fi
  git add .
  git commit -qm develop
  DEVELOP_HEAD="$(git rev-parse HEAD)"
  git checkout -q release/test
  for file in "${HASH_FILES[@]}"; do
    printf '%s\n' "${RELEASE_HASH}" >"nix/expected-hashes/${file}"
  done
  printf 'release lockfile\n' >Cargo.lock
  if [[ "${scenario}" == source-conflict ]]; then
    printf 'release source\n' >source.txt
  elif [[ "${scenario}" == invalid-hash ]]; then
    printf 'invalid hash\n' >nix/expected-hashes/server.vendor.static.sha256
  fi
  git add .
  git commit -qm release
  RELEASE_HEAD="$(git rev-parse HEAD)"
  git checkout -q develop
}

setup_case hash-only
bash "${SCRIPT_DIR}/merge_into_develop.sh" release/test
[[ "$(git rev-parse HEAD^1)" == "${DEVELOP_HEAD}" ]]
[[ "$(git rev-parse HEAD^2)" == "${RELEASE_HEAD}" ]]
git diff --exit-code HEAD release/test
[[ -z "$(git status --porcelain)" ]]
MERGED_HEAD="$(git rev-parse HEAD)"
bash "${SCRIPT_DIR}/merge_into_develop.sh" release/test
[[ "$(git rev-parse HEAD)" == "${MERGED_HEAD}" ]]

for SCENARIO in source-conflict mixed-inputs invalid-hash; do
  setup_case "${SCENARIO}"
  if bash "${SCRIPT_DIR}/merge_into_develop.sh" release/test; then
    echo "ERROR: ${SCENARIO} unexpectedly succeeded" >&2
    exit 1
  fi
  [[ "$(git rev-parse HEAD)" == "${DEVELOP_HEAD}" ]]
  git rev-parse --verify MERGE_HEAD >/dev/null
  [[ -n "$(git diff --name-only --diff-filter=U)" ]]
done

# A fatal merge error without conflicts must not be converted into a commit.
setup_case invalid-ref
if bash "${SCRIPT_DIR}/merge_into_develop.sh" nonexistent-release; then
  echo 'ERROR: invalid release ref unexpectedly succeeded' >&2
  exit 1
fi
[[ "$(git rev-parse HEAD)" == "${DEVELOP_HEAD}" ]]
if git rev-parse --verify MERGE_HEAD >/dev/null 2>&1; then
  echo 'ERROR: invalid release ref left a merge in progress' >&2
  exit 1
fi
printf 'Release backmerge regression checks passed.\n'
