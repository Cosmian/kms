#!/usr/bin/env bash
# Upload build artifacts to package.cosmian.com with a write-only, directory-restricted rsync key.
#
# The server pins the key to `rrsync -wo -munge -no-del /mnt/package/kms` (forced command): no shell,
# no download, no delete, no path outside the upload root. Every remote path below is therefore
# relative to /mnt/package/kms. Used by .github/actions/push-package-cosmian.
#
# Environment (all values come from the calling action, never interpolated into this script):
#   SUBDIR           required  sub-directory under the version directory
#   FILES            newline-separated bash globs relative to the workspace   } exactly one of
#   DIRECTORY        directory whose contents (nested files included) are sent } FILES / DIRECTORY
#   VERSION_DIR      optional  overrides the tag / last_build/<branch> prefix
#   KNOWN_HOSTS      required  pinned host key line(s) of the package server
#   SSH_PRIVATE_KEY  required  dedicated upload key (PACKAGE_COSMIAN_SSH_PRIVATE_KEY)
#   GITHUB_REF, GITHUB_REF_NAME, GITHUB_HEAD_REF, GITHUB_OUTPUT: as set by GitHub Actions
set -euo pipefail
set +x
umask 077

PACKAGE_HOST="package.cosmian.com"
PACKAGE_USER="kms-ci-upload"
REMOTE_ROOT="/mnt/package/kms"

fail() {
  echo "::error::$*" >&2
  exit 1
}

# A relative path made of [A-Za-z0-9._-] components only: no empty, `.` or `..` component.
validate_relative_path() {
  local label="$1" value="$2" component
  [[ "${value}" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || fail "Invalid ${label}: '${value}'"
  local IFS=/
  for component in ${value}; do
    case "${component}" in . | ..) fail "Invalid ${label} (dot component): '${value}'" ;; esac
  done
}

# rsync reads `host:path` as a remote source: force a path prefix on relative local names.
local_path() {
  case "$1" in /* | ./*) printf '%s' "$1" ;; *) printf './%s' "$1" ;; esac
}

: "${SUBDIR:?SUBDIR is required}"
: "${KNOWN_HOSTS:?Package server SSH host key is not configured}"
: "${SSH_PRIVATE_KEY:?Package server SSH private key is not configured}"
FILES="${FILES:-}"
DIRECTORY="${DIRECTORY:-}"
if [ -n "${FILES//[[:space:]]/}" ] && [ -n "${DIRECTORY}" ]; then fail "Set exactly one of files or directory"; fi
if [ -z "${FILES//[[:space:]]/}" ] && [ -z "${DIRECTORY}" ]; then fail "Set exactly one of files or directory"; fi

if [ -n "${VERSION_DIR:-}" ]; then
  version="${VERSION_DIR}"
elif [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  version="${GITHUB_REF_NAME}"
else
  version="last_build/${GITHUB_HEAD_REF:-${GITHUB_REF#refs/heads/}}"
fi
validate_relative_path "version directory" "${version}"
validate_relative_path "subdir" "${SUBDIR}"
relative_dir="${version}/${SUBDIR}"

# ── Collect the sources; refuse anything that is not a plain regular file ────
sources=()
if [ -n "${DIRECTORY}" ]; then
  [ -d "${DIRECTORY}" ] && [ ! -L "${DIRECTORY}" ] || fail "Not a directory: ${DIRECTORY}"
  [ -z "$(find "${DIRECTORY}" -mindepth 1 \( -type l -o \( ! -type f ! -type d \) \) -print -quit)" ] ||
    fail "Symlink or special file under ${DIRECTORY}"
  [ -n "$(find "${DIRECTORY}" -type f -print -quit)" ] || fail "No file to upload under ${DIRECTORY}"
  sources=("$(local_path "${DIRECTORY%/}")/")
else
  shopt -s nullglob globstar
  declare -A seen=()
  while IFS= read -r pattern; do
    [ -z "${pattern}" ] && continue
    # shellcheck disable=SC2206 # intentional glob expansion of the caller's pattern
    matches=(${pattern})
    [ "${#matches[@]}" -gt 0 ] || fail "No file matches '${pattern}'"
    for f in "${matches[@]}"; do
      { [ -f "${f}" ] && [ ! -L "${f}" ]; } || fail "Not a regular file: ${f}"
      [ -z "${seen[${f##*/}]:-}" ] || fail "Two uploads share the name '${f##*/}'"
      seen["${f##*/}"]=1
      sources+=("$(local_path "${f}")")
    done
  done <<<"${FILES}"
  [ "${#sources[@]}" -gt 0 ] || fail "Nothing to upload"
fi

# ── Private SSH material, removed on every exit path ─────────────────────────
ssh_dir="$(mktemp -d)"
trap 'rm -rf -- "${ssh_dir}"' EXIT
chmod 700 "${ssh_dir}"
[[ "${ssh_dir}" != *[[:space:]]* ]] || fail "TMPDIR must not contain whitespace"
printf '%s\n' "${SSH_PRIVATE_KEY}" >"${ssh_dir}/key"
printf '%s\n' "${KNOWN_HOSTS}" >"${ssh_dir}/known_hosts"
chmod 600 "${ssh_dir}/key" "${ssh_dir}/known_hosts"
cat >"${ssh_dir}/config" <<EOF
Host ${PACKAGE_HOST}
  User ${PACKAGE_USER}
  IdentityFile ${ssh_dir}/key
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking yes
  UserKnownHostsFile ${ssh_dir}/known_hosts
  GlobalKnownHostsFile /dev/null
  VerifyHostKeyDNS no
  ForwardAgent no
  ClearAllForwardings yes
  ConnectTimeout 30
EOF

# --mkpath creates the version/subdir tree; no --delete, no --protect-args (rrsync rejects it).
rsync -rt --mkpath --chmod=D755,F644 --timeout=300 \
  -e "ssh -F ${ssh_dir}/config" \
  -- "${sources[@]}" "${PACKAGE_USER}@${PACKAGE_HOST}:${relative_dir}/"

echo "Uploaded to ${REMOTE_ROOT}/${relative_dir}"
if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "remote-dir=${REMOTE_ROOT}/${relative_dir}" >>"${GITHUB_OUTPUT}"; fi
