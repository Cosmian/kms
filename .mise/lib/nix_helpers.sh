#!/usr/bin/env bash
# .mise/lib/nix_helpers.sh — Nix shell re-entry and build helpers.
#
# Replaces the IN_NIX_SHELL guard pattern from nix.sh. When a task requires
# Nix-provided tools (OpenSSL FIPS, SoftHSM2, etc.), it calls ensure_nix_shell
# which re-execs the task script inside nix-shell if not already inside one.
#
# Source this from a task file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/nix_helpers.sh"
#
# Provides:
#   ensure_nix_shell [nix_attr] [extra_nix_args...]
#   nix_build <attr> <out_link>
#   resolve_pinned_nixpkgs_store
#   prewarm_nixpkgs_and_tools

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_NIX_HELPERS_SH_LOADED:-}" ] && return 0
_MISE_NIX_HELPERS_SH_LOADED=1

# ── Require common.sh ─────────────────────────────────────────────────────────
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
fi

# Re-enter the current script inside a nix-shell if not already inside one.
#
# Usage: ensure_nix_shell [nix_attr] [extra_env_exports...]
#   nix_attr:  shell.nix attribute (e.g., "default", "non-fips"); defaults to inferring
#              from $VARIANT (fips → default attr, non-fips → kms-non-fips attr).
#   The function re-execs the calling script ($MISE_TASK_FILE or $0) with all
#   original arguments inside the nix-shell. Does not return if re-entry occurs.
#
# Environment variables that should survive the transition:
#   VARIANT, LINK, FEATURES_FLAG, HSM_USER_PASSWORD, KMS_*, REDIS_*, MYSQL_*, etc.
ensure_nix_shell() {
  # Already inside nix-shell — nothing to do
  if [ "${IN_NIX_SHELL:-0}" = "1" ]; then
    return 0
  fi

  require_cmd nix-shell "Nix is required for this task. Install Nix: https://nixos.org/download"

  local repo_root
  repo_root="$(get_repo_root)"

  # Determine the script to re-exec.
  # MISE sets MISE_TASK_FILE to the task *directory* for _default tasks, not the
  # _default file itself. When sub-tasks are called via `bash path/to/subtask`
  # they inherit that env var, which would make nix-shell try to exec a directory.
  # Always prefer $0 (the actually executing script) when it is a regular file.
  local task_script
  if [ -f "$0" ]; then
    task_script="$0"
  else
    task_script="${MISE_TASK_FILE:-$0}"
  fi
  # Final safety: if task_script is still a directory, fall back to $0
  if [ -d "${task_script}" ]; then
    task_script="$0"
  fi

  # Determine nix variant argument based on variant
  local nix_variant="${1:-}"
  if [ -z "$nix_variant" ]; then
    nix_variant="${VARIANT:-fips}"
  fi
  shift 2>/dev/null || true

  # Ensure NIX_PATH is set
  if [ -z "${NIX_PATH:-}" ]; then
    export NIX_PATH="nixpkgs=${PIN_URL}"
  fi

  # Build the environment export string for variables that must survive
  local env_exports=""
  for var in VARIANT LINK IN_NIX_SHELL MISE_CONFIG_ROOT MISE_TASK_FILE \
    HSM_USER_PASSWORD SOFTHSM2_CONF SOFTHSM2_HOME \
    KMS_POSTGRES_URL KMS_MYSQL_URL KMS_TEST_DB \
    REDIS_HOST REDIS_PORT \
    TEST_GOOGLE_OAUTH_CLIENT_ID TEST_GOOGLE_OAUTH_CLIENT_SECRET \
    TEST_GOOGLE_OAUTH_REFRESH_TOKEN GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY \
    CI GITHUB_ACTIONS \
    WITH_WASM WITH_HSM WITH_PYTHON WITH_GO WITH_CURL WITH_XKS WITH_OPENSSH WITH_LUKS; do
    if [ -n "${!var:-}" ]; then
      env_exports="${env_exports}export ${var}='${!var}'; "
    fi
  done

  # Re-exec the task script inside nix-shell
  echo "Entering nix-shell (variant=${nix_variant}) for: $(basename "$task_script")"
  exec nix-shell "${repo_root}/shell.nix" \
    --argstr variant "$nix_variant" \
    -I "nixpkgs=${PIN_URL}" \
    --run "${env_exports}export IN_NIX_SHELL=1; bash '${task_script}' $*"
}

# Resolve pinned nixpkgs to a local store path.
resolve_pinned_nixpkgs_store() {
  local path
  if path=$(nix eval --raw "(builtins.fetchTarball \"${PINNED_NIXPKGS_URL}\")" 2>/dev/null); then
    :
  else
    path=$(nix-instantiate --eval -E "builtins.fetchTarball { url = \"${PINNED_NIXPKGS_URL}\"; }" 2>/dev/null | sed -e 's/\"//g') || path=""
  fi
  if [ -n "$path" ] && [ -e "$path" ]; then
    echo "$path"
    return 0
  fi
  return 1
}

# Prewarm nixpkgs and smoke-test tools into the Nix store (online phase).
prewarm_nixpkgs_and_tools() {
  if [ -n "${NO_PREWARM:-}" ]; then
    echo "Skipping prewarm (NO_PREWARM set)"
    return 0
  fi
  echo "Prewarming pinned nixpkgs into the store..."
  if ! resolve_pinned_nixpkgs_store >/dev/null; then
    nix-instantiate --eval -E "builtins.fetchTarball { url = \"${PINNED_NIXPKGS_URL}\"; }" >/dev/null
  fi
  local nixpkgs_store
  nixpkgs_store=$(resolve_pinned_nixpkgs_store || true)
  if [ -n "$nixpkgs_store" ]; then
    export NIXPKGS_STORE="$nixpkgs_store"
    echo "Pinned nixpkgs realized at: $NIXPKGS_STORE"
    if [ "$(uname)" = "Linux" ]; then
      echo "Prewarming dpkg/rpm/cpio/curl into the store..."
      env -u LD_LIBRARY_PATH -u LD_PRELOAD nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; dpkg' --no-out-link >/dev/null 2>/dev/null || true
      env -u LD_LIBRARY_PATH -u LD_PRELOAD nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; rpm' --no-out-link >/dev/null 2>/dev/null || true
      env -u LD_LIBRARY_PATH -u LD_PRELOAD nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; cpio' --no-out-link >/dev/null 2>/dev/null || true
      env -u LD_LIBRARY_PATH -u LD_PRELOAD nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; curl.bin' --no-out-link >/dev/null 2>/dev/null ||
        env -u LD_LIBRARY_PATH -u LD_PRELOAD nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; curl' --no-out-link >/dev/null 2>/dev/null || true
    fi
  fi
}

# Build a Nix derivation and produce an output link.
# Usage: nix_build <attr> <out_link>
nix_build() {
  local attr="$1" out_link="$2"
  require_cmd nix-build "Nix is required for nix_build."
  echo "Building Nix attribute: $attr -> $out_link"
  env -u LD_LIBRARY_PATH -u LD_PRELOAD nix-build -I "nixpkgs=${PIN_URL}" -A "$attr" -o "$out_link"
}
