#!/usr/bin/env bash
# .mise/lib/suites.sh — Test-suite registry, leaf prologue and runner.
#
# Every runnable test task declares its facts once, in a `#SUITE` header line placed after its
# `#USAGE` block and before `set -euo pipefail`:
#
#   #SUITE key=value [key=value ...]        (values never contain spaces; lists are comma-separated)
#
#   variants      REQUIRED  fips | non-fips | fips,non-fips
#   needs         comma list of probes and actions (below)                      default: none
#   ci            CI leg name; suites with the same `ci` share a runner per variant  default: not in CI
#   ci_variants   variants CI runs (subset of variants)                          default: variants
#   pr_variants   variants CI runs on pull_request events (subset of ci_variants) default: ci_variants
#   scope         public (secret-free) | js (no secrets, JS toolchain) | upstream (secrets, skipped on forks)
#                                                                                default: public
#   lock          concurrency group shared with hardware users                   default: none
#   bench         HSM model for the nightly bench steps                          default: none
#
# `needs` items. A local run evaluates all of them; CI=true evaluates only those marked (CI) and
# ignores the others, so the suite runs and fails on its own there.
#   nix | docker | k8s | cmd:<c> | file:<repo path>   probe: unmet => the suite is skipped
#   os:<Linux|Darwin>   (CI) probe on `uname -s`
#   env:<VAR>           (CI) probe: VAR set and non-empty (CI also emits a ::warning::)
#   profile             (CI) action: source ~/.cosmian/<last id segment>.sh when it exists
#   apt:<pkg>           (CI) probe locally; CI on Linux installs the package before the suite
#   compose:<service>   (CI) `docker compose up -d <service>` once, before the first suite
#
# Source this from a task file:
#   source "${MISE_CONFIG_ROOT}/.mise/lib/suites.sh"
#
# Provides:
#   suite_id_of <file>                            task file -> suite id (db/psql -> db:psql, spire/_default -> spire)
#   suites_index                                  `id|file|variants|needs|ci|ci_variants|pr_variants|scope|lock|bench` per suite
#   suite_field <key> <file>                      one #SUITE field of <file> (empty if absent)
#   suite_init <default-variant> [WITH_FLAG...]   standard leaf prologue (variant/os gate, optional nix entry)
#   suites_main <selector...>                     run or --list suites: ids, @<group>, @all

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_SUITES_SH_LOADED:-}" ] && return 0
_MISE_SUITES_SH_LOADED=1

# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
# shellcheck source=.mise/lib/nix_helpers.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/nix_helpers.sh"

SUITES_TASK_DIR="${MISE_CONFIG_ROOT}/.mise/tasks/test"

# Whole-line grammar of a #SUITE line (everything after the `#SUITE ` prefix).
_SUITE_RE='^([a-z_]+=[A-Za-z0-9:,._/-]*)( [a-z_]+=[A-Za-z0-9:,._/-]*)*$'

# ── Registry ──────────────────────────────────────────────────────────────────

# Prints the suite id of a task file: its path under tasks/test/, without a trailing /_default,
# with `/` replaced by `:`.
suite_id_of() {
  local id="${1#*/.mise/tasks/test/}"
  id="${id%/_default}"
  printf '%s\n' "${id//\//:}"
}

# Prints the `#SUITE` line of <file> without its prefix (nothing when the file has none).
_suite_line() { sed -n '/^#SUITE /{s/^#SUITE //p;q;}' "$1"; }

# Parses the #SUITE line of <file> into the globals S_VARIANTS S_NEEDS S_CI S_CI_VARIANTS
# S_PR_VARIANTS S_SCOPE S_LOCK S_BENCH. Returns 1 when the file has no #SUITE line; a malformed
# line is fatal. Call it in the current shell, never in a command substitution.
_suite_parse() {
  local file="$1" line kv key val item
  S_VARIANTS='' S_NEEDS='' S_CI='' S_CI_VARIANTS='' S_PR_VARIANTS='' S_SCOPE=public S_LOCK='' S_BENCH=''
  line="$(_suite_line "$file")"
  [ -n "$line" ] || return 1
  [[ $line =~ $_SUITE_RE ]] || print_error "${file}: invalid #SUITE line"
  for kv in $line; do
    key="${kv%%=*}"
    val="${kv#*=}"
    case "$key" in
      variants) S_VARIANTS="$val" ;;
      needs) S_NEEDS="$val" ;;
      ci) S_CI="$val" ;;
      ci_variants) S_CI_VARIANTS="$val" ;;
      pr_variants) S_PR_VARIANTS="$val" ;;
      scope) S_SCOPE="$val" ;;
      lock) S_LOCK="$val" ;;
      bench) S_BENCH="$val" ;;
      *) print_error "${file}: unknown #SUITE key ${key}" ;;
    esac
  done
  [ -n "$S_VARIANTS" ] || print_error "${file}: #SUITE needs variants="
  for item in ${S_VARIANTS//,/ }; do
    case "$item" in fips | non-fips) ;; *) print_error "${file}: unknown variant '${item}' in #SUITE variants=" ;; esac
  done
  for item in ${S_NEEDS//,/ }; do
    case "$item" in
      nix | docker | k8s | profile | os:Linux | os:Darwin | cmd:?* | file:?* | env:?* | apt:?* | compose:?*) ;;
      *) print_error "${file}: unknown #SUITE need '${item}'" ;;
    esac
  done
}

# Prints one field of <file>'s #SUITE line (nothing if absent). Usage: suite_field <key> <file>
suite_field() {
  local kv
  for kv in $(_suite_line "$2"); do
    if [ "${kv%%=*}" = "$1" ]; then
      printf '%s\n' "${kv#*=}"
      return 0
    fi
  done
}

# Prints one `id|file|variants|needs|ci|ci_variants|pr_variants|scope|lock|bench` line per suite,
# sorted by id; absent fields stay empty (scope defaults to public). Fatal on a malformed header,
# so capture it as `x="$(suites_index)" || exit 1`.
suites_index() {
  local file
  while IFS= read -r file; do
    _suite_parse "$file" || continue
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$(suite_id_of "$file")" "$file" "$S_VARIANTS" "$S_NEEDS" \
      "$S_CI" "$S_CI_VARIANTS" "$S_PR_VARIANTS" "$S_SCOPE" "$S_LOCK" "$S_BENCH"
  done < <(find "$SUITES_TASK_DIR" -type f ! -name '*.md') | LC_ALL=C sort -t'|' -k1,1
}

# ── Leaf prologue ─────────────────────────────────────────────────────────────

# The task file being executed: $0 when it is a regular file (as ensure_nix_shell decides), else
# $MISE_TASK_FILE (which a parent task may leak into a `bash <leaf>` child).
_suite_self() {
  if [ -f "$0" ]; then printf '%s\n' "$0"; else printf '%s\n' "${MISE_TASK_FILE:-$0}"; fi
}

# Standard prologue of a test leaf: initialises variant/link/logging/REPO_ROOT, rejects a variant
# or OS the suite's #SUITE header does not allow, and — only when WITH_* flags are given — exports
# them and re-enters the pinned nix-shell (the script then restarts; this function is idempotent).
# Usage: suite_init <default-variant> [WITH_FLAG...]
suite_init() {
  local default_variant="$1" file id variants need flag
  shift
  kms_init_env "${usage_variant:-${default_variant}}" "${usage_link:-static}"
  setup_test_logging
  REPO_ROOT="$(get_repo_root "${MISE_CONFIG_ROOT}")"
  file="$(_suite_self)"
  id="$(suite_id_of "$file")"
  variants="$(suite_field variants "$file")"
  case ",${variants}," in
    ",,") ;; # no #SUITE header: nothing to enforce
    *",${VARIANT},"*) ;;
    *) print_error "${id} supports --variant ${variants//,/ or } only (got: ${VARIANT})" ;;
  esac
  for need in $(suite_field needs "$file" | tr ',' ' '); do
    case "$need" in
      os:*) [ "$(uname -s)" = "${need#os:}" ] || print_error "${id} requires ${need#os:}" ;;
    esac
  done
  if [ "$#" -gt 0 ]; then
    for flag in "$@"; do export "${flag}=1"; done
    ensure_nix_shell
  fi
}

# ── Gating ────────────────────────────────────────────────────────────────────

# Sources ~/.cosmian/<last segment of suite id>.sh when it exists (hardware credentials for local runs).
_suite_profile() {
  local profile="${HOME}/.cosmian/${1##*:}.sh"
  if [ -f "$profile" ]; then
    # shellcheck source=/dev/null
    source "$profile"
  fi
}

# Memoised machine-global probe: runs "$@" once per process and remembers the verdict.
_suite_probe() {
  local key="$*" var
  key="${key//[^A-Za-z0-9]/_}"
  var="_SUITES_PROBE_${key}"
  if [ -z "${!var:-}" ]; then
    if "$@" >/dev/null 2>&1; then printf -v "$var" '%s' ok; else printf -v "$var" '%s' no; fi
  fi
  [ "${!var}" = ok ]
}

# Prints the first unset `env:` need of a suite, after sourcing its profile. Call it in a command
# substitution so the sourced profile does not leak into the caller. Usage: _suite_unset_env <id> <needs>
_suite_unset_env() {
  local id="$1" needs="$2" item
  for item in ${needs//,/ }; do
    if [ "$item" = profile ]; then _suite_profile "$id"; fi
  done
  for item in ${needs//,/ }; do
    case "$item" in
      env:*) has_env_vars "${item#env:}" || {
        printf '%s\n' "${item#env:}"
        return 0
      } ;;
    esac
  done
}

# Sets SKIP_REASON to why a suite cannot run here (empty when it can). Reads VARIANT and REPO_ROOT;
# CI=true skips the probes that only make sense on a developer machine.
# Usage: _suite_skip_reason <id> <variants> <needs>
_suite_skip_reason() {
  local id="$1" variants="$2" needs="$3" item var
  SKIP_REASON=''
  case ",${variants}," in
    *",${VARIANT},"*) ;;
    *)
      SKIP_REASON="supports --variant ${variants//,/ or } only"
      return 0
      ;;
  esac
  for item in ${needs//,/ }; do
    case "$item" in
      os:*) if [ "$(uname -s)" != "${item#os:}" ]; then
        SKIP_REASON="requires ${item#os:}"
        return 0
      fi ;;
    esac
  done
  var="$(_suite_unset_env "$id" "$needs")"
  if [ -n "$var" ]; then
    SKIP_REASON="env ${var} not set"
    return 0
  fi
  if [ "${CI:-}" = "true" ]; then return 0; fi
  for item in ${needs//,/ }; do
    case "$item" in
      apt:*) has_cmd "${item#apt:}" || {
        SKIP_REASON="${item#apt:} not installed"
        return 0
      } ;;
      nix) _suite_probe has_cmd nix-shell || {
        SKIP_REASON="nix-shell not found"
        return 0
      } ;;
      docker) _suite_probe docker_ready || {
        SKIP_REASON="Docker is not running"
        return 0
      } ;;
      cmd:*) _suite_probe has_cmd "${item#cmd:}" || {
        SKIP_REASON="'${item#cmd:}' not found on PATH"
        return 0
      } ;;
      file:*) [ -f "${REPO_ROOT}/${item#file:}" ] || {
        SKIP_REASON="${item#file:} not found (submodule not checked out?)"
        return 0
      } ;;
      k8s) _suite_probe kubectl cluster-info --request-timeout=5s || {
        SKIP_REASON="no reachable Kubernetes cluster"
        return 0
      } ;;
    esac
  done
}

# ── Runner ────────────────────────────────────────────────────────────────────

# True when suite id $1 is selected by selector $2: `@all`, `@<group>` (the id or its `<group>:` children) or an exact id.
_suite_match() {
  case "$2" in
    @all) return 0 ;;
    @*) [ "$1" = "${2#@}" ] || [[ $1 == "${2#@}":* ]] ;;
    *) [ "$1" = "$2" ] ;;
  esac
}

# CI only: installs the `apt:` needs missing on this Linux runner. Usage: _suite_prepare <needs>
_suite_prepare() {
  local item
  if [ "${CI:-}" != "true" ] || [ "$(uname -s)" != "Linux" ]; then return 0; fi
  for item in ${1//,/ }; do
    case "$item" in
      apt:*) has_cmd "${item#apt:}" || { sudo apt-get update -qq && sudo apt-get install -y -qq "${item#apt:}"; } ;;
    esac
  done
}

# Runs one suite as `mise run test:<id>` in a subshell and returns its status. The variant/link flags
# are passed only when the task declares them; the usage_* environment covers tasks that do not
# (and stops the parent's own values leaking in).
# Usage: _suite_run <id> <file> <needs>
_suite_run() {
  local id="$1" file="$2" needs="$3" item
  local -a flags=()
  if grep -q '^#USAGE flag "-v --variant' "$file"; then flags+=(--variant "$VARIANT"); fi
  if grep -q '^#USAGE flag "-l --link' "$file"; then flags+=(--link "$LINK"); fi
  (
    _suite_prepare "$needs" || exit 1
    for item in ${needs//,/ }; do
      if [ "$item" = profile ]; then _suite_profile "$id"; fi
    done
    usage_variant="$VARIANT" usage_link="$LINK" usage_list='' mise run "test:${id}" ${flags[@]+"${flags[@]}"}
  )
}

# Runs the selected suites (ids, @<group>, @all) under --variant/--link, skipping those that cannot
# run here with their reason, then prints a summary; returns 1 if any suite failed. With --list it
# only prints what would run or be skipped.
# Usage: suites_main <selector...>
suites_main() {
  local sel id file variants needs hit matched ok item i n list=0 services=''
  local -a sel_id=() sel_file=() sel_needs=() sel_reason=() pass=() skip=() fail=()

  [ "$#" -gt 0 ] || print_error "no suite selected"
  kms_init_env "${usage_variant:-fips}" "${usage_link:-static}"
  REPO_ROOT="$(get_repo_root "${MISE_CONFIG_ROOT}")"
  if [ "${usage_list:-}" = "true" ]; then list=1; fi
  SUITES_INDEX="$(suites_index)" || exit 1

  for sel in "$@"; do
    hit=0
    while IFS='|' read -r id _; do
      if _suite_match "$id" "$sel"; then
        hit=1
        break
      fi
    done <<<"$SUITES_INDEX"
    [ "$hit" = 1 ] || print_error "unknown suite: ${sel}"
  done

  # Pass 1 — gate: why can't each selected suite run here? Collect the compose services of those that can.
  while IFS='|' read -r id file variants needs _; do
    matched=0
    for sel in "$@"; do
      if _suite_match "$id" "$sel"; then
        matched=1
        break
      fi
    done
    [ "$matched" = 1 ] || continue
    _suite_skip_reason "$id" "$variants" "$needs"
    sel_id+=("$id")
    sel_file+=("$file")
    sel_needs+=("$needs")
    sel_reason+=("$SKIP_REASON")
    if [ -z "$SKIP_REASON" ]; then
      for item in ${needs//,/ }; do
        case "$item" in
          compose:*) case " ${services} " in *" ${item#compose:} "*) ;; *) services="${services:+${services} }${item#compose:}" ;; esac ;;
        esac
      done
    elif [ "${GITHUB_ACTIONS:-}" = "true" ]; then
      case "$SKIP_REASON" in "env "*) echo "::warning::test:${id} skipped: ${SKIP_REASON}" ;; esac
    fi
  done <<<"$SUITES_INDEX"
  n=${#sel_id[@]}

  if [ "$list" = 1 ]; then
    i=0
    while [ "$i" -lt "$n" ]; do
      if [ -n "${sel_reason[$i]}" ]; then
        printf '  %-28s %s\n' "${sel_id[$i]}" "skip: ${sel_reason[$i]}"
      else
        printf '  %-28s %s\n' "${sel_id[$i]}" "run"
      fi
      i=$((i + 1))
    done
    if [ -n "$services" ]; then echo "would start compose: ${services}"; fi
    return 0
  fi

  # Start every compose service once, before the first suite.
  if [ -n "$services" ]; then
    print_status "Starting compose services: ${services}"
    # shellcheck disable=SC2086 # services is a space-separated service list
    if ! docker compose -f "${REPO_ROOT}/docker-compose.yml" up -d ${services}; then
      if [ "${CI:-}" = "true" ]; then print_error "could not start compose services: ${services}"; fi
      i=0
      while [ "$i" -lt "$n" ]; do
        case ",${sel_needs[$i]}," in
          *,compose:*) if [ -z "${sel_reason[$i]}" ]; then sel_reason[i]="could not start compose: ${services}"; fi ;;
        esac
        i=$((i + 1))
      done
    fi
  fi

  # Pass 2 — run.
  i=0
  while [ "$i" -lt "$n" ]; do
    id="${sel_id[$i]}"
    if [ -n "${sel_reason[$i]}" ]; then
      skip+=("${id} — ${sel_reason[$i]}")
    else
      if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::group::test:${id} (${VARIANT})"
      else
        print_header "test:${id} (${VARIANT})"
      fi
      if _suite_run "$id" "${sel_file[$i]}" "${sel_needs[$i]}"; then
        pass+=("$id")
        ok=1
      else
        fail+=("$id")
        ok=0
      fi
      if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::endgroup::"
        if [ "$ok" = 0 ]; then echo "::error::test:${id} failed"; fi
      fi
    fi
    i=$((i + 1))
  done

  echo ""
  echo "============================================"
  for item in ${pass[@]+"${pass[@]}"}; do echo "  [PASS] ${item}"; done
  for item in ${skip[@]+"${skip[@]}"}; do echo "  [SKIP] ${item}"; done
  for item in ${fail[@]+"${fail[@]}"}; do echo "  [FAIL] ${item}"; done
  printf '  PASS: %d  SKIP: %d  FAIL: %d\n' "${#pass[@]}" "${#skip[@]}" "${#fail[@]}"
  [ "${#fail[@]}" -eq 0 ]
}
