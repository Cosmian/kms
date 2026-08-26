#!/usr/bin/env bash
# Sync instruction files ↔ pre-commit hooks.
#
# Instruction files define `applyTo` patterns telling AI agents which files
# to apply rules to. Pre-commit hooks should enforce the same rules for the
# same file types. This script validates consistency.
#
# Usage: sync-instructions.sh [--report]
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../../.." || exit 1

# ── Extract applyTo from instruction files ─────────────────────────────
declare -A INST_PATTERNS
for f in .github/instructions/*.instructions.md; do
  name=$(basename "$f" .instructions.md)
  apply=$(awk '/^applyTo:/{gsub(/^applyTo: *\047?/, ""); gsub(/\047$/,""); print; exit}' "$f" || true)
  [[ -n "${apply:-}" ]] && INST_PATTERNS["$name"]="$apply"
done
# ── Build a directory → instruction file index ─────────────────────────
# Map common directory prefixes to the instruction files that cover them.
declare -A DIR_TO_INST
DIR_TO_INST["crate/server/src/routes/aws_xks"]="cloud-providers"
DIR_TO_INST["crate/server/src/routes/azure_ekm"]="cloud-providers"
DIR_TO_INST["crate/server/src/routes/google_cse"]="cloud-providers"
DIR_TO_INST["crate/server/src/routes/ms_dke"]="cloud-providers"
DIR_TO_INST["crate/server_database/src/stores/sql"]="database-tables"
DIR_TO_INST["crate/server_database"]="rust-database"
DIR_TO_INST["crate/server/src/middlewares"]="middlewares"
DIR_TO_INST["crate/server/src/config"]="server-config"
DIR_TO_INST["crate/server/src/core/operations"]="kmip-operations"
DIR_TO_INST["crate/server/src/routes"]="routes"
DIR_TO_INST["crate/server"]="rust-server"
DIR_TO_INST["crate/crypto"]="rust-crypto"
DIR_TO_INST["crate/kmip"]="rust-kmip"
DIR_TO_INST["crate/access"]="rust"
DIR_TO_INST["crate/interfaces"]="rust"
DIR_TO_INST["crate/test_kms_server"]="test-vectors"
DIR_TO_INST["crate/clients/ckms"]="rust-cli"
DIR_TO_INST["crate/clients/clap"]="rust-cli"
DIR_TO_INST["crate/clients/client"]="rust-cli"
DIR_TO_INST["crate/clients/client_utils"]="rust-cli"
DIR_TO_INST["crate/clients/wasm"]="wasm"
DIR_TO_INST["crate/clients/cng"]="rust-cli"
DIR_TO_INST["crate/clients/k8s"]="rust-cli"
DIR_TO_INST["crate/clients/pkcs11"]="rust-cli"
DIR_TO_INST["crate/hsm"]="hsm"
DIR_TO_INST["ui/src"]="typescript-ui"
DIR_TO_INST["ui/tests/e2e"]="playwright"
DIR_TO_INST["documentation"]="docs"
DIR_TO_INST["nix"]="nix"
DIR_TO_INST[".github/workflows"]="github-actions"
DIR_TO_INST[".mise"]="mise"

# ── Extract hooks with files/types from pre-commit config ──────────────
declare -A HOOK_FILES HOOK_TYPES
current=""
while IFS= read -r line; do
  [[ "$line" =~ ^[[:space:]]*-[[:space:]]*id:[[:space:]]*(.+)$ ]] && current="${BASH_REMATCH[1]}"
  [[ -n "$current" && "$line" =~ ^[[:space:]]*files:[[:space:]]*(.+)$ ]] && HOOK_FILES["$current"]="${BASH_REMATCH[1]}"
  [[ -n "$current" && "$line" =~ ^[[:space:]]*types:[[:space:]]*\[(.+)\]$ ]] && HOOK_TYPES["$current"]="${BASH_REMATCH[1]}"
  [[ -n "$current" && "$line" =~ ^[[:space:]]*types_or:[[:space:]]*\[(.+)\]$ ]] && HOOK_TYPES["$current"]="${BASH_REMATCH[1]}"
done <.pre-commit-config.yaml

# ── Validate: each hook's files/types should map to an instruction file ─
GAPS=0

# Map pre-commit types to instruction file categories
declare -A TYPE_TO_INST
TYPE_TO_INST["rust"]="rust"
TYPE_TO_INST["shell"]="bash"
TYPE_TO_INST["python"]="python"
TYPE_TO_INST["javascript"]="typescript-ui"
TYPE_TO_INST["jsx"]="typescript-ui"
TYPE_TO_INST["ts"]="typescript-ui"
TYPE_TO_INST["tsx"]="typescript-ui"
TYPE_TO_INST["json"]="i18n"
TYPE_TO_INST["yaml"]="yaml"
TYPE_TO_INST["markdown"]="markdown"
TYPE_TO_INST["toml"]="toml"

check_hook() {
  local hook_id="$1" gating="$2" gating_type="$3"
  local found=0

  # Check types-based gating
  if [[ "$gating_type" == "types" ]]; then
    for t in ${gating//,/ }; do
      t="${t// /}"
      [[ -n "${TYPE_TO_INST[$t]:-}" ]] && found=1 && break
    done
    [[ $found -eq 0 ]] && {
      echo "  UNCOVERED $hook_id (types: $gating)"
      ((GAPS++))
    }
    return
  fi

  # Check files-based gating: match against DIR_TO_INST
  for dir in "${!DIR_TO_INST[@]}"; do
    if [[ "$gating" == *"$dir"* ]]; then
      found=1
      break
    fi
  done

  # Also check for extension-based patterns
  if [[ $found -eq 0 ]]; then
    for ext in "${!TYPE_TO_INST[@]}"; do
      if [[ "$gating" =~ \.$ext ]]; then
        found=1
        break
      fi
    done
  fi

  # Special cases: Cargo.lock, Cargo.toml, cross-cutting hooks
  if [[ $found -eq 0 ]]; then
    case "$gating" in
      *Cargo*) found=1 ;;               # lockfile-hashes or rust
      *README*) found=1 ;;              # docs
      *\.nix*) found=1 ;;               # nix
      *\.sh*) found=1 ;;                # bash
      *\.py*) found=1 ;;                # python
      *\.md*) found=1 ;;                # markdown
      *\\\.\(rs\|ts\|tsx\)*) found=1 ;; # update-log-index (cross-cutting)
    esac
  fi

  [[ $found -eq 0 ]] && {
    echo "  UNCOVERED $hook_id (files: $gating)"
    ((GAPS++))
  }
}

for hook_id in "${!HOOK_FILES[@]}"; do
  check_hook "$hook_id" "${HOOK_FILES[$hook_id]}" "files"
done
for hook_id in "${!HOOK_TYPES[@]}"; do
  check_hook "$hook_id" "${HOOK_TYPES[$hook_id]}" "types"
done

# ── Report ─────────────────────────────────────────────────────────────
echo "Instruction files: ${#INST_PATTERNS[@]}"
echo "Hooks with file-type gating: $((${#HOOK_FILES[@]} + ${#HOOK_TYPES[@]}))"

if [[ "${1:-}" == "--report" ]]; then
  echo ""
  echo "=== Instruction files ==="
  for inst in $(printf '%s\n' "${!INST_PATTERNS[@]}" | sort); do
    printf "  %-25s %s\n" "$inst" "${INST_PATTERNS[$inst]}"
  done
  echo ""
  echo "=== Directory → instruction mapping ==="
  for dir in $(printf '%s\n' "${!DIR_TO_INST[@]}" | sort); do
    printf "  %-50s → %s\n" "$dir" "${DIR_TO_INST[$dir]}"
  done
fi

echo ""
if [[ $GAPS -gt 0 ]]; then
  echo "⚠ $GAPS gap(s) — update DIR_TO_INST in sync-instructions.sh"
  [[ "${1:-}" != "--report" ]] && exit 1
else
  echo "✓ All hooks covered by instruction files"
fi
exit 0
