#!/usr/bin/env bash
# Smart docs regeneration — only runs when CLI args or config options change.
#
# Detects changes to:
#   - clap derive macros (#[command], #[arg], #[clap])
#   - Server config structs (pub struct *Config)
#   - CLI command definitions
#
# Only triggers docs regeneration when these patterns change.
set -euo pipefail

# Get staged diff (only added/modified lines)
DIFF=$(git diff --cached --diff-filter=ACMR -U0 2>/dev/null || true)

if [[ -z "$DIFF" ]]; then
  exit 0
fi

NEEDS_REGEN=false

# Check for clap derive macro changes
if echo "$DIFF" | grep -qE '^\+.*#\[(command|arg|clap|value_parser)(\]|\()'; then
  echo "  [docs] clap derive macro changes detected"
  NEEDS_REGEN=true
fi

# Check for CLI command struct changes
if echo "$DIFF" | grep -qE '^\+.*pub struct.*(Args|Command|Opts|Cli)'; then
  echo "  [docs] CLI command struct changes detected"
  NEEDS_REGEN=true
fi

# Check for server config struct changes
if echo "$DIFF" | grep -qE '^\+.*pub struct.*(Config|Settings)'; then
  echo "  [docs] server config struct changes detected"
  NEEDS_REGEN=true
fi

# Check for config field changes (pub fields in config structs)
if echo "$DIFF" | grep -qE '^\+.*pub [a-z_]+:' && echo "$DIFF" | grep -qE '(crate/server/src/config|crate/clients/clap)'; then
  echo "  [docs] config field changes detected"
  NEEDS_REGEN=true
fi

if [[ "$NEEDS_REGEN" == "true" ]]; then
  echo "  [docs] regenerating documentation..."
  mise run docs:generate --skip-cbom
  exit $?
fi

# No doc-affecting changes — skip
exit 0
