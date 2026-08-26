#!/usr/bin/env bash
# Smart log-index updater — only runs when log macros actually changed.
#
# Instead of running on every .rs/.ts/.tsx change (which is wasteful),
# this script checks the staged diff for log macro patterns and only
# invokes the log-index updater when relevant changes are detected.
#
# Log macros detected:
#   Rust: tracing::{info, debug, warn, error, trace}!, log::{info, debug, warn, error, trace}!
#   TypeScript: console.{log,info,warn,error,debug}
set -euo pipefail

# Get staged diff (only added/modified lines)
DIFF=$(git diff --cached --diff-filter=ACMR -U0 2>/dev/null || true)

if [[ -z "$DIFF" ]]; then
  exit 0
fi

# Check for Rust log macros
if echo "$DIFF" | grep -qE '^\+.*\b(tracing|log)::(info|debug|warn|error|trace)!\s*\('; then
  echo "  [log-index] log macro changes detected in Rust — updating index"
  mise run docs:log-index
  exit $?
fi

# Check for TypeScript console methods
if echo "$DIFF" | grep -qE '^\+.*\bconsole\.(log|info|warn|error|debug)\s*\('; then
  echo "  [log-index] console method changes detected in TypeScript — updating index"
  mise run docs:log-index
  exit $?
fi

# No log macro changes — skip
exit 0
