---
name: 'Bash / Shell Scripts'
description: 'Shell scripting conventions for MISE tasks, reusable scripts, and CI helpers in the Eviden KMS project'
applyTo: '**/*.sh'
---

# Bash / Shell script conventions

## Mandatory header

Every shell script must begin with the following canonical header:

```bash
#!/usr/bin/env bash
set -euo pipefail
```

- `set -e` — exit immediately on error.
- `set -u` — treat unset variables as errors.
- `set -o pipefail` — propagate failures through pipes.

## MISE task scripts (`.mise/tasks/**`)

MISE task scripts must include the `#MISE description` and `#USAGE` annotations directly below the shebang:

```bash
#!/usr/bin/env bash
#MISE description="One-line human-readable description"
#USAGE flag "-v --variant <variant>" env="VARIANT" help="FIPS variant (fips|non-fips)" default="fips" {
#  "fips"
#  "non-fips"
#}
set -euo pipefail
```

Use the shared library helpers from `.mise/lib/` rather than duplicating logic:

```bash
# Source shared helpers
# shellcheck source=.mise/lib/common.sh
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT}/.mise/lib/common.sh"
```

## Variable quoting and expansion

- **Always quote** variable expansions: `"${VAR}"`, not `$VAR`.
- Use `${VAR:-default}` for defaults; `${VAR:?error message}` to enforce required variables.
- Prefer `$(command)` over backticks for command substitution.

## Error messages

Write error messages to stderr and exit non-zero:

```bash
echo "ERROR: description of problem" >&2
exit 1
```

## Functions

- Use `snake_case` for function names.
- Keep functions under 40 lines; extract sub-functions for complex logic.
- Document functions with a brief comment above them.

## Temporary files

- Use `mktemp` for temporary files; clean up with a `trap`:

```bash
TMP=$(mktemp)
trap 'rm -f "${TMP}"' EXIT
```

## Shellcheck

- All scripts must pass `shellcheck`. Use inline `# shellcheck disable=SC...` only when unavoidable, with a comment explaining why.

## Secrets and credentials

- Never hardcode secrets or tokens in scripts.
- Use environment variables sourced from CI secrets or `.env` files (not committed).

> For MISE-specific task conventions (flags, variants, lib usage), see `.github/instructions/mise.instructions.md`.
