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
#USAGE flag "-v --variant <variant>" env="VARIANT" help="FIPS variant" default="fips" {
#USAGE   choices "fips" "non-fips"
#USAGE }
set -euo pipefail
```

Use the shared library helpers from `.mise/lib/` rather than duplicating logic:

```bash
# Source shared helpers
# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
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

## Destructive commands

- `rm -rf` on a variable is `rm -rf -- "${VAR:?}"`; `set -u` does not catch an empty value or `/`. Same inside `trap` strings.
- Never `chmod 777` / `chmod -R 777`; use `0700`/`0755` and `chown`.

## TLS verification

- `curl -k` / `--insecure` is allowed only in test scripts under `.mise/**/test*` talking to a loopback server started by the script, with a comment saying so. Never in docs, workflows, packaging or deploy scripts: use `--cacert`.

## Waiting and ports

- Never `sleep N` to wait for a condition: use `wait_for_port` / `kms_wait_ready` (`.mise/lib/common.sh`). Never a literal port: `kms_pick_free_port` or `test_slots.sh`.

## Credentials

- Never commit a bearer token, JWT or API key, even for tests. Test-only passwords are obviously fake constants defined once at the top of the script.

> For MISE-specific task conventions (flags, variants, lib usage), see `.github/instructions/mise.instructions.md`.
