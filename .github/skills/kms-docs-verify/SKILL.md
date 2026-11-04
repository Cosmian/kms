---
name: kms-docs-verify
description: 'Verify documentation claims against the code: ckms commands, flags, KMS_* env vars, config keys, versions, relative links, nav sync. Use after writing or editing documentation/** or README.md.'
---

# KMS Docs Verify

Docs drift is the most common hallucination here: sampled pages documented flags that do not exist, `ckms access grant` (real: `ckms access-rights`) and a socket port of 4696 (real: 5696). This skill turns the rules of `.github/instructions/docs.instructions.md` into checks. Every hit is a **candidate**: open the page, judge it in context (other tools' flags are legitimate), fix or justify.

## Scope

```bash
FILES=$(git diff --name-only origin/develop...HEAD -- documentation README.md | grep '\.md$')   # default: changed pages
# `/kms-docs-verify all` → FILES=$(find documentation/docs -name '*.md')
```

## 1. `ckms` subcommands exist

```bash
CLI=documentation/docs/kms_clients/cli/main_commands.md
grep -h -E '^[[:space:]]*(\$ )?ckms ' $FILES | awk '{for(i=1;i<=NF;i++) if($i=="ckms"){for(j=i+1;j<=NF;j++) if($j !~ /^-/){print $j; break}; break}}' \
  | grep -E '^[a-z][a-z0-9-]+$' | sort -u | while read -r s; do grep -qE "^## [0-9]+ ckms ${s}( |\$)" "$CLI" || echo "UNKNOWN ckms subcommand: $s"; done
```

For nested commands (`ckms access-rights grant`) also grep `^## [0-9.]+ ckms <a> <b>`.

## 2. Flags and env vars exist

```bash
REFS="documentation/docs/configuration/server_cli.md $CLI"
grep -ohE -- '(^|[ `])--[a-z][a-z0-9-]{3,}' $FILES | tr -d ' `' | sort -u | while read -r f; do grep -qF -- "$f" $REFS || echo "UNKNOWN flag: $f"; done
grep -ohE '\bKMS_[A-Z0-9_]{3,}\b' $FILES | sort -u | while read -r v; do grep -qF "$v" documentation/docs/configuration/server_cli.md || echo "UNKNOWN env var: $v"; done
```

Config keys: `grep -n '<key>' crate/server/kms_template.toml crate/server/src/config/command_line/*.rs`. A key documented but absent from both is wrong.

## 3. Versions

```bash
grep -m1 '^version' Cargo.toml
grep -nE '\b5\.[0-9]{1,2}\.[0-9]+\b' $FILES    # each hit must be the current version in a release.sh-bumped file, or a historical reference
```

## 4. Relative links and navigation

```bash
python3 - $FILES <<'EOF'
import re, sys, pathlib
for f in map(pathlib.Path, sys.argv[1:]):
    t = re.sub(r'```.*?```', '', f.read_text(errors='ignore'), flags=re.S)
    for m in re.finditer(r'\]\(([^)#\s]+\.md)(#[^)]*)?\)', t):
        if not m.group(1).startswith('http') and not (f.parent / m.group(1)).resolve().exists():
            print(f'BROKEN link {f}: {m.group(1)}')
EOF
```

New or removed page → both `documentation/docs/SUMMARY.md` and `documentation/nav.yml` list it (`docs.instructions.md`).

## 5. Generated files untouched

`git diff --name-only origin/develop...HEAD` must not list a file of the "Generated files" table in `docs.instructions.md` unless the matching `mise run docs:sync-*` task was run and its output committed.

## 6. Examples

Credentials are placeholders; no `curl -k`; non-FIPS-only features are labelled (see `docs.instructions.md`).

Report: `file:line — claim — evidence (file:line) — fixed | justified`. Done when every candidate is fixed or justified.
