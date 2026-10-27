---
name: kms-test-config
description: 'Reuse or create complete KMS / Auth Verifier / ckms config fixtures in the test_data submodule and audit for partial inline configs. Use when a test, script or smoke run needs a KMS or Auth Verifier config.'
---

# KMS Test Config

Normative rules: `.github/instructions/test-configs.instructions.md` (rule 4.20). This skill is the workflow.

## When to Use

- A test, mise task or smoke run needs a KMS server, Auth Verifier or ckms config.
- You are about to write `cat > x.toml <<EOF`, a Rust TOML string, or `sed` a config.
- Auditing a branch for partial configs (`/kms-test-config audit`).

## Step 1 — Find an existing fixture

```bash
ls test_data/configs/server/* test_data/configs/auth_verifier test_data/configs/client test_data/spire/config
grep -rln '\[auth_verifier\]' test_data
grep -rn 'port *= *[0-9]' test_data/configs | sort -t= -k2 -n     # used ports
```

Exact scenario fixture found → go to Step 4. Close fixture found → Step 2 (copy whole, edit).

## Step 2 — Create the fixture(s)

1. Copy the closest complete fixture to its directory (see instruction file table); never write it from scratch or from a fragment.
2. Make it complete for the scenario; for Auth Verifier scenarios create **both** the Auth Verifier and the KMS fixture and make ports/realm consistent.
3. Add the header comment (purpose, port, loader, pair). Pick a free port (Step 1 grep).

## Step 3 — Commit in the submodule

```bash
git -C test_data checkout -b <branch>          # branch name = parent branch name
git -C test_data add configs/ spire/config/
git -C test_data commit -m "test: add <name> KMS/auth-verifier config"
git add test_data                              # gitlink bump, separate parent commit (rule 4.19)
```

Never force-push. Do not push `test_data` without the user's go-ahead.

## Step 4 — Use it

- Rust: `test_config_path(..)` / `hsm_config_path(..)` / `load_client_config(..)`.
- Shell: copy fixture to a temp dir, `set_toml_value` for ports/paths (snippet in the instruction file). No heredocs, no `cat >>`.

## Step 5 — Verify with the real binary

Run the commands of instruction section 5. A fixture is done only when the server / Auth Verifier starts from it and the scenario's request succeeds.

## Audit mode (`/kms-test-config audit [path]`)

```bash
# shell writers (exclude the legacy helper definition itself)
grep -rnE '(cat|tee|printf|echo)[^|]*>>? *"?[^ ]*\.(toml|conf)|kms_write_config' .mise .github/scripts | grep -v '^.mise/lib/kms_server.sh'
# Rust inline TOML
grep -rnE '"\[(http|db|auth_verifier|tls|ui_config|socket_server)\]|^\s*\[(http|db|auth_verifier)\]\s*$' crate --include=*.rs
# configs sed-patched from outside test_data
grep -rn 'auth_verifier.dev.toml' .mise .github/scripts
```

Report each hit as `file:line — legacy | introduced by this diff`. Only hits introduced by the current diff (`git diff` added lines) block; legacy hits are listed, not migrated, unless the file is being touched. Known legacy: `.mise/scripts/test/test_ui_auth.sh`, 21 `kms_write_config` callers, `crate/server/src/config/command_line/clap_config.rs` loader-precedence tests, `crate/server/src/main.rs` inline TOML, `crate/clients/ckms/src/tests/login_tests.rs`.
