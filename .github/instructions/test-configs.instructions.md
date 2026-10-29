---
name: 'Test Configuration Fixtures'
description: 'Never write partial KMS or Auth Verifier configs; reuse or add complete fixtures in the test_data submodule'
applyTo: '**/*.sh, .mise/**, crate/test_kms_server/**/*.rs, crate/**/tests/**/*.rs, crate/server/src/config/**/*.rs, test_data/configs/**, test_data/spire/config/**'
---

# Test configuration fixtures

A KMS server config (`kms.toml`), an Auth Verifier config (`auth_verifier.toml`) or a `ckms` client
config used by a test, script or smoke run is a **complete file in the `test_data` submodule**.
Never assemble one from fragments.

## What counts as partial (forbidden)

- Heredoc / `printf` / `echo` / `tee` writing a `*.toml` or `*.conf`, or `cat >>` appending a section
  to a config (`[audit]`, `[ocsp]`, `[auth_verifier]`, …).
- A Rust string literal, `format!`, or `toml::to_string` that builds TOML sections for a KMS /
  Auth Verifier / ckms config.
- `sed` / copy of a config that lives outside `test_data` (e.g. `authentication/server/auth_verifier.dev.toml`).
- New callers of `kms_write_config` (`.mise/lib/kms_server.sh`) or its "extra TOML lines" arguments.
- An `[auth_verifier]` section without its matching Auth Verifier fixture, or vice versa.

Legacy offenders exist. Do not add new ones; when you touch a file that has one, migrate it to a fixture in the same change.

## Where fixtures live

| Config | Location |
|---|---|
| KMS server | `test_data/configs/server/{auth,db,hsm,rbac,tls,test}/<name>.toml` |
| Auth Verifier | `test_data/configs/auth_verifier/<name>.toml` |
| `ckms` client | `test_data/configs/client/<name>.toml` |
| SPIRE harness (Docker-coupled) | `test_data/spire/config/` |
| Negative / malformed configs | same directories (precedent: `client/bad.toml`) |

## 1. Reuse first

```bash
ls test_data/configs/server/* test_data/configs/auth_verifier test_data/spire/config
grep -rln '\[auth_verifier\]' test_data          # fixtures that already wire an Auth Verifier
```

Load by path, never by copy-paste:

- Rust server tests: `test_kms_server::test_config_path("auth/auth_verifier.toml")` (`hsm_config_path` for `hsm/`).
- Rust `ckms` tests: `load_client_config("<template>.toml", ctx)` in `crate/clients/ckms/src/tests/utils/config.rs`.
- Shell: `"${REPO_ROOT}/test_data/configs/server/<area>/<name>.toml"`.

## 2. Create a fixture only when none fits

1. Start from a whole existing fixture (closest scenario); for Auth Verifier use
   `test_data/spire/config/auth_verifier.toml` or `test_data/configs/auth_verifier/test_auth_verifier.toml`.
   If you must import a config from another repo (e.g. `authentication/`), copy it whole into `test_data` first.
2. Complete for the scenario: every section the scenario exercises, on **both** sides of a pair.
   Auth Verifier needs `host_name`, `host_port`, `[tls_params]`, `[session_jwt_params]`, `[database_params]`.
   KMS needs `[http]`, `[db]` plus feature sections.
3. Auth Verifier ⇔ KMS pairing: KMS `[auth_verifier].auth_verifier_url` port == Auth Verifier `host_port`;
   set `auth_verifier_realm` whenever the Web UI login is exercised (`ui_login_enabled()` needs url **and** realm);
   `auth_verifier_accept_invalid_certs = true` only in test fixtures. Name the pair in both headers.
4. Header comment: purpose, bound port, which test/script loads it, paired fixture.
5. Unique port: `grep -rn 'port *= *<N>' test_data/configs test_data/spire/config` must return only your file.
6. Cert/key/DB paths: repo-root-relative paths to material already in `test_data` (`test_data/certificates`,
   `test_data/spire/certs`); run the process with cwd = repo root, or resolve to absolute in Rust.

## 3. Runtime variation — the only allowed one

Copy the **complete** fixture to a temp file and substitute scalar **values of keys that already exist**
(port, `sqlite_path`, tmp dirs, URL port). Never add, remove or reorder sections/keys.

```bash
# Fails when the key is absent (a bare sed would silently leave the fixture value in place).
set_toml_value() { # <file> <key> <already-quoted-value>
  grep -qE "^$2 *= " "$1" || { echo "ERROR: key '$2' missing in $1" >&2; return 1; }
  sed -E "s|^($2 *= *).*|\1$3|" "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}
cp "${REPO_ROOT}/test_data/configs/auth_verifier/<name>.toml" "${WORK_DIR}/auth_verifier.toml"
set_toml_value "${WORK_DIR}/auth_verifier.toml" host_port "${AUTH_PORT}"
```

Rust: parse the fixture into its typed struct, patch fields, write to `std::env::temp_dir()` — exactly like `load_client_config`.
A needed variation that is not a scalar value ⇒ it is a new fixture (section 2), not a patch.

## 4. Submodule workflow

`test_data` is a separate repo (`Cosmian/test_data`). Commit the fixture **inside `test_data/` first**
(never leave it untracked/uncommitted — CI checks out the pinned gitlink), then commit the gitlink bump in
the parent repo as its own commit in the same PR (sync rule 4.19 applies to the bump). Never force-push.

## 5. Verify the fixture with the real binary

```bash
# KMS fixture — unknown/misspelled keys make the server refuse to start
cargo run -p cosmian_kms_server --bin cosmian_kms -- --config test_data/configs/server/<area>/<name>.toml
# Auth Verifier fixture — from the repo root; build: cargo build --manifest-path authentication/Cargo.toml --bin auth_verifier
authentication/target/debug/auth_verifier test_data/configs/auth_verifier/<name>.toml &
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:<host_port>/.well-known/jwks.json   # expect 200
```

For a pair, start the Auth Verifier first, then the KMS, and exercise the path the scenario needs
(e.g. `POST /ui/login_as` for UI login). Features/flags as the surrounding task (`--features non-fips`).

> Rule 4.20 of `/kms-sync-rules`. Guided workflow and audit: `/kms-test-config`.
