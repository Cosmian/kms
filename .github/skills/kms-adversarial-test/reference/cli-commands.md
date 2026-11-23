# CLI Commands Reference

## Contents

- [General pattern](#general-pattern)
- [Command tree](#command-tree)
- [Roundtrip examples](#roundtrip-examples)

---

## General pattern

```bash
cargo run -p ckms --features non-fips -- <subcommand> [args]

# FIPS-only (drop --features non-fips):
cargo run -p ckms -- <subcommand> [args]
```

---

## Command tree

| Command              | Subcommands                                                                                         | Feature gate |
| -------------------- | --------------------------------------------------------------------------------------------------- | ------------ |
| `ckms sym`           | `keys` (`create`, `create-split-key`, `join-split-key`, `re-key`, `export`, `import`, `destroy`, …), `encrypt`, `decrypt` | — |
| `ckms rsa`           | `keys` (`create`, `re-key`, `export`, `import`, `destroy`, …), `encrypt`, `decrypt`, `sign`, `sign-verify` | — |
| `ckms ec`            | `keys` (`create`, `re-key`, `export`, `import`, `destroy`, …), `sign`, `sign-verify`; `encrypt`, `decrypt` (`non-fips`) | — |
| `ckms certificates`  | `activate`, `certify`, `validate`, `encrypt`, `decrypt`, `export`, `import`, `revoke`, `destroy`, `generate-crl`, `generate-csr`, `set-rotation-policy` | — |
| `ckms mac`           | `compute`, `verify`                                                                                 | —            |
| `ckms hash`          | (hash operations)                                                                                   | —            |
| `ckms derive-key`    | (key derivation)                                                                                    | —            |
| `ckms locate`        | (object search with filters)                                                                        | —            |
| `ckms attributes`    | `get`, `set`, `modify`, `delete`                                                                    | —            |
| `ckms access-rights` | `grant`, `revoke`, `list`, `owned`, `obtained`, `crypto-officer`                                    | —            |
| `ckms audit`         | `export`, `verify`                                                                                  | —            |
| `ckms rng`           | `retrieve`, `seed`                                                                                  | —            |
| `ckms secret-data`   | `create`, `export`, `import`, `wrap`, `unwrap`, `activate`, `revoke`, `destroy`                     | —            |
| `ckms opaque-object` | `create`, `export`, `import`, `activate`, `revoke`, `destroy`                                       | —            |
| `ckms kv`            | `put`, `get`, `list`, `delete`                                                                      | —            |
| `ckms login`         | (authenticate and store token in `ckms.toml`)                                                       | —            |
| `ckms logout`        | (clear stored credentials from `ckms.toml`)                                                         | —            |
| `ckms aws`           | (BYOK export/import)                                                                                | —            |
| `ckms azure`         | (BYOK export/import)                                                                                | —            |
| `ckms google`        | `key-pairs`, `identities` (Google Workspace CSE)                                                    | —            |
| `ckms cng`           | `register`, `unregister`, `status`, `list-keys`, `verify`                                           | —            |
| `ckms pkcs11`        | `verify`, `capabilities`, `bench`                                                                   | —            |
| `ckms vault`         | `approle`                                                                                           | —            |
| `ckms server`        | `version`, `query`, `discover-versions`                                                             | —            |
| `ckms bench`         | (performance benchmarks)                                                                            | —            |
| `ckms cc`            | (Covercrypt operations)                                                                             | `non-fips`   |
| `ckms fpe`           | `keys` (`create`, `export`, `import`, `destroy`, …), `encrypt`, `decrypt`                           | `non-fips`   |
| `ckms pgp`           | `keys` (`create`, `export`, `import`, `destroy`, …), `export`, `import`, `encrypt`, `decrypt`, `sign`, `sign-verify` | `non-fips` |
| `ckms pqc`           | `keys` (`create`, `re-key`, `export`, `import`, `destroy`, …), `encrypt`, `decrypt`, `sign`, `sign-verify` | `non-fips` |
| `ckms tokenize`      | `hash`, `noise`, `word-mask`, `word-tokenize`, `word-pattern-mask`, `aggregate-number`, `aggregate-date`, `scale-number` | `non-fips` |

---

## Roundtrip examples

### FPE

```bash
cargo run -p ckms --features non-fips -- fpe keys create --tag my-fpe-key
# → note the key ID, e.g. 859362c9-eabc-4702-bf50-a33627042dfd

cargo run -p ckms --features non-fips -- fpe encrypt -k 859362c9-eabc-4702-bf50-a33627042dfd target/lol.md
cargo run -p ckms --features non-fips -- fpe decrypt -k 859362c9-eabc-4702-bf50-a33627042dfd target/lol.md.enc
diff target/lol.md target/lol.md.dec
```

### Symmetric (AES)

```bash
cargo run -p ckms --features non-fips -- sym keys create --algorithm aes --number-of-bits 256 --tag test-aes
cargo run -p ckms --features non-fips -- sym encrypt -k <key-id> test_data/plain.txt
cargo run -p ckms --features non-fips -- sym decrypt -k <key-id> test_data/plain.txt.enc
```

### Key lifecycle (Antisocial tour example)

```bash
KEY_ID=$(cargo run -p ckms --features non-fips -- sym keys create --algorithm aes --number-of-bits 256 2>&1 | grep -oP '[0-9a-f-]{36}')

# PreActive → encrypt should fail
cargo run -p ckms --features non-fips -- sym encrypt -k "$KEY_ID" test_data/plain.txt

# Destroy → export should fail
cargo run -p ckms --features non-fips -- sym keys destroy -k "$KEY_ID"
cargo run -p ckms --features non-fips -- sym keys export -k "$KEY_ID" /tmp/dead-key.json
```
