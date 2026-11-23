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

Read [commands.rs](../../../../crate/clients/ckms/src/commands.rs) for top-level commands, then follow the relevant handler into [the clap actions](../../../../crate/clients/clap/src/actions/) for subcommands, flags, and feature gates. If the test binary is already built, use its `--help` to check which commands and flags that build exposes.

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
