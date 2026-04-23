# feature/fpe-kmip

## Features

### FPE-FF1 via KMIP

- Add `ckms fpe keys create` command to create AES-FF1 encryption keys (non-FIPS only).
- Add `ckms fpe encrypt` and `ckms fpe decrypt` commands supporting text, integer, and float data types via `--type`; alphabet/metadata passed as additional data; optional tweak supported.
- Add `ckms fpe keys export`, `import`, `wrap`, `unwrap`, `revoke`, `destroy` commands, mirroring the symmetric key lifecycle ([#869](https://github.com/Cosmian/kms/issues/869)).

### Anonymization REST API (`POST /tokenize/{method}`)

- Add 8 stateless REST endpoints under `/tokenize/{method}` (non-FIPS only): `hash` (SHA2/SHA3/Argon2), `noise` (Gaussian/Laplace/Uniform on float/integer/date), `word-mask`, `word-tokenize`, `word-pattern-mask`, `aggregate-number`, `aggregate-date`, `scale-number`.
- Add matching `ckms tokenize` CLI commands for all 8 methods ([#869](https://github.com/Cosmian/kms/issues/869)).

### Web UI — FPE menu group

- Add **FPE** sidebar menu group with key lifecycle pages (`create`, `export`, `import`, `revoke`, `destroy`) and `encrypt` / `decrypt` pages under `/ui/fpe/*` ([#869](https://github.com/Cosmian/kms/issues/869)).
- Add WASM bindings `create_fpe_key_ttlv_request`, `encrypt_fpe_ttlv_request`, `decrypt_fpe_ttlv_request` for the FPE UI.
- FPE menu group hidden automatically in FIPS mode.

### Web UI — Anonymize menu group

- Add **Anonymize** sidebar menu group with 8 form pages under `/ui/tokenize/*`: Hash, Add Noise, Word Mask, Word Tokenize, Pattern Mask, Aggregate Number, Aggregate Date, Scale Number ([#869](https://github.com/Cosmian/kms/issues/869)).
- Anonymize menu group hidden automatically in FIPS mode.

## Testing

- Add FPE E2E Playwright tests: navigation smoke tests for all 7 FPE pages, key creation, encrypt/decrypt roundtrip with numeric alphabet.
- Add FPE routes to E2E sitemap tests.

## Security

- Remove stale RUSTSEC-2026-0097 advisory ignore from `deny.toml` — `rand 0.8.6` (already in `Cargo.lock`) is patched.

## Documentation

- Add `documentation/docs/use_cases/anonymization.md` — new documentation page covering all 8 `/tokenize` endpoints with JSON request/response examples, algorithm notes, and a comparison table against FPE (KMIP).
- Update `documentation/mkdocs.yml` — add **Anonymization** under the `Use cases` navigation section.

Closes [#869](https://github.com/Cosmian/kms/issues/869)
