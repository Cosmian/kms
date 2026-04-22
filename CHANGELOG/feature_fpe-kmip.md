# feature/fpe-kmip

## Features

### FPE-FF1 via KMIP

- Add `ckms fpe keys create` command to create AES-FF1 encryption keys (non-FIPS only).
- Add `ckms fpe encrypt` and `ckms fpe decrypt` commands supporting text, integer, and float data types via `--type`; alphabet/metadata passed as additional data; optional tweak supported.

### Anonymization REST API (`POST /tokenize/{method}`)

- Add 8 stateless REST endpoints under `/tokenize/{method}` (non-FIPS only): `hash` (SHA2/SHA3/Argon2), `noise` (Gaussian/Laplace/Uniform on float/integer/date), `word-mask`, `word-tokenize`, `word-pattern-mask`, `aggregate-number`, `aggregate-date`, `scale-number`.
- Add matching `ckms tokenize` CLI commands for all 8 methods ([#869](https://github.com/Cosmian/kms/issues/869)).

### Web UI — Anonymize menu group

- Add **Anonymize** sidebar menu group with 8 form pages under `/ui/tokenize/*`: Hash, Add Noise, Word Mask, Word Tokenize, Pattern Mask, Aggregate Number, Aggregate Date, Scale Number ([#869](https://github.com/Cosmian/kms/issues/869)).
- Anonymize menu group hidden automatically in FIPS mode.

## Documentation

- Add `documentation/docs/use_cases/anonymization.md` — new documentation page covering all 8 `/tokenize` endpoints with JSON request/response examples, algorithm notes, and a comparison table against FPE (KMIP).
- Update `documentation/mkdocs.yml` — add **Anonymization** under the `Use cases` navigation section.


Closes [#869](https://github.com/Cosmian/kms/issues/869)
