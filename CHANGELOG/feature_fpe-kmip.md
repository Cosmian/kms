# feature/fpe-kmip

## Features

- Expose non-FIPS FPE-FF1 through KMIP `Encrypt`/`Decrypt`, add `ckms fpe` commands, and remove the legacy `/tokenize` route.
- Add anonymization REST endpoints `POST /tokenize/{method}` (8 methods: hash, noise, word-mask, word-tokenize, word-pattern-mask, aggregate-number, aggregate-date, scale-number) and matching `ckms tokenize` CLI commands; feature-gated behind `non-fips`.
