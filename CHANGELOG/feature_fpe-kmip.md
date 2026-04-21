# feature/fpe-kmip

## Features

- Expose non-FIPS FPE-FF1 through KMIP `Encrypt`/`Decrypt`, add `ckms fpe` commands, and remove the legacy `/tokenize` route.
- Add anonymization REST endpoints `POST /tokenize/{method}` (8 methods: hash, noise, word-mask, word-tokenize, word-pattern-mask, aggregate-number, aggregate-date, scale-number) and matching `ckms tokenize` CLI commands; feature-gated behind `non-fips`.

## Web UI

- Add **Anonymize** menu group (non-FIPS only) with 8 form pages matching the `POST /tokenize/{method}` REST endpoints: Hash, Add Noise, Word Mask, Word Tokenize, Pattern Mask, Aggregate Number, Aggregate Date, Scale Number ([#869](https://github.com/Cosmian/kms/issues/869)).
- Anonymize menu group is hidden automatically in FIPS mode (same gating as PQC and MAC).
- Add Playwright E2E smoke tests for all 8 anonymization pages (`tokenize.spec.ts`).

Closes #869
