# feature/fpe-kmip

## Features

### FPE-FF1 via KMIP

- Register `FPE_FF1 = 0x8880_0001` in `CryptographicAlgorithm` KMIP enum; vendor-extension slot, non-FIPS only.
- Add `ckms fpe keys create` command to create 256-bit AES-FF1 keys (automatically tagged `fpe-ff1`); key creation is blocked in FIPS mode with a clear `NotSupported` error.
- Add `ckms fpe encrypt` and `ckms fpe decrypt` commands that invoke KMIP `Encrypt`/`Decrypt` with `CryptographicParameters { cryptographic_algorithm: FPE_FF1 }`; support text, integer, and float data types via `--type`; alphabet/metadata passed as `authenticated_encryption_additional_data`; optional tweak passed as `i_v_counter_nonce`.
- Server-side: `encrypt_with_symmetric_key` and `decrypt_single_with_symmetric_key` dispatch to `encrypt_fpe`/`decrypt_fpe` when `CryptographicAlgorithm::FPE_FF1` is detected; FIPS builds return `NotSupported` immediately without reaching the crypto layer.
- Add `cosmian_kms_crypto` as a direct dependency of `cosmian_kms_server` (previously only reachable through `cosmian_kms_server_database`).
- FPE key creation defaults to 256 bits; any other length returns `InvalidRequest`.

### Anonymization REST API (`POST /tokenize/{method}`)

- Add 8 new stateless REST endpoints under `/tokenize/{method}` (feature-gated `non-fips`, payload limit 64 KB, auth middleware applied):
  - `POST /tokenize/hash` — irreversible base64 digest; algorithms: SHA2, SHA3, Argon2; optional base64-encoded salt.
  - `POST /tokenize/noise` — statistical noise for `float`, `integer`, or RFC 3339 `date`; distributions: Gaussian, Laplace, Uniform; parameterised by `(mean, std_dev)` or `(min_bound, max_bound)`.
  - `POST /tokenize/word-mask` — replace listed words on word boundaries with `XXXX`.
  - `POST /tokenize/word-tokenize` — replace listed words with consistent per-request random hex tokens.
  - `POST /tokenize/word-pattern-mask` — replace regex matches with a replacement string; pattern capped at 1 024 chars (ReDoS mitigation).
  - `POST /tokenize/aggregate-number` — round a float or integer to the nearest power of ten.
  - `POST /tokenize/aggregate-date` — truncate an RFC 3339 date to Second/Minute/Hour/Day/Month/Year precision; timezone preserved.
  - `POST /tokenize/scale-number` — z-score normalization followed by a `scale × z + translate` linear transform.
- All errors returned as HTTP 422 `{ "code": 422, "message": "..." }`.
- Add matching `ckms tokenize {hash,noise,word-mask,word-tokenize,word-pattern-mask,aggregate-number,aggregate-date,scale-number}` CLI commands ([#869](https://github.com/Cosmian/kms/issues/869)).

### Web UI — Anonymize menu group

- Add **Anonymize** sidebar menu group with 8 form pages under `/ui/tokenize/*` mapping to each `POST /tokenize/{method}` endpoint: Hash, Add Noise, Word Mask, Word Tokenize, Pattern Mask, Aggregate Number, Aggregate Date, Scale Number ([#869](https://github.com/Cosmian/kms/issues/869)).
- Anonymize menu group hidden automatically in FIPS mode (same gating as PQC and MAC).
- Sidebar icon normalised: Symmetric, RSA, Elliptic Curve, and PQC all now use `SafetyCertificateOutlined`; Secret Data uses `LockOutlined`; Anonymize uses `EyeInvisibleOutlined`.
- `AuthContext` split into `AuthContext.tsx` (provider), `AuthContextDef.tsx` (types/context object), and `useAuth.ts` (hook) to avoid circular imports.
- `resolveServerUrl` now checks `import.meta.env.VITE_DEV_MODE` in addition to `import.meta.env.DEV` for dev-server URL fallback.

## Testing

### CLI integration tests

- `crate/clients/clap/src/tests/fpe.rs` — FPE encrypt/decrypt round-trip tests for text, integer, and float data types through an in-process test server.
- `crate/clients/clap/src/tests/tokenize.rs` — integration tests for all 8 `ckms tokenize` commands against a running KMS instance.

### Playwright E2E

- `ui/tests/e2e/tokenize.spec.ts` — 214-line Playwright spec covering navigation smoke tests for all 8 pages plus functional checks: SHA2/SHA3 known digests, Gaussian/Uniform noise, word mask `XXXX` replacement, word tokenize hex consistency, pattern mask email replacement, aggregate-number `1234 → 1200`, aggregate-date truncation to Hour, scale-number finite result.
- Fix CORS: added `.wrap(Cors::permissive())` to `/tokenize` scope in `start_kms_server.rs` so the UI (Vite preview on port 5173) can reach the KMS (port 9998) cross-origin; consistent with Google CSE, MS DKE, and AWS XKS scopes.
- Fix SHA3 dropdown interaction in `tokenize.spec.ts`: replaced brittle direct click on `.ant-select-dropdown :text("SHA3")` with the robust `selectOption(page, "hash-method-select", "SHA3 (256-bit)")` helper.
- Fix invalid CSS selector in `tokenize.spec.ts` pattern mask test: added `data-testid="pattern-input"` to the pattern `<Input>` in `TokenizeWordPatternMask.tsx` and updated the test to use `[data-testid="pattern-input"]` (backslash in a CSS attribute selector is invalid).
- `ui/tests/e2e/routes.ts` — added 8 `TOKENIZE_ROUTES` entries and registered them under the `"Anonymize"` section of `ALL_ROUTES` for the navigation smoke test.
- `ui/tests/e2e/README.md` — added Anonymize section documenting all 8 test cases with sourced expected values.

## Documentation

- Add `documentation/docs/use_cases/anonymization.md` — new documentation page covering all 8 `/tokenize` endpoints with JSON request/response examples, algorithm notes, and a comparison table against FPE (KMIP).
- Update `documentation/mkdocs.yml` — add **Anonymization** under the `Use cases` navigation section.

## Build

- Version bump: `5.20.1` → `5.21.0` across all crates and the UI `package.json`.
- Update Nix vendor hashes (`server.vendor.{dynamic,static}.sha256`, `cli.vendor.*.sha256`, `ui.vendor.{fips,non-fips}.sha256`) following new dependencies.
- Update SBOM and CBOM artefacts for the 5.21.0 release.
- Remove legacy `.github/copilot-instructions.md` (superseded by `AGENTS.md`) and `.vscode/settings.json`.
- `AGENTS.md` improvements: table alignment, §16 post-task self-review checklist, Clippy `#[allow]` policy, technical examples sourcing rule, debugging residue comment convention, improved CHANGELOG location guidance.

Closes #869
