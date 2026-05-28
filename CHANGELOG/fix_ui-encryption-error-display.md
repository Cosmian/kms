# Changelog — develop

## Bug Fixes

- Fix HTML error message incorrectly displayed in UI when encryption payload is too large ([#966](https://github.com/Cosmian/kms/issues/966))
- Fix WASM panic "capacity overflow" when encrypting large files via UI — TTLV serializer now detects byte-like tags and accumulates bytes directly instead of allocating one TTLV element per byte ([#967](https://github.com/Cosmian/kms/pull/967))
- Add client-side file size validation (30 MB limit) with user-friendly warning in `FormUploadDragger` — accounts for 2× hex encoding in TTLV JSON
- Add server-side `JsonConfig` error handler for KMIP endpoint to return plain text instead of HTML

## Security

- Remove GPL-3.0-or-later `actix-governor` dependency; replaced with a direct `governor` (MIT/Apache-2.0) middleware to eliminate copyleft license contamination

## Build

- Add `cargo deny list -l crate > sbom/licenses.txt` pre-commit manual hook and automate generation in `release.yml` `prepare` job
- Remove `GPL-3.0-or-later` from `deny.toml` allow list

## Testing

- Add regression test for large byte payload TTLV serialization (1 MB round-trip via ByteString)

Closes #966
