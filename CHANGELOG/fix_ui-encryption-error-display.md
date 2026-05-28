# Changelog — develop

## Bug Fixes

- Fix HTML error message incorrectly displayed in UI when encryption payload is too large ([#966](https://github.com/Cosmian/kms/issues/966))
- Add client-side file size validation (48 MB limit) with user-friendly warning in `FormUploadDragger`
- Add server-side `JsonConfig` error handler for KMIP endpoint to return plain text instead of HTML

## Security

- Remove GPL-3.0-or-later `actix-governor` dependency; replaced with a direct `governor` (MIT/Apache-2.0) middleware to eliminate copyleft license contamination

## Build

- Add `cargo deny list -l crate > sbom/licenses.txt` pre-commit manual hook and automate generation in `release.yml` `prepare` job
- Remove `GPL-3.0-or-later` from `deny.toml` allow list

Closes #966
