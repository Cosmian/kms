## Features

### PKCS#11

- Expose KMS symmetric keys tagged `disk-encryption` as `CKO_DATA` token objects so VeraCrypt can
  discover and use them via the PKCS#11 provider without any custom plugin
- Add `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG` environment variable to override the discovery tag
  (default: `disk-encryption`); the second tag on each key becomes the label shown in the
  VeraCrypt GUI (e.g. `vol1`)

## Bug Fixes

### PKCS#11 / Client

- Fix `batch_get` not returning tags: add an explicit `GetAttributes(tags)` call alongside the
  existing `GetAttributes(all)` so that tag-based labels are correctly populated when the PKCS#11
  provider builds `CKO_DATA` object identifiers

## Documentation

- Update VeraCrypt integration guide: rename "Eviden KMS" → "Cosmian KMS" throughout
- Document `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG` environment variable
- Add warning that keys must not use `--sensitive` (must remain exportable)
- Clarify that `CKO_DATA` label corresponds to the second tag on the key

## Testing

- Add `.mise/tasks/test/veracrypt` MISE task for VeraCrypt PKCS#11 integration tests
- Add `.mise/scripts/test/test_veracrypt.sh` comprehensive integration test covering:
  PKCS#11 Rust unit tests, `pkcs11-tool` object discovery, VeraCrypt volume create/mount/dismount

---
