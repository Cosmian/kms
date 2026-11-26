## Bug Fixes

### CLI

- Stop lower-casing the output of `ckms ... keys export --key-format base64`: Base64 is case sensitive, so the exported text could not be decoded back to the key bytes ([#1499](https://github.com/Cosmian/kms/issues/1499))

### WASM

- Stop lower-casing the Base64 key export returned by `parse_export_ttlv_response` (used by the Web UI key export) ([#1499](https://github.com/Cosmian/kms/issues/1499))

---

Closes #1499
