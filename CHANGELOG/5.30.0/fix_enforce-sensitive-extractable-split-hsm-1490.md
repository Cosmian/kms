## Bug Fixes

### Hardening

- `CreateSplitKey` refuses a source key that is `Sensitive` or not extractable (`Extractable=false` or `NeverExtractable=true`) with the KMIP `Sensitive` / `Not_Extractable` error, instead of returning its plaintext in shares ([#1490](https://github.com/Cosmian/kms/issues/1490))
- Keys and key pairs created on an HSM without an explicit `Sensitive` attribute are now sensitive and non-extractable (`CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`) instead of extractable. Clients that need an extractable HSM key must send `Sensitive=false` (`ckms ... --sensitive false`) ([#1490](https://github.com/Cosmian/kms/issues/1490))

### CLI

- `--sensitive` of `ckms sym keys create`, `ckms rsa keys create` and `ckms ec keys create` accepts an optional value: `--sensitive` and `--sensitive true` keep the key non-exportable, `--sensitive false` sends `Sensitive=false` explicitly (opt-out of the HSM default)

## Documentation

- HSM, Luna and key ceremony pages describe the sensitive-by-default HSM keys and that sensitive keys cannot be split

---

Closes #1490
