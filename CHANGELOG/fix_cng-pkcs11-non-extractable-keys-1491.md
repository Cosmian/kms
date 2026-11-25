## Bug Fixes

### PKCS#11
- Stop returning `CKA_VALUE` of sensitive or non-extractable secret and private keys: `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_NEVER_EXTRACTABLE` and `CKA_ALWAYS_SENSITIVE` now mirror the KMS `Sensitive`, `Extractable`, `NeverExtractable` and `AlwaysSensitive` attributes (unset `Sensitive` is false, unset `Extractable` is true), and `C_GetAttributeValue` answers `CKR_ATTRIBUTE_SENSITIVE` with `ulValueLen = CK_UNAVAILABLE_INFORMATION` for a protected `CKA_VALUE` while still serving the other attributes. Public keys and `CKO_DATA` objects are unchanged. Applications that created secret keys without `CKA_SENSITIVE=true` and relied on the previously hard-coded `CKA_SENSITIVE=true`/`CKA_EXTRACTABLE=false` answers must set the flags when creating the key ([#1491](https://github.com/Cosmian/kms/issues/1491))

### CNG
- Derive the CNG key export policy from the KMS key attributes instead of always allowing export, failing closed: private-key export (`NCryptExportKey`) returns `NTE_PERM` unless the KMS key is explicitly `Extractable=true` and neither `Sensitive` nor `NeverExtractable`. Private keys created through the KSP are now created `Sensitive` and non-extractable in the KMS ([#1491](https://github.com/Cosmian/kms/issues/1491))

---

Closes #1491
