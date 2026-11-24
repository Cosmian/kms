## Bug Fixes

### Hardening

- `Debug` of `OpaqueObject` (KMIP 1.4 and 2.1) and of the KMIP 2.1 `RNGSeed` request prints the byte length instead of the opaque value or seed; wire format and KMIP 1.4 to 2.1 conversions are unchanged ([#1445](https://github.com/Cosmian/kms/issues/1445))

---

Closes #1445
