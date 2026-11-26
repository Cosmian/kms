## Bug Fixes

### Hardening

- `Debug` of `OpaqueObject` (KMIP 1.4 and 2.1) and of the KMIP 2.1 `RNGSeed` request prints the byte length instead of the opaque value or seed; wire format and KMIP 1.4 to 2.1 conversions are unchanged ([#1445](https://github.com/Cosmian/kms/issues/1445))

## Refactor

### KMIP

- Remove the unused KMIP 1.4 `TransparentSymmetricKey` and `Transparent{Dsa,Rsa,Dh,Ecdsa,Ecdh,Ecmqv}PrivateKey` structs; key material uses the `KeyMaterial` variants

---

Closes #1445
