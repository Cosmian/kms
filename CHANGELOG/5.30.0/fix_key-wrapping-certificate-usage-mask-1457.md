## Security

- Key wrapping with a Certificate enforces the `WrapKey` Cryptographic Usage Mask: the certificate's own mask, or, when it has none, the mask of the public key it links to with `PublicKeyLink` (same owner as the certificate); a certificate with neither is refused with `is not meant to wrap keys` (COSMIAN-2026-070, [#1457](https://github.com/Cosmian/kms/issues/1457)). In FIPS builds, a certificate imported without a usage mask must be linked to a public key carrying `WrapKey` or be given a `CryptographicUsageMask` with `WrapKey` to keep wrapping.

---

Closes #1457
