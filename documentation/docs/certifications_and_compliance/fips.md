# FIPS 140-3

The Federal Information Processing Standard (FIPS) Publication 140-3, Security Requirements for
Cryptographic Modules, is a US government standard that specifies the security requirements for
cryptographic modules protecting sensitive information.

When compiled in FIPS mode, the Eviden KMS uses only cryptographic primitives that are compliant
with the standards of the National Institute of Standards and Technology (NIST) and uses
implementations of an NIST FIPS 140-3 compliant cryptographic module: the OpenSSL FIPS provider.

The OpenSSL FIPS provider is certified under

- [#4779](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4794)
  when used un Ubuntu 22.04
- [#4776](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4746)
  when used on Red Hat Enterprise Linux 9 (RHEL 9)

Eviden
produces [pre-built Debian based Linux packages](https://package.cosmian.com/kms/5.29.0/deb/)
and docker containers of the KMS (on gcr.io).

By default, the Eviden KMS is built with FIPS compliance enabled.
Alternatively, you can enable all cryptographic mechanisms by building from source, using the `--features non-fips` flag:

```shell
cargo build --release --features non-fips
```

## Rules enforced by the FIPS build

Beyond the choice of algorithms, the FIPS build enforces these rules:

- **FIPS provider only.** The server refuses to start when the non-validated OpenSSL `default` provider is active
  (for example through `OPENSSL_CONF`), and sets the `fips=yes` default property so that every algorithm is fetched
  from the FIPS provider.
- **AES-GCM IV generated inside the module** (NIST SP 800-38D §9.1, FIPS 140-3 IG C.H). `Encrypt`, `MAC` (GMAC) and
  AES-GCM key wrapping draw the 96-bit IV in the FIPS provider and refuse one chosen by the client; the same holds
  for the IV of an HSM encryption, so a PKCS#11 HSM must generate it. The tag is always the full 16 bytes.
- **At most 2^32 AES-GCM invocations per key** (SP 800-38D §8.3). The server counts them in the
  [`gcm_invocations` table](../configuration/database/tables.md#gcm_invocations) and refuses `Encrypt`, `MAC` and
  wrapping with that key once the cap is reached; rekey to continue.
- **Parameter bounds the FIPS provider does not check.** An HMAC is not generated with a key under 112 bits
  (SP 800-131A r2); a PBKDF2 `DeriveKey` needs a salt of at least 16 bytes, at least 1,000 iterations and a derived
  key of at least 14 bytes (SP 800-132).
- **No AES-XTS** and no RSA PKCS#1 v1.5 encryption or SHA-1 signature.
