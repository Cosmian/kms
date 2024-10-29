# FIPS 140-3

The Federal Information Processing Standard (FIPS) Publication 140-3, Security Requirements for
Cryptographic Modules, is a US government standard that specifies the security requirements for
cryptographic modules protecting sensitive information.

When compiled in FIPS mode, the Cosmian KMS uses only cryptographic primitives that are compliant
with the standards of the National Institute of Standards and Technology (NIST) and uses
implementations of an NIST FIPS 140-3 compliant cryptographic module: the OpenSSL FIPS provider.

The OpenSSL FIPS provider is certified under

- [#4779](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4794)
  when used un Ubuntu 22.04
- [#4776](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4746)
  when used on Red Hat Enterprise Linux 9 (RHEL 9)

Cosmian
produces [pre-built Ubuntu 22.04 FIPS mode binaries](https://package.cosmian.com/kms/4.19.3/ubuntu-22.04/)
and docker containers of the KMS (on gcr.io).

Alternatively, you can build the FIPS mode version from source, using the `--features fips` flag:

```shell
cargo build --release --features fips
```
