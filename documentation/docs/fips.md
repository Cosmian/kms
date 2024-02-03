Cosmian KMS has a build option, called the FIPS mode, to ensure the KMS only uses cryptographic primitives that are
compliant with the standards of the National Institute of Standards and Technology (NIST) and uses implementations of a
NIST [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) compliant cryptographic module.

When built using this mode, the KMS will be produced as a binary, statically linked to an OpenSSL library (also in FIPS
mode), that will only contain compliant algorithms and primitives. The [Cryptographic algorithms page](./algorithms.md)
specifies the list of NIST compliant algorithms available in this mode.

OpenSSL in FIPS mode, operated on certain operating systems, is part of the list of FIPS compliant cryptographic
modules; the full list can be
searched [here](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search).
Cosmian recommends using the OpensSSL 3.1 library on Red Hat Linux 9 or Ubuntu 22.04 to fully meet future NIST
compliance requirements.

Cosmian produces pre-built FIPS mode binaries and docker containers of the KMS.
Alternatively, to build the FIPS mode version from source, use the `--features fips` flag when building the project:

```shell
cargo build --release --features fips
```
