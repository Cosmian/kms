Cosmian KMS has a build option, called the FIPS mode, to only use cryptographic primitives that are compliant with the
[FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) norm distributed by the National Institute of Standards and
Technology (NIST).

When built using this mode, the KMS will produce a binary statically linked to an OpenSSL library (also in FIPS mode)
and will only contain compliant algorithms and primitives. The [Cryptographic algorithms page](./algorithms.md)
specifies the FIPS compliant algorithms.

Cosmian recommends using the OpensSSL 3.2 library on Red Hat Linux 9 or Ubuntu 22.04 to fully meet future NIST
compliance requirements.

Cosmian produces pre-built FIPS mode binaries of the server.

To build the FIPS mode version from source, use the `--features fips` flag when building the project:

```shell
cargo build --release --features fips
```
