# This directory provides

- base Rust PKCS#11 bindings and traits that can be used to create a PKCS#11 client or a [PKCS#11](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html) provider
- a PKCS#11 library to interface the KMS (the `provider` crate) from a PKCS#11 compliant application such as LUKS

[PKCS##11 documentation](https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf)

1. `module` crate

    The module crate exposes traits to create a PKCS#11 library. It is a modified fork of
    the `native_pkcs11` crate from Google. The `module` crate is used to build the `provider` PKCS#11 library.

2. `provider` crate

    The provider crate is a PKCS#11 library that interfaces the KMS. It provides a PKCS#11 library that can be used by
    applications such as LUKS to interface the KMS. The `provider` crate is built from the `module` crate.
