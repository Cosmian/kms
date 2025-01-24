This directory provides

- base Rust PKCS#11 bindings and traits that ccan be used to create a PKCS#11 client or a PPKCS#11 provider
- a PKCS#11 library to interface the KMS (the `provider` crate) from a PKCS#11 compliant application such as LUKS


[PKCS##11 documentation](https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf)

1. `sys` crate

    The sys crate is generated from the cryptoki headers files using `bindgen` and provides Linux and Windows bindings for
    the PKCS#11 API.

2. `module` crate

    The module crate exposes traits to create a PKCS#11 library. It is a modified fork of
    the `native_pkcs11` crate from Google. The `module` crate is used to build the `provider` PKCS#11 library.

3. `provider` crate

    The provider crate is a PKCS#11 library that interfaces the KMS. It provides a PKCS#11 library that can be used by
    applications such as LUKS to interface the KMS. The `provider` crate is built from the `module` crate.
