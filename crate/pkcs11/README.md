This directory provides

- a PKCS#11 library to interface the KMS (the `provider` crate) from a PKCS#11 compliant application such as LUKS
- a PKCS#11 wrapper to connect to an HSM (the `proteccio` crate)

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

4. `hsm` crate

    The `hsm` crate provides traits that should be implemented by wrapper loading HSM PKC#11 libraries.

5. `proteccio` crate

    The `proteccio` crate is a PKCS#11 wrapper that connects to the Proteccio HSM. It wraps the Proteccio HSM PKCS#11
    library and provides implementation of the `hsm` crate traits used by the KMS.

    The PKCS#11 library is built from the `provider` crate.

    The `module` crate is a modified fork of Google native_pkcs11 crate. See its readme for details.

    The `sys`crate is a direct clone of the crate with the same name from the `native_pkcs11` crate. Its license is Apache
    2.0.
