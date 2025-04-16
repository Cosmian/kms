# Folder structure

- base Rust PKCS#11 bindings and traits that can be used to create a PKCS#11 client or a PKCS#11 provider
- a PKCS#11 library to interface the KMS (the `provider` crate) from a PKCS#11 compliant application such as LUKS

[PKCS##11 documentation](https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf)

1. `sys` crate

    The sys crate is generated from the cryptoki headers files using `bindgen` and provides Linux and Windows bindings for
    the PKCS#11 API.
