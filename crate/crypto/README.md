# Cosmian KMS Crypto

To understand what the `cosmian_kms_crypto` is, let's first remind the followings:

- [kms_server](https://github.com/Cosmian/kms/tree/main/crate/server) exposes a KMS relying on the KMIP standard. The KMS server offers a REST API to run crypto operations like key generation, encryption or decryption relying on CoverCrypt. It stores the generated keys in a relational database.

Therefore the `cosmian_kms_crypto` offers upper functions to deal with the KMIP format for the crypto-systems designed by Cosmian. In deed, the KMS server waits for a query containing a Kmip-formatted data. This format is very exhautive and complexe but we just need a part of it to cover our needs. Then, in our library, we offer functions which specialized Kmip objects and operations for our crypto-systems, enabling the user to easily create queries to the KMS server without really be aware about the Kmip format.

The `cosmian_kms_crypto` is designed to be called in any end-user programs such as a CLI or a web backend.

For now, the supported crypto-systems are:

- [x] ABE
- [x] Cover Crypt

## Compiling

You can build the lib as follow:

```sh
cargo build
```

## Testing

You can find a complete example of the library usage in the integration tests of the KMS server [here](https://github.com/Cosmian/kms/tree/main/crate/server/src/tests).
