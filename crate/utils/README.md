# Cosmian KMS utils

To understand what the `cosmian_kms_utils` is, let's first remind the followings:

- [abe_gpsw](https://github.com/Cosmian/abe_gpsw) offers functions to use ABE crypto-system such as key creation, encryption, etc. Such libairies exist for various crypto-systems.
- [kms_server](http://gitlab.cosmian.com/core/kms/-/tree/main/server) exposes a KMS relying on the KMIP standard. The KMS server offers a REST API to run crypto operations like key generation, encryption or decryption relying on libraries like `abe_gpsw` for instance. It stores the generated keys in a relational database. 

Therefore the `cosmian_kms_utils` offers upper functions to deal with the KMIP format for the crypto-systems designed by Cosmian. In deed, the KMS server waits for a query containing a Kmip-formatted data. This format is very exhautive and complexe but we just need a part of it to cover our needs. Then, in our library, we offer functions which specialized Kmip objects and operations for our crypto-systems, enabling the user to easily create queries to the KMS server without really be aware about the Kmip format.  

The `cosmian_kms_utils` is designed to be called in any end-user programs such as a CLI or a web backend. 

For now, the supported crypto-systems are: 

- [x] ABE
- [x] Cover Crypt
- [ ] To be continued...

## Compiling

You can build the lib as follow:

```
cargo build
```

## Testing

You can find a complete example of the library usage for ABE in the integration tests of the KMS server [here](http://gitlab.cosmian.com/core/cosmian_server/-/blob/develop/microservices/kms/kms_server/src/kmip/tests/abe_tests/integration_tests.rs).
