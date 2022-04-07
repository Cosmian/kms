# KMS common

The `kms_commmon` library implements the kmip standard such as operations, objects, types, etc. 
It also implements the ttlv serialization format.

This kmip data are then used by the `kms_client` to query the `kms_server` and then by the `kms_server` to respond. 

For specific Cosmian crypto-systems, you can use the [rust_lib](http://gitlab.cosmian.com/core/cosmian_server/-/tree/develop/microservices/rust_lib) to generate kmip data with an abstraction level.
