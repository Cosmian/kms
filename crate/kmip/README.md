# Cosmian KMIP

The `cosmian_kmip` library implements the kmip standard such as operations, objects, types, etc. 
It also implements the ttlv serialization format.

This kmip data are then used by the `cosmian_kms_client` to query the `cosmian_kms_server` and then by the `cosmian_kms_server` to respond. 

For specific Cosmian crypto-systems, you can use the [cosmian_kms_utils](http://gitlab.cosmian.com/core/kms/-/tree/main/utils) to generate kmip data with an abstraction level.
