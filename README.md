# Cosmian KMS

It's the implementation of the **Key Management Services** provided by *Cosmian* .

It is broken down into severals binaries: 
- A server (`cosmian_kms_server`) which is the KMS itself
- A CLI (`cosmian_kms_cli`) to interact with this server

And also some libraries:
- `cosmian_kms_client` to query the server
- `cosmian_kms_utils` to create kmip requests for the crypto-systems designed by *Cosmian*
- `cosmian_kmip` which is an implementation of the kmip standard

Please refer to the README of the inner directories to have more information.
