# Running the KMS inside an enclave

When running the KMS inside an enclave, data in the database should be protected using keys managed on the client side.

This is done by using a [user encrypted database](../single_server_mode.md#using-client-secret-encrypted-databases). The client secret is a symmetric key that is used to encrypt the database. While in use, the client secret is stored in the protected enclave memory and is never written to disk.

The `new-database`` command will initialize a new encrypted database and return the client secret. The client's secret must then be provided on every call to the KMS server.   

For the `ckms` client, the secret must be set in `kms_database_secret` property of the CLI `kms.json` configuration file.

```json
{
    "kms_server_url": "https://my-server:9998",
    "kms_database_secret": "eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0="
}
```


**Note**: passing the correct secret “auto-selects” the correct encrypted database: multiple encrypted databases can be used concurrently on the same KMS server.

### new-database

Initialize a new user encrypted database and return the secret (SQLCipher only).

This secret is only displayed once and is not stored anywhere on the server.
The secret must be set in the `kms_database_secret` property of the CLI `kms.json` configuration file to use the encrypted database.

Passing the correct secret "auto-selects" the correct encrypted database:
multiple encrypted databases can be used concurrently on the same KMS server.

Note: this action creates a new database: it will not return the secret
of the last created database and will not overwrite it.

**Usage:**
```
ckms new-database 
```



