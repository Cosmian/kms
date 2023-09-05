
The Cosmian KMS is designed to run in the cloud or any zero-trust environment.

The design relies on 3 features:

 **Starting the server in bootstrap mode**: This initial phase allows the secure input of secret components, including the database encryption secret and the HTTPS certificate key, directly into the encrypted machine memory, through a secure connection
 
 **Running the KMS server in a confidential VM**: The KMS runs in a confidential VM which keeps memory encrypted at runtime using a key concealed in the CPU
 
 **Using an application-level encrypted Redis database:** Using the Redis-With-Findex database type, the data, and indexes are both encrypted by the main application using keys derived from the previously provisioned database encryption secret.
 

To start the database server in bootstrap mode, use the `--use-bootstrap-server` option:

```sh
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.6.0 \
  --use-bootstrap-server
```

See the [bootstrap mode documentation](./bootstrap.md) for more details.

To supply the database encryption secret, and Https certificate key, use:
 
 - either the `ckms` client CLI, using the `ckms bootstrap-start` command
 - or HTTPS POSTs to the bootstrap server, followed by a final POST on the `/start` endpoint to start the KMS server

 See [this documentation](./bootstrap.md#available-configurations) for more details.
