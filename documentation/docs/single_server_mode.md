The single server mode uses an embedded SQLite database stored on a filesystem and therefore does
not require access to an external database.

Although it does not provide high availability through redundancy, this configuration is suitable
for production and serving millions of cryptographic objects. The server will concurrently serve
requests on as many threads as available cores to the docker container.

This configuration also supports user encrypted databases, a secure way to store cryptographic
objects since database keys are provisioned on every request, and no database key is stored server
side. To offer a fully secure solution suitable for deployment in a zero-trust environment such as
the cloud, TLS must be enabled on the server, and the memory of the KMS server must also be
protected during operation by running the server inside an enclave. Ask Cosmian for details.

### Quick start

To run in single server mode, using the defaults, run the container as follows:

```sh
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.19.3
```

The KMS will be available on `http://localhost:9998`, and the server will store its data inside the
container in the `/root/cosmian-kms/sqlite-data` directory.

### Persisting data between restarts

To persist data between restarts, map the `/root/cosmian-kms/sqlite-data` path to a filesystem
directory or a Docker volume, e.g. with a volume named `cosmian-kms`:

```sh
docker run --rm -p 9998:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  --name kms ghcr.io/cosmian/kms:4.19.3
```

### Using client-side encrypted databases

To start the KMS server with a client-side encrypted SQLite databases, pass the
`--database-type=sqlite-enc` on start, e.g.

```sh
docker run --rm -p 9998:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  --name kms ghcr.io/cosmian/kms:4.19.3 \
  --database-type=sqlite-enc
```

!!! important "Important: encrypted databases must be created first"

    Before using an encrypted database, you must create it by calling the `POST /new_database` endpoint.
    The call will return a secret

    === "ckms"

        ```sh
        ckms new-database
        ```

    === "curl"

        ```sh
        ➜ curl -X POST https://my-server:9998/new_database
        "eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0="%
        ```
        The secret is the value between the quotes `""`.

    :warning: This secret is only displayed **once** and is **not stored** anywhere on the server.

    :warning: Each call to `new_database` will create a **new additional** database. It will not return the secret of the last created database, and it will not overwrite the last created database.

Once an encrypted database is created, the secret must be passed in every subsequent query to the
KMS server.
Passing the correct secret "auto-selects" the correct encrypted database: multiple encrypted
databases can be used concurrently on the same KMS server.

=== "ckms"

    The secret must be set in `kms_database_secret` property of the CLI `kms.json` configuration file.

    ```json
        {
            "kms_server_url": "https://my-server:9998",
            "kms_database_secret": "eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0="
        }
    ```

=== "curl"

    The secret must be passed using a `KmsDatabaseSecret` HTTP header, e.g.

    ```sh
        curl \
        -H "KmsDatabaseSecret: eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0=" \
        http://localhost:9998/objects/owned
    ```
