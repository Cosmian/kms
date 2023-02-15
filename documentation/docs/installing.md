The KMS server is available as a Docker image on the [Cosmian public docker hub](https://hub.docker.com/r/cosmian/kms).

## Quick start

To start a Cosmian KMS server on `http://localhost:9998` that stores its data inside the container, simply run

```sh
docker run -p 9998:9998 --name kms cosmian/kms
```

Check the Cosmian KMS server version

```sh
curl http://localhost:9998/version
```

!!! info "List configuration options"
    The KMS server offers many configuration options which can be listed using

    ```sh
    docker run --rm cosmian/kms --help
    ```

    Most of these options can be passed on the command line or using the environment variables listed by the `--help` command.

## Single server mode

The single server mode uses an embedded SQLite database stored on a filesystem and therefore does not require access to an external database.

To run in single server mode, using the defaults, run the container as follows:

```sh
docker run -p 9998:9998 --name kms cosmian/kms
```

The KMS will be available on `http://localhost:9998` and data will be stored inside the container in `/root/cosmian-kms/sqlite-data`.

### Persisting data between restarts

To persist data between restarts, map the `/root/cosmian-kms/sqlite-data` path to a filesystem directory or a Docker volume, e.g. with a volume named `cosmian-kms`:

```sh
docker run --rm -p 9998:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  --name kms cosmian/kms
```

### Using encrypted databases

To start the KMS server with encrypted SQLite databases, pass the `--database-type=sqlite-enc` on start, e.g.

```sh
docker run --rm -p 9998:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  --name kms cosmian/kms \
  --database-type=sqlite-enc
```

!!! important "Important: encrypted databases must be created first"
    Before using an encrypted database, you must create it by calling the `POST /new_database` endpoint. The call will return a secret

    ```sh
    ➜ curl -X POST http://localhost:9998/new_database
    "eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0="%
    ```

    The secret is the value between the quotes `""`. This secret is only displayed **once** and is **not stored** anywhere on the server.

    :warning: Each call to `/new_database` will create a **new additional** database. It will not return the secret of the last created database and it will not overwrite the last created database.

Once an encrypted database is created, the secret must be passed every subsequent query to the KMS using a `KmsDatabaseSecret` HTTP header, e.g.

```sh
curl \
  -H "KmsDatabaseSecret: eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0=" \
  http://localhost:9998/objects/owned
```

Each encrypted database owns its encrypted file. Encrypted databases can be used concurrently on the same KMS server.

## Replicated mode

In replicated mode, the server can use PostgreSQL, Maria DB, or MySQL. Since the KMS servers are stateless, they can be scaled horizontally by connecting to the same database.

With the correct `database-type`, a `database-url` must also be provided

For

- PostgreSQL, use `--database-type=postgresql`
- MySQL or MariaDB, use `--database-type=mysql`

e.g.

```sh
docker run --rm -p 9998:9998 \
  --name kms cosmian/kms \
  --database-type=postgresql \
  --database-url=postgres://kms_user:kms_password@pgsql-server:5432/kms

```

!!!info "Setting up a PostgreSQL database"
    Before running the server a dedicated database with a dedicated user should be created on the PostgreSQL instance. These sample instructions create a database called `kms` owned by a user `kms_user` with password `kms_password`:

    1. Connect to psql under user `postgres`
    ```sh
    sudo -u postgres psql  # or `psql -U postgres`
    ```

    2. Create user `kms_user` with password `kms_password`
    ```psql
    create user kms_user with encrypted password 'kms_password';
    ```

    3. Create database `kms` under owner `kms_user`
    ```psql
    create database kms owner=kms_user;
    ```

### Using a certificate to authenticate to MySQL or Maria DB

Use a certificate to authenticate to MySQL or Maria DB with the `--mysql-user-cert-file` option. Specify the certificate file name and mount the file to docker.

Say the certificate is called `cert.p12` and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 9998:9998 \
  --name kms cosmian/kms \
  -v /certificate/cert.p12:/root/cosmian-kms/cert.p12 \
  --database-type=mysql \
  --database-url=mysql://mysql_server:3306/kms \
  --mysql-user-cert-file=cert.p12
```

## Enabling HTTPS

The server may be started using http/s by either installing certificates or using `certbot`.

### Installing certificates

The certificate (key and full chain) must be available in a PKCS#12 format.
Specify the certificate name and mount the file to docker.

Say the certificate is called `server.mydomain.com.p12`, is protected by the password `myPass`, and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 443:9998 \
  -v /certificate/server.mydomain.com.p12:/root/cosmian-kms/server.mydomain.com.p12 \
  --name kms cosmian/kms \
  --database-type=mysql \
  --database-url=mysql://mysql_server:3306/kms \
  --https-p12-file=server.mydomain.com.p12 \
  --https-p12-password=myPass
```

!!!info "Generate a PKCS#12 from PEM files"
    To generate a PKCS12 from PEM files, you can use `openssl`:

    ```sh
    openssl pkcs12 -export \
    -in server.mydomain.com.fullchain.pem \
    -inkey server.mydomain.com.privkey.pem \
    -out server.mydomain.com.p12
    ```

### Using the certificate bot

The Cosmian KMS server has support for a certificate bot that can automatically obtain and renew its certificates from Let's Encrypt using the acme protocol.

To enable the use of the certificate bot, enable the `--use-certbot` switch then specify

- the KMS hostname (Common Name in the certificate) using the `--certbot-hostname` option
- and the domain name owner email using the `--certbot-email` option, e.g.

The hostname must be a valid DNS A or AAAA record pointing to the IP address of this server as the Let's Encrypt server will attempt to connect to the server during the process.

By default, the certificates will be saved inside the container in the `/root/cosmian-kms/certbot-ssl` directory. This directory is adjustable with the `--certbot-ssl-path` option. To persist the generated certificates between restarts, this directory should be mapped to a host directory or persistent docker volume.

Example:

```sh
docker run --rm -p 443:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  -v cosmian-kms-certs:/root/cosmian-kms/certbot-ssl \
  --name kms cosmian/kms \
  --database-type=sqlite-enc \
  --use-certbot \
  --certbot-server-name server.mydomain.com \
  --certbot-email admin@mydomain.com
```

<!--

#### Note

On Linux, if PostgreSQL is running on the Docker host, the network should be mapped to the `host`.

## KMS CLI

The `cosmian/kms` Docker image also contains the KMS client `cosmian_kms_cli`. This client simplifies the communications with the server as described in the CLI documentation.

The KMS CLI can be used as follows:

```bash
docker run --network=host -it --entrypoint /bin/cosmian_kms_cli -v $PWD/conf:/conf -e KMS_CLI_CONF=/conf/kms.json cosmian/kms:latest cc init --policy /conf/policy.json
```

where `$PWD/conf` is a folder containing the following files:

- kms.json
- policy.json: The JSON file refers to [CoverCrypt](https://github.com/Cosmian/cover_crypt) which is a Cosmian encryption scheme which allows creating ciphertexts for a set of attributes and issuing user keys with access policies over these attributes.

As example:

kms.json:

```json
{ "kms_server_url": "http://127.0.0.1:9998", "kms_access_token": "" }
```

policy.json:

```json
{
  "policy":
    {
      "level":
        {
          "hierarchical": true,
          "attributes": ["confidential", "secret", "top-secret"],
        },
      "department":
        {
          "hierarchical": false,
          "attributes": ["finance", "marketing", "operations"],
        },
    },
  "max-rotations": 100,
}
``` -->
