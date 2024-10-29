# Database

## Selecting the database

The KMS server has support for PostgreSQL, Maria DB, and MySQL, as well as Redis, using the Redis-with-Findex configuration.

Redis with Findex offers the ability to use Redis as a database with application-level encryption: all data is encrypted (using AES 256 GCM) by the KMS servers before being sent to Redis. [Findex](https://github.com/Cosmian/findex/) is a Cosmian cryptographic algorithm used to build encrypted indexes on encrypted data, also stored in Redis. This allows the KMS to perform fast encrypted queries on encrypted data. Redis with Findex offers post-quantum resistance on encrypted data and encrypted indexes.

Redis-with-Findex is most useful when:

- KMS servers are run inside a confidential VM or an enclave. In this case, the secret used to encrypt the Redis data and indexes is protected by the VM or enclave and cannot be recovered at runtime by inspecting the KMS servers' memory.
- KMS servers are run by a trusted party but the Redis backend is managed by an untrusted third party.

Redis-with-Findex should be selected to [run the Cosmian KMS in the cloud or any other zero-trust environment](./zero_trust.md).

## Configuring the database

The database parameters may be configured either:

- using options on the command line that is used to start the KMS server

### Configuring the database via the command line

For

- PostgreSQL, use:

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.19.3 \
  --database-type=postgresql \
  --database-url=postgres://kms_user:kms_password@pgsql-server:5432/kms
```

- MySQL or MariaDB, use:

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.19.3 \
  --database-type=mysql \
  --database-url=mysql://kms_user:kms_password@mariadb:3306/kms
```

- Redis (with-Findex), use:

For Redis with Findex, the `--redis-master-password` and `--redis-findex-label` options must also be specified:

- the `redis-master-password` is the password from which keys will be derived (using Argon 2) to encrypt the Redis data and indexes.
- the `redis-findex-label` is a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the password/key.

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.19.3 \
  --database-type=redis-findex \
  --database-url=redis://localhost:6379 \
  --redis-master-password password \
  --redis-findex-label label
```

The `redis-master-password` is the password from which a key will be derived (using Argon 2) to encrypt the Redis data and indexes.

The `redis-findex-label` is a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the password/key.

!!!info "Setting up a PostgreSQL database"
    Before running the server, a dedicated database with a dedicated user should be created on the PostgreSQL instance. These sample instructions create a database called `kms` owned by a user `kms_user` with password `kms_password`:

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

## Using a certificate to authenticate to MySQL or Maria DB

Use a certificate to authenticate to MySQL or Maria DB with the `--mysql-user-cert-file` option on the command line. Specify the certificate file name and mount the file to docker.

Say the certificate is called `cert.p12` and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.19.3 \
  -v /certificate/cert.p12:/root/cosmian-kms/cert.p12 \
  --database-type=mysql \
  --database-url=mysql://mysql_server:3306/kms \
  --mysql-user-cert-file=cert.p12
```

## Database migration

Depending on the KMS database evolution, a migration can happen between 2 versions of the KMS server. It will be clearly written in the CHANGELOG.md. In that case, a generic database upgrade mechanism is run on startup.

At first, the table `context` is responsible for storing the version of the software run and the state of the database. The state can be one of the following:

- `ready`: the database is ready to be used
- `upgrading`: the database is being upgraded

On server startup:

- the server checks if the software version is greater than the last version run:

  - if no, it simply starts;
  - if yes:

    - it looks for all upgrades to apply in order from the last version run to this version;
    - if there is any to run, it sets an upgrading flag on the db state field in the context table;
    - it runs all the upgrades in order;
    - it sets the flag from upgrading to ready;

On every call to the database, a check is performed on the db state field to check if the database is upgrading. If yes, calls fail.

Upgrades resist to being interrupted in the middle and resumed from start if that happens.
