Replicated mode offers high availability through redundancy and load-balancing.

The KMS servers are stateless, so they can simply be scaled horizontally by connecting them to the same database and fronting them with a load balancer.

### Selecting the database

The KMS server has support for PostgreSQL, Maria DB, MySQL databases, as well as Redis-with-Findex (see [below](#redis-with-findex)).

For

- PostgreSQL, use `--database-type=postgresql`
- MySQL or MariaDB, use `--database-type=mysql`
- Redis-with-Findex, use `--database-type=redis-findex`

e.g.

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.5.0 \
  --database-type=postgresql \
  --database-url=postgres://kms_user:kms_password@pgsql-server:5432/kms

```

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

### Using a certificate to authenticate to MySQL or Maria DB

Use a certificate to authenticate to MySQL or Maria DB with the `--mysql-user-cert-file` option. Specify the certificate file name and mount the file to docker.

Say the certificate is called `cert.p12` and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.5.0 \
  -v /certificate/cert.p12:/root/cosmian-kms/cert.p12 \
  --database-type=mysql \
  --database-url=mysql://mysql_server:3306/kms \
  --mysql-user-cert-file=cert.p12
```

### Redis with Findex

Redis-with-Findex makes the Cosmian KMS an excellent choice for a KMS in a zero-trust environment.

Redis with Findex offers the ability to use Redis as a database with application-level encryption: all data is encrypted by the KMS before being sent to Redis.

[Findex](https://github.com/Cosmian/findex/) is a Cosmian cryptographic algorithm used to build encrypted indexes on encrypted data. This allows the KMS to perform fast encrypted queries on encrypted data. Findex indexes are also stored in Redis.

Redis-with-Findex is most useful when the KMS is used inside a confidential VM or in an enclave. In this case, the secret used to encrypt the Redis data is protected by the VM or enclave and cannot be recovered at runtime by inspecting the machine memory.

As with the other databases, the Redis-with-Findex database mode is stateless and can be scaled horizontally.

Example:

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.5.0 \
  --database-type=redis-findex \
  --database-url=redis://localhost:6379 \
  --redis-master-password password \
  --redis-findex-label label
```

The `redis-master-password` is the password from which a key will be derived (using Argon 2) to encrypt the Redis data and indexes.

The `redis-findex-label` is a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the password/key.
