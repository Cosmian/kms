This mode offers high availability through redundancy and load-balancing.

The KMS servers are stateless, so they can simply be scaled horizontally by connecting them to the same database and fronting them with a load balancer.

![high-availability](./drawings/high-availability.drawio.svg)

### Configuring the load balancer

Since the KMS servers are stateless, any load-balancing strategy may be selected, such as a simple round-robin.

When the Cosmian KMS servers are configured to export an HTTPS port (as is the case when running inside a confidential VM):

- all the Cosmian KMS servers should expose the same server certificate on their HTTPS port
- and the load balancer should be configured as an SSL load balancer (HAProxy is a good example of a high-performance SSL load balancer)

### Selecting the database

The KMS server has support for PostgreSQL, Maria DB, and MySQL, as well as Redis, using the Redis-with-Findex configuration.

Redis with Findex offers the ability to use Redis as a database with application-level encryption: all data is encrypted (using AES 256 GCM) by the KMS servers before being sent to Redis. [Findex](https://github.com/Cosmian/findex/) is a Cosmian cryptographic algorithm used to build encrypted indexes on encrypted data, also stored in Redis. This allows the KMS to perform fast encrypted queries on encrypted data. Redis with Findex offers post-quantum resistance on encrypted data and encrypted indexes.

Redis-with-Findex is most useful when:

- KMS servers are run inside a confidential VM or an enclave. In this case, the secret used to encrypt the Redis data and indexes is protected by the VM or enclave and cannot be recovered at runtime by inspecting the KMS servers' memory.
- KMS servers are run by a trusted party but the Redis backend is managed by an untrusted third party.

Redis-with-Findex should be selected to [run the Cosmian KMS in the cloud or any other zero-trust environment](./zero_trust.md).

### Configuring the database

The database parameters may be configured either:

- using options on the command line that is used to start the KMS server
- via a TLS connection when the KMS server is started in [bootstrap](./bootstrap.md) mode. Database parameters may contain sensitive information, such as passwords: providing them on a TLS connection is more secure than specifying them in plain text on the command line.

Configuring the database via the [bootstrap](./bootstrap.md) TLS Connection should be selected to [run the Cosmian KMS in the cloud or any other zero-trust environment](./zero_trust.md).

#### Configuring the database via the bootstrap server

Configuring the database via the bootstrap TLS connection is described in the [bootstrap server documentation](bootstrap.md).

#### Configuring the database via the command line

For

- PostgreSQL, use `--database-type=postgresql`
- MySQL or MariaDB, use `--database-type=mysql`
- Redis (with-Findex), use `--database-type=redis-findex`

and specify the database URL with the `--database-url` option.

e.g.

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.9.1 \
  --database-type=postgresql \
  --database-url=postgres://kms_user:kms_password@pgsql-server:5432/kms

```

For Redis with Findex, the `--redis-master-password` and `--redis-findex-label` options must also be specified:

- the `redis-master-password` is the password from which keys will be derived (using Argon 2) to encrypt the Redis data and indexes.
- the `redis-findex-label` is a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the password/key.

Example:

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.9.1 \
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

### Using a certificate to authenticate to MySQL or Maria DB

Use a certificate to authenticate to MySQL or Maria DB with the `--mysql-user-cert-file` option on the command line. Specify the certificate file name and mount the file to docker.

Say the certificate is called `cert.p12` and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.9.1 \
  -v /certificate/cert.p12:/root/cosmian-kms/cert.p12 \
  --database-type=mysql \
  --database-url=mysql://mysql_server:3306/kms \
  --mysql-user-cert-file=cert.p12
```
