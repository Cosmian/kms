Replicated mode offers high availability through redundancy and load-balancing.

The KMS servers are stateless, so they can simply be scaled horizontally by connecting them to the same database and fronting them with a load balancer.

### Selecting the database

The KMS server has support for PostgreSQL, Maria DB, and MySQL databases
For

- PostgreSQL, use `--database-type=postgresql`
- MySQL or MariaDB, use `--database-type=mysql`

e.g.

```sh
docker run --rm -p 9998:9998 \
  --name kms ghcr.io/cosmian/kms:4.4.3 \
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
  --name kms ghcr.io/cosmian/kms:4.4.3 \
  -v /certificate/cert.p12:/root/cosmian-kms/cert.p12 \
  --database-type=mysql \
  --database-url=mysql://mysql_server:3306/kms \
  --mysql-user-cert-file=cert.p12
```
