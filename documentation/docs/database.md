By default the server runs using a [SQLite](https://www.sqlite.org/) database, but it can be configured to use a choice
of databases: SQLite encrypted, [PostgreSQL](https://www.postgresql.org/), [Maria DB](https://mariadb.org/),
and [MySQL](https://www.mysql.com/), as well as [Redis](https://redis.io/), using
the [Redis-with-Findex](#redis-with-findex)
configuration.

<!-- TOC -->
  * [Selecting the database](#selecting-the-database)
      * [Redis with Findex](#redis-with-findex)
  * [Configuring the database](#configuring-the-database)
      * [SQLite](#sqlite)
      * [PostgreSQL](#postgresql)
      * [MySQL or MariaDB](#mysql-or-mariadb)
      * [Redis with Findex](#redis-with-findex-1)
      * [SQLite encrypted](#sqlite-encrypted)
  * [Clearing the database](#clearing-the-database)
  * [Database migration](#database-migration)
<!-- TOC -->

## Selecting the database

All databases but SQLite and SQLite encrypted can be used in a high-availability setup.

The **SQLite** database can serve high loads and millions of objects, and is very suitable
for scenarios that do not demand high availability. To use SQLIte encrypted, see
the [SQLite encrypted](#sqlite-encrypted) section.

#### Redis with Findex

**Redis with Findex** offers the ability to use Redis as a database with application-level encryption: all data is
encrypted (using AES 256 GCM) by the KMS servers before being sent to
Redis. [Findex](https://github.com/Cosmian/findex/) is a Cosmian cryptographic algorithm used to build encrypted indexes
on encrypted data, also stored in Redis. This allows the KMS to perform fast encrypted queries on encrypted data. Redis
with Findex offers post-quantum resistance on encrypted data and encrypted indexes.

**Redis-with-Findex** is most useful when:

- KMS servers are run inside a confidential VM or an enclave. In this case, the secret used to encrypt the Redis data
  and indexes, is protected by the VM or enclave and cannot be recovered at runtime by inspecting the KMS servers'
  memory.
- KMS servers are run by a trusted party but the Redis backend is managed by an untrusted third party.

Redis-with-Findex is the database selected
to [run the Cosmian KMS in the cloud or any other zero-trust environment](installation/marketplace_guide.md).

## Configuring the database

The database parameters may be configured either:

- the [TOML configuration file](./server_configuration_file.md)
- ot the [arguments passed to the server](./server_cli.md) on the command line.

The

#### SQLite

This is the default configuration. To use SQLite, no additional configuration is needed.

"postgresql", "mysql", "sqlite", "sqlite-enc", "redis-findex"

=== "kms.toml"

    ```toml
    [db]
    database_type = "sqlite"
    sqlite_path = "./sqlite-data"
    ```

=== "Command line arguments"

    ```sh
    --database-type=sqlite \
    --sqlite-path="./sqlite-data"
    ```

#### PostgreSQL

=== "kms.toml"

    ```toml
    [db]
    database-type="postgresql" 
    database-url="postgres://kms_user:kms_password@pgsql-server:5432/kms"
    ```

=== "Command line arguments"

    ```sh
    --database-type=postgresql \
    --database-url=postgres://kms_user:kms_password@pgsql-server:5432/kms
    ```

!!!info "Setting up a PostgreSQL database"
    Before running the server, a dedicated database with a dedicated user should be created on the PostgreSQL instance.
    These sample instructions create a database called `kms` owned by a user `kms_user` with password `kms_password`:

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

#### MySQL or MariaDB

=== "kms.toml"

    ```toml
    [db]
    database-type="mysql"
    database-url="mysql://kms_user:kms_password@mysql-server:3306/kms"
    ```

=== "Command line arguments"

    ```sh
    --database-type=mysql \
    --database-url=mysql://kms_user:kms_password@mariadb:3306/kms
    ```

!!!info "Using a certificate to authenticate to MySQL or Maria DB"

    Use a certificate to authenticate to MySQL or Maria DB with the `mysql-user-cert-file` option to
    specify the certificate file name.
    
    **Docker Example**: say the certificate is called `cert.p12` 
    and is in a directory called `/certificate` on the host disk.
    
    ```sh
    docker run --rm -p 9998:9998 \
      --name kms ghcr.io/cosmian/kms:latest \
      -v /certificate/cert.p12:/root/cosmian-kms/cert.p12 \
      --database-type=mysql \
      --database-url=mysql://mysql_server:3306/kms \
      --mysql-user-cert-file=cert.p12
    ```


#### Redis with Findex

For Redis with Findex, the `--redis-master-password` and `--redis-findex-label` options must also be specified:

- the `redis-master-password` is the password from which keys will be derived (using Argon 2) to encrypt the Redis data
  and indexes.
- the `redis-findex-label` is a public arbitrary label that can be changed to rotate the Findex ciphertexts without
  changing the password/key.


=== "kms.toml"

    ```toml
    [db]
    database-type="redis-findex"
    database-url="redis://localhost:6379"
    redis-master-password="password"
    redis-findex-label="label"
    ```

=== "Command line arguments"

    ```sh
    --database-type=redis-findex \
    --database-url=redis://localhost:6379 \
    --redis-master-password=password \
    --redis-findex-label=label
    ```

- Redis (with-Findex), use:




#### SQLite encrypted

=== "kms.toml"

    ```toml
    [db]
    database_type = "sqlite-enc"
    sqlite_path = "./sqlite-data"
    ```

=== "Command line arguments"

    ```sh
    --database-type=sqlite-enc \
    --sqlite-path="./sqlite-data"
    ```


It requires now to install the [Cosmian CLI](../cosmian_cli/index.md) and create a new encrypted database.

!!! important "Important: encrypted databases must be created first"

    Before using an encrypted database, you must create it by either using the [Cosmian CLI](../cosmian_cli/index.md)
    or calling the `POST /new_database` endpoint.
    The call will return a secret

    === "cosmian CLI"

        ```sh
        ➜ cosmian kms new-database

        eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0=
        ```

    === "curl"

        ```sh
        ➜ curl -X POST https://my-server:9998/new_database
        
        "eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0="%
        ```
        The secret is the value between the quotes `""`.

    Warning:

    - This secret is only displayed **once** and is **not stored** 
        anywhere on the server.
    - Each call to `new_database` will create a **new additional** database. 
      It will not return the secret of the last created database, 
      and it will not overwrite the last created database.

Once an encrypted database is created, the secret must be passed in every subsequent query to the
KMS server.
Passing the correct secret "auto-selects" the correct encrypted database: multiple encrypted
databases can be used concurrently on the same KMS server.

=== "cosmian CLI"

    The secret must be set in `database_secret` property of the CLI `cosmian.json` configuration file,
    and it will be used for all subsequent calls to the KMS server.

    ```toml
    [kms_config.http_config]
    server_url = "http://127.0.0.1:9990"
    access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6Ik...yaJbDDql3A"
    database_secret = "eyJncm91cF9pZCI6MTI5N...MWIwYjE5ZmNlN2U3In0="
    ```

=== "curl"

    The secret must be passed using a `DatabaseSecret` HTTP header, e.g.

    ```sh
    curl \
    -H "DatabaseSecret: eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0=" \
    http://localhost:9998/objects/owned
    ```

## Clearing the database

The KMS server can be configured to automatically clear the database on restart.

!!! warning "Warning: this operation is irreversible"
    The cleanup operation will delete all objects and keys stored in the database.

=== "kms.toml"

    ```toml
    [db]
    cleanup_on_startup = true
    ```
=== "Command line arguments"

    ```sh
    --cleanup-on-startup
    ```


## Database migration

Depending on the KMS database evolution, a migration can happen between 2 versions of the KMS server. It will be clearly
written in the CHANGELOG.md. In that case, a generic database upgrade mechanism is run on startup.

At first, the table `context` is responsible for storing the version of the software run and the state of the database.
The state can be one of the following:

- `ready`: the database is ready to be used
- `upgrading`: the database is being upgraded

On startup, the server checks if the software version is greater than the last version run:

- if no, it simply starts;
- if yes:

    - it looks for all upgrades to apply in order from the last version run to this version;
    - if there is any to run, it sets an upgrading flag on the db state field in the context table;
    - it runs all the upgrades in order;
    - it sets the flag from upgrading to ready;

On every call to the database, a check is performed on the db state field to check if the database is upgrading. If yes,
calls fail.

Upgrades resist to being interrupted in the middle and resumed from start if that happens.

