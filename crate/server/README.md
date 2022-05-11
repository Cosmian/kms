# Cosmian KMS Server

Note for the followings: the environment variables can be passed through a `.env` file at the location where you start the binary.

## Configure the authentication

The KMS server relies on an OAuth2 authentication provided by Auth0 to authenticate the user.

Example of how to run for test authentication:
```sh
$ KMS_DELEGATED_AUTHORITY_DOMAIN="dev-1mbsbmin.us.auth0.com" cargo run
```

## Configure the SGDB


The KMS relies on a database using various kinds of connector to store all the user secrets. The database is made up of two tables: `objects` et `read_access`.

### `objects` table

This table is designed to contain the kmip objects. A row is described as:

- `id` which is the index of the kmip object. This value is known by a user and used to retreive any stored objects
- `object` is the object itself
- `state` could be `PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed` or `Destroyed_Compromised`
- `owner` is the external id (email) of the user the object belongs to

### `read_access` table

Object's owner can allow any other user to perform actions on a given object.

This table describes those actions a specific user is allowed to perform onto the object:

- `id` which is the internal id of the kmip object
- `userid` which is the external id of the user: its email address
- `permissions` is a serialized JSON list containing one or more of the following flags: `Create`, `Get`, `Encrypt`, `Decrypt`, `Import`, `Revoke`, `Locate`, `Rekey`, `Destroy` defining the operation kinds the user is granted

The `userid` field will be used to check authorization by matching the email address contained in the authorization JWT.

By default, an sqlite database is used. This configuration is not suitable for production environment. Use one of the two followings instead.

### Running with PostgreSQL

```sh
KMS_POSTGRES_URL=postgresql://kms:kms@127.0.0.1:5432/kms cargo run
```

### Running with MySQL/MariaDB

```sh
KMS_MYSQL_URL=mysql://root:kms@localhost/kms cargo run
```

## Tests

`cargo make` setups PostgreSQL and MariaDB automatically to perform tests.

```console
cargo install cargo-make
cargo make rust-tests
```

## Dev

For development, you can use `--features=dev`. It will tell the server:
- to not verify the expiration of OAuth2 tokens
- to use HTTP connection

## Staging

For staging environment, you can use `--features=staging`. It will tell the server:
- to not verify the expiration of OAuth2 tokens
- to use HTTPS connection with unsecure SSL certificates (it will play anyway all the process to get a valid certificates and starts a HTTPS server)

## Run into a Secure Enclave (production environment)

For testing and development the KMS server accepts HTTP connection only. You just have to run it as previously specified. 

For production, the architecture and the security rely on secure enclaves. With no feature flag specified during the building process, the generated binary targets the production environment.

### HTTPS

The REST API server of the KMS server is launched into a secure enclave. It accepts HTTPS connection only.
To be sure that Cosmian can't decrypt the HTTPS flow (in a MITM scenario), the SSL certificate is generated inside the enclave. The private key is not exposed to the host.

### The database 

The database is located in another secure enclave using a MariaDB authenticated using a PEM certificate also generated inside the enclave and shared between the two servers. Here again Cosmian can't directly access the DB because Cosmian or any root user can't access the PEM certificate. 

Read more information about this database in the following section.

### Updating process

TODO: describe the process to update the kms and get back the previous SSL private key

### Resilience & Redundancy

TODO: describe how we procede to backup&restore the database in case of lost


## Timeout

The KMS server's binary can be configured to stop running 3 months after date of compilation.

This is done by using feature flag `demo_timeout`:

```console
cargo build --features demo_timeout
```

The demo version only uses HTTP. 

## EdgelessDB as database

[EdgelessDB](https://docs.edgeless.systems/edgelessdb/#/) is based on MariaDB, so the MySQL connector will be used for that.

Currently, the `sqlx` crate is not able to authentify using a key-file, as requested with EdgelessDB.

That's why two implementations are available in the KMS Server.

Follow this guide to use EdgelessDB in simulation mode (without SGX): https://docs.edgeless.systems/edgelessdb/#/getting-started/quickstart-simulation

### TL;DR

Data has been generated and is available in `data-ssl` and `data_ssl3` folder such
as:

- `data-ssl` is to use if you have a libssl<=2
- `data-ssl3` is to use if you have a libssl=3

To re-create key material, perform the following:

```console
openssl req -x509 -newkey rsa -nodes -days 3650 -subj '/CN=My CA' -keyout ca-key.pem -out ca-cert.pem
openssl req -newkey rsa -nodes -subj '/CN=rootuser' -keyout key.pem -out csr.pem
openssl x509 -req -days 3650 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -in csr.pem -out cert.pem

awk 1 ORS='\\n' ca-cert.pem
```

Then create a `manifest.json` file as requested in the guide.

An additional step is required to use properly the `mysql` crate that will connect using key-file.

```console
openssl pkcs12 -export -out cert.p12 -in cert.pem -inkey key.pem
```

If it prompts for export password, just hit `Enter`.

For simplified example, see: http://gitlab.cosmian.com/thibaud.genty/mysql_test

### EdgelessDB for Gitlab CI

An EdgelessDB is running on `gitlab-runner-1` so that CI can test MySQL connector against it.

The database is using key material located on the home folder of the `gitlab-runner` user.

#### Start Docker container

```console
sudo docker run --restart unless-stopped -d --name my-edb -p3306:3306 -p8080:8080 -e OE_SIMULATION=1 -t ghcr.io/edgelesssys/edgelessdb-sgx-1gb
```

Note: the EdgelessDB is currently running in simulation mode (not using SGX enclave).

#### Upload manifest to setup key material

```console
cd /home/gitlab-runner/data
curl -k --data-binary @manifest.json http://gitlab-runner-1.cosmian.com:8080/manifest
```

#### Test it works

```console
cd /home/gitlab-runner/
mysql -h127.0.0.1  -uroot -e "SHOW DATABASES"  --ssl-cert $(pwd)/data/cert.pem --ssl-key $(pwd)/data/key.pem
+--------------------+
| Database           |
+--------------------+
| $edgeless          |
| information_schema |
| kms                |
| mysql              |
+--------------------+
```