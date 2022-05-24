# Cosmian KMS Server

The server configuration can be passed through the server using:
- Environment variables
- A dotenv `.env` file at the location where you start the binary 
- Command line arguments
  
The list of parameters is:


| Variable                        | Parameter                       | Default | dev          | staging/production |
| ------------------------------- | ------------------------------- | ------- | ------------ | ------------------ |
| KMS_DAYS_THRESHOLD_BEFORE_RENEW | `--days-threshold-before-renew` | 15      | ⛔            | 🔥                  |
| KMS_DELEGATED_AUTHORITY_DOMAIN  | `--delegated-authority-domain`  |         | ✅            | ✅                  |
| KMS_DOMAIN_NAME                 | `--domain-name`                 |         | ⛔            | 🔥                  |
| KMS_EMAIL                       | `--email`                       |         | ⛔            | 🔥                  |
| KMS_HOSTNAME                    | `--hostname`                    | 0.0.0.0 | ✅            | ⛔                  |
| KMS_HTTP_ROOT_PATH              | `--http-root-path`              |         | ⛔            | 🔥                  |
| KMS_KEYS_PATH                   | `--keys-path`                   |         | ⛔            | 🔥                  |
| KMS_MANIFEST_PATH               | `--manifest-path`               |         | ✅ (SGX only) | ✅ (SGX only)       |
| KMS_MYSQL_URL                   | `--mysql-url`                   |         | ✅            | ✅                  |
| KMS_PORT                        | `--port`                        | 9998    | ✅            | ⛔                  |
| KMS_POSTGRES_URL                | `--postgres-url`                |         | ✅            | ✅                  |
| KMS_ROOT_DIR                    | `--root-dir`                    | /tmp    | ✅            | ✅                  |
| KMS_USER_CERT_PATH              | `--user-cert-path`              |         | ✅            | ✅                  |

__Caption__: 
⛔ Unused
✅ Available
🔥 Mandatory


## Configure the authentication

The KMS server relies on an OAuth2 authentication provided by Auth0 to authenticate the user.

Example of how to run for test authentication:
```sh
$ KMS_DELEGATED_AUTHORITY_DOMAIN="dev-1mbsbmin.us.auth0.com" cargo run
```

This authentication enables the KMS to deal with several users with the same database. 
If there is no `KMS_DELEGATED_AUTHORITY_DOMAIN` provided, the KMS disables the authentication. Only one user is allowed. 
If so, `admin` will be the user id.

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

### EdgelessDB as database

[EdgelessDB](https://docs.edgeless.systems/edgelessdb/#/) is based on MariaDB, so the MySQL connector will be used for that.

Currently, the `sqlx` crate is not able to authentify using a key-file, as requested with EdgelessDB.

That's why two implementations are available in the KMS Server.

Follow this guide to use EdgelessDB in simulation mode (without SGX): https://docs.edgeless.systems/edgelessdb/#/getting-started/quickstart-simulation

Use `KMS_USER_CERT_PATH` to give the client certificate to the KMS server. 

**TL;DR**

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

**EdgelessDB for Gitlab CI**

An EdgelessDB is running on `gitlab-runner-1` so that CI can test MySQL connector against it.

The database is using key material located on the home folder of the `gitlab-runner` user.

<u>Start Docker container</u>

```console
sudo docker run --restart unless-stopped -d --name my-edb -p3306:3306 -p8080:8080 -e OE_SIMULATION=1 -t ghcr.io/edgelesssys/edgelessdb-sgx-1gb
```

Note: the EdgelessDB is currently running in simulation mode (not using SGX enclave).

<u>Upload manifest to setup key material</u>

```console
cd /home/gitlab-runner/data
curl -k --data-binary @manifest.json http://gitlab-runner-1.cosmian.com:8080/manifest
```

<u>Test it works</u>

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

## Tests

`cargo make` setups PostgreSQL and MariaDB automatically to perform tests.

```console
cargo install cargo-make
cargo make rust-tests
```

## Dev

For development, you can use `--features=dev`. It will tell the server:
- to not verify the expiration of OAuth2 tokens if `KMS_DELEGATED_AUTHORITY_DOMAIN` is set.
- to use HTTP connection

## Staging

For staging environment, you can use `--features=staging`. It will tell the server:
- to not verify the expiration of OAuth2 tokens if `KMS_DELEGATED_AUTHORITY_DOMAIN` is set.
- to use HTTPS connection with unsecure SSL certificates (it will play anyway all the process to get a valid certificates and starts a HTTPS server)

## Timeout

The KMS server's binary can be configured to stop running 3 months after date of compilation.

This is done by using feature flag `demo_timeout`:

```console
cargo build --features demo_timeout
```

The demo version only uses HTTP. 

## Production / Running inside a Secure Enclave 

> You can run the KMS on a non-sgx environment for production. In that case, the server will have the same behavior with a lower security level and with some routes disabled for the user.

> You can run the KMS for testing or staging inside the enclave. You just have to run it as previously specified.

At *Cosmian*, for production, the architecture and the security rely on secure enclaves. With no feature flag specified during the building process, the generated binary targets the production environment.

![Production](./resources/production.drawio.svg)

To set up the enclave to run the kms server, please refer to the dedicated [Readme](../../enclave/server/README.md)

**Mandatory**: all KMS source codes are fully opensource.

### HTTPS

The REST API server of the KMS server is launched into a secure enclave. It accepts HTTPS connection only.
To be sure that *Cosmian* can't decrypt the HTTPS flow (in a MITM scenario), the SSL certificate is generated inside the enclave. The private key is not exposed to the host in plain-text. 

**How it works?**

The KMS will ask a certificate to *Let's Encrypt*. To do so, it starts a temporary HTTP server to play the HTTP-challenge. 
After getting the certificate, it stores them on disk: the private key is encrypted and only readable inside the enclave. 
Then, the real HTTPS server is started using this latter and the user can now query the KMS. 

If the initialized KMS is manually restarted while running: 
- if the private key can be read, the HTTPS server is restarted immediatelly
- otherwise, the certification process will raise an exception and the server won't start

At a point, the certificate will be renew automatically and the HTTPS server will be restarted immediatelly and automatically. 
If an error occurs during the certification process, the server stops. 

### The database 

The database is located in another secure enclave using a MariaDB authenticated using a PEM certificate also generated inside the enclave and shared between the two servers. Here again, *Cosmian* will is to not be able to directly access the DB because *Cosmian* or any root user can't access the PEM certificate. However, because of resilience matters (see below), the PEM certificate is stored encryted using the `mr_signer` key which is know from *Cosmian*.


**How it works?**

The KMS need a `.pem` client certificate to initiate a connection to the EdgelessDB. The first time, the KMS starts, it will generate that key, store it encrypted on the disk and use it to initialize the EdgelessDB. Therefore the connection could be normally established.

If the initialized KMS is manually restarted while running: 
- if the client certificate can be read, the KMS is restarted immediatelly
- otherwise, the KMS won't restart. 

### Update

#### KMS server 

Now, we have described how to initialize the KMS secrets and use them to communication with the end-user or the database, we will describe how it deals with these secrets when there is an update. 

Let's remind that any modifications of the KMS source code, will generate a different binary. Therefore, the signature of that binary will be altered. As a consequence, any secrets stored in the KMS using `mr_enclave` won't be readable by the new version of the KMS. Besides, as said previously, *Cosmian* doesn't know imost of these secrets and can't initialize the new version of the KMS with these unknown secrets. 

Let's describe how the migration of these various secrets happens.

To restart the KMS needs: 
- The SSL keys and the public certificate. *Cosmian* can't read them as the the new KMS. Therefore, the new KMS version will remove the previous keys and regenerate them. As a consequence, all new versions pushed by *Cosmian* could be transparently known by any KMS user.
- The Edgeless keys. These secrets are encrypted using `mr_signer` and then could be directly decrypted by a new KMS version. 

#### Database

The Edgeless DB could be updated. However if so, the database files couldn't be decrypt by the new version of the Edgeless because it depends on the `mr_enclave` which has changed. To prevent from that, when the database is firstly initialized by the KMS, the latter get a recovery key from the former. This key is encrypted inside the KMS enclave using `mr_signer`. Therefore, when a new Edgeless is setup, the recover key will be send to the new version to recover and read the DB files. 

The PEM certificate will also be sent by the KMS to initialize the DB.

### Resilience & Redundancy

This part cover the following scenario: we lost the KMS server or the KMS database. As a consequence, we have lost the user data and the secrets. We wan't to avoid that scenario to occur by having some sort of a database backup and secrets backup to be able to restore them if needed.

#### KMS server

The HTTPS server can be lost. *Cosmian* will start a new one in another machine. The `mr_enclave` key will changed. As the update process, the new KMS version will remove the previous SSL keys and regenerate them.

The Edgeless keys are stored on a shared volume, with a high level of redundancy. Therefore, we can mount these files to the new machine. Then the new enclave can decrypt and use them.

#### Database

The database filesystem is stored encrypted on the host. The replication of this volume is managed by Azure with a high level of redundancy. 

In the case the database enclave is destroyed, a new one will be created using the same shared volume. The KMS, using the previous recovery key, will initialize a new database being able to read the previous storage as if it was an update of the Edgeless.

### Going further: fully zero trust

Even if *Cosmian* wishes to offer a fully SaaS zero trust KMS, because of data resilience, *Cosmian* owns some keys which can be use to read the database. 
If a user doesn't want to trust *Cosmian* to not use these keys for bad purpose, it can choose one of these options:
- Use Key Wrapping 
- Give its own client Edgeless PEM certificate (not supported yet)

