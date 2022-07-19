# Cosmian KMS Server

## Features

The KMS server provides several features which can be enabled at compilation times. Enable/Disable these features will change the server configuration variables. 

| Feature  | Description                                                                                                       | Local | Staging | Prod 🔥 |
| -------- | ----------------------------------------------------------------------------------------------------------------- | ----- | ------- | ------ |
| auth     | Enable authentication. If disabled, multi-user is not supported                                                   | ✅     | ✅       |
| enclave  | Enable the ability to run inside an enclave                                                                       | ✅     | ✅       |
| https    | Enable https in the KMS in order to encrypt query between client and the KMS. If disabled, it uses http           | ✅     | ✅       |
| insecure | Do not verify auth0 token expiration date and https ssl is self-signed (to avoid to be banned by letsencrypt)     | ✅     |         |
| timeout  | The binary will stop (and won't be able to start again) after a period of time, starting from date of compilation |       |         |

__Caption__: 
✅ Enabled
🔥 Default

### Development

For development, you can use `--no-default-features`. It will tell the server:
- to not use authentication
- to use HTTP connection

### Staging feature

For staging environment, you can use `--features=staging --no-default-features`. It will tell the server:
- to not verify the expiration of OAuth2 tokens if `KMS_DELEGATED_AUTHORITY_DOMAIN` is set.
- to use HTTPS connection with unsecure SSL certificates (it will play anyway all the process to get a valid certificates and starts a HTTPS server)
- to be runnable only inside an enclave

### Timeout feature

The KMS server's binary can be configured to stop running 3 months after date of compilation.

This is done by using feature flag `timeout`:

```console
cargo build --features timeout
```

This feature can be combined with any other features.

## Configuration

The server configuration can be passed through the server using:
- Environment variables
- A dotenv `.env` file at the location where you start the binary 
- Command line arguments
  
The list of parameters, which depends on the compiled features, can be obtained by doing: 

```sh
cosmian_kms_server -h
```

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

The KMS relies on a database using various kinds of connector to store all the user secrets. 

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



## Production / Running inside a Secure Enclave 

> You can run the KMS on a non-sgx environment for production. In that case, the server will have the same behavior with a lower security level and with some routes disabled for the user.

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

The KMS database is located in the same secure enclave as multiple sqlcipher databases. Let's call *group* a set of user sharing the same database. 

As a consequence:
- These users share the same key to decrypt the database
- They can share KMS objects between each other

A single KMS instance can manage several groups, that is to say, several databases.

The key to decrypt a database is firstly generated by the KMS and returned to the user who has queried the creation of a new *group*. The KMS will not save this key. That is to say, *Cosmian* can't decrypt the database apart from the users queries.

To reply to the user queries, the KMS is expecting the user to send the key with the query. 

If the initialized KMS is manually restarted while running: 
- the KMS won't be able to read the databases. It will wait for the user to resend the key with its next query.

Because:
- the link between the KMS and the user is SSL-encrypted,
- the memory of the KMS is located inside the enclave,
- the ssl key material is located inside the enclave,

Then: *Cosmian* can't get the database keys at any points.

### Update

Now, we have described how to initialize the KMS secrets and use them to communication with the end-user or the database, we will describe how it deals with these secrets when there is an update. 

Let's remind that any modifications of the KMS source code, will generate a different binary. Therefore, the signature of that binary will be altered. As a consequence, any secrets stored in the KMS using `mr_enclave` won't be readable by the new version of the KMS. Besides, as said previously, *Cosmian* doesn't know these secrets and can't initialize the new version of the KMS with these unknown previous secrets. 

Let's describe how the migration of these various secrets happens.

To restart the KMS needs: 
- The SSL keys and the public certificate. *Cosmian* can't read them as the the new KMS. Therefore, the new KMS version will remove the previous keys and regenerate them. As a consequence, all new versions pushed by *Cosmian* could be transparently known by any KMS user.
- The sqlcipher keys. These secrets are located in the user side. Therefore, the keys will be read from the users queries.

### Resilience & Redundancy

This part cover the following scenario: we lost the KMS server and the KMS database. As a consequence, we have lost the user data and the secrets. We wan't to avoid that scenario to occur by having some sort of a database backup and secrets backup to be able to restore them if needed.

Let's describe how *Cosmian* deals with this concern:
- The HTTPS server can be lost. *Cosmian* will start a new one in another machine. The `mr_enclave` key will changed. As the update process, the new KMS version will remove the previous SSL keys and regenerate them.
- The sqlcipher-encrypted databases are stored in plain-text on the host. It means that, if the user provides thesqlcipher key, a new KMS in another secure enclave can reload the database. The database files are written to a network volume. The replication of this volume is managed by Azure with a high level of redundancy. 

## In-depth understanding

### Database

The database is made up of two tables: `objects` et `read_access`.

#### `objects` table

This table is designed to contain the kmip objects. A row is described as:

- `id` which is the index of the kmip object. This value is known by a user and used to retreive any stored objects
- `object` is the object itself
- `state` could be `PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed` or `Destroyed_Compromised`
- `owner` is the external id (email) of the user the object belongs to

#### `read_access` table

Object's owner can allow any other user to perform actions on a given object.

This table describes those actions a specific user is allowed to perform onto the object:

- `id` which is the internal id of the kmip object
- `userid` which is the external id of the user: its email address
- `permissions` is a serialized JSON list containing one or more of the following flags: `Create`, `Get`, `Encrypt`, `Decrypt`, `Import`, `Revoke`, `Locate`, `Rekey`, `Destroy` defining the operation kinds the user is granted

The `userid` field will be used to check authorization by matching the email address contained in the authorization JWT.
