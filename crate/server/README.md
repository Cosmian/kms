# Cosmian KMS Server

## Features

The KMS server provides several features which can be enabled at compilation times. Enable/Disable these features will change the server configuration variables.

| Feature  | Description                                                                                                       | Staging | Prod 🔥 |
|----------|-------------------------------------------------------------------------------------------------------------------|---------|---------|
| insecure | Do not verify auth0 token expiration date     | ✅       |         |
| timeout  | The binary will stop (and won't be able to start again) after a period of time, starting from date of compilation |         |         |

**Caption**:
✅ Enabled
🔥 Default

### Development

For development, you can use `--no-default-features`. It will tell the server:

- to not use authentication
- to use HTTP connection

```console
cargo build --no-default-features
```

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

A server for development can be quickly run as follow (with sqlite):

```sh
cargo run --no-default-features -- --tmp-path /tmp
```

or:

```sh
export KMS_SQLITE_PATH=/tmp
cargo run --no-default-features
```

## Configure the authentication

The KMS server relies on an OAuth2 authentication provided by Auth0 to authenticate the user.

Example of how to run for test authentication:

```sh
KMS_JWT_ISSUER_URI="kms-cosmian.eu.auth0.com" cargo run
```

This authentication enables the KMS to deal with several users with the same database.
If there is no `KMS_JWT_ISSUER_URI` provided, the KMS disables the authentication. Only one user is allowed.
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

## In-depth understanding

### Database

The database is made up of two tables: `objects` et `read_access`.

#### `objects` table

This table is designed to contain the kmip objects. A row is described as:

- `id` which is the index of the kmip object. This value is known by a user and used to retrieve any stored objects
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
