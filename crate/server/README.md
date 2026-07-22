# Cosmian KMS Server

Main KMS application: Actix-web HTTP/KMIP server, routes KMIP operations, manages cryptographic keys and objects, enforces access control, persists to database backends (SQLite, PostgreSQL, MySQL, Redis-findex).

**Build modes:**

- `cargo build` — FIPS mode (default; no PQC, Covercrypt, or Redis-findex)
- `cargo build --features non-fips` — All algorithms enabled

See `src/routes/`, `src/core/operations/`, and `start_kms_server.rs` for entry points.

### Development Mode

For development, you can use `--features insecure` to disable authentication and HTTPS:

```bash
cargo build --features insecure
cargo run --features insecure --
```

This configuration:

- Disables authentication requirements
- Uses HTTP instead of HTTPS
- Suitable for local development only

### Non-FIPS Mode

Enable additional cryptographic algorithms:

```bash
cargo build --features non-fips
cargo run --features non-fips
```

### Timeout Feature

Create a time-limited binary (stops after 3 months):

```bash
cargo build --features timeout
```

## Configuration

The server configuration can be provided through multiple methods (in order of precedence):

- Environment variables
- A dotenv `.env` file at the location where you start the binary
- Command line arguments

The list of parameters, which depends on the compiled features, can be obtained by doing:

```sh
cosmian_kms_server -h
```

A server for development can be quickly run as follow (with sqlite):

```sh
cargo run
```

## Configure the authentication

The KMS server relies on an OAuth2 authentication provided by Auth0 to authenticate the user.

Example of how to run for test authentication:

```sh
KMS_JWT_AUTH_PROVIDER="https://demo-kms.eu.auth0.com" cargo run
```

This authentication enables the KMS to deal with several users with the same database.
If there is no `KMS_JWT_AUTH_PROVIDER` provided, the KMS disables the authentication. Only one user is allowed.
If so, `admin` will be the user id.

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
