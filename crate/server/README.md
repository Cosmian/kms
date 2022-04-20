# Cosmian KMS Server

## Start with Authentication

Example of how to run for test authentication
```sh
$ KMS_DELEGATED_AUTHORITY_DOMAIN="dev-1mbsbmin.us.auth0.com" cargo run
```

## Running with PostgreSQL

```sh
KMS_POSTGRES_URL=postgresql://kms:kms@127.0.0.1:5432/kms cargo run
```

## Running with MySQL/MariaDB

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

For developping you can use `--features=dev` to tell the server to not verify the expiration of tokens.


The KMS relies on a database using various kinds of connector. The database is made up of two tables: `objects` et `read_access`.

## Database

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