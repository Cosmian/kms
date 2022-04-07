# KMS Server

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