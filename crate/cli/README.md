# Cosmian CLI

This command line interface (CLI) is used to manage the KMS server. In the current KMS repository, the `cosmian_kms_cli` is only used for testing purposes. The CLI is built using the `cosmian` crate on repository <https://github.com/Cosmian/cli>.

## Build

```sh
cargo build --bin cosmian
```

## Usage

[Usage](../../documentation/docs/index.md)

## Testing

```sh
cargo build --bin cosmian
docker compose up -d
cargo test -p cosmian
```
