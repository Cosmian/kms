# Cosmian CLI

KMS or Findex server can be managed using the `cosmian` command line interface (CLI) or its graphical
client `cosmian_gui`.

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
