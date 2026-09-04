# Kryoptic

The Kryoptic integration is supported on **Linux (x86_64, aarch64)** and **macOS**.

Kryoptic is a modern PKCS#11 v3.0 software token implementation from Red Hat's latchset project, providing support for OASIS Cryptoki v3.0 features including EdDSA, HKDF key derivation, and message-based authenticated encryption (AEAD).

## Runtime setup

To use Kryoptic with the KMS, the PKCS#11 shared library and a token configuration file must be provided.

1. Set the library path via the `KRYOPTIC_PKCS11_LIB` environment variable (defaults to `libkryoptic_pkcs11.so` on Linux or `libkryoptic_pkcs11.dylib` on macOS).
2. Set `KRYOPTIC_CONF` to point to a Kryoptic TOML configuration file defining the token slot and SQLite storage:

```toml
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/var/lib/kryoptic/token.sql"
```

## Testing and Out-of-tree Build

Kryoptic 1.5.2 pins `rusqlite = 0.38.0`, which conflicts with the workspace's `libsqlite3-sys` dependency graph. Therefore, the library is built out-of-tree for testing and verification.

To run the complete Kryoptic test suite:

```shell
mise run test:hsm:kryoptic
```

## KMS configuration

At least one slot and its corresponding PIN must be configured.

### Configuration via config file

When using the [TOML configuration file](../configuration/server_configuration_file.md#toml-configuration-file), enable Kryoptic HSM support by setting:

```toml
hsm_model = "kryoptic"
hsm_admin = ["admin"]
hsm_slot = [1]
hsm_password = ["12345678"]
```

### Configuration via command-line

```shell
--hsm-model "kryoptic" \
--hsm-admin "admin" \
--hsm-slot 1 --hsm-password "12345678"
```
