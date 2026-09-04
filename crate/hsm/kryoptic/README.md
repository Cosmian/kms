# Kryoptic PKCS#11 Loader

Kryoptic is a modern PKCS#11 v3.0 software token implementation from Red Hat's latchset project.

## Runtime Configuration

Running with Kryoptic requires two runtime configuration settings:

1. `KRYOPTIC_PKCS11_LIB`: Absolute or relative path to `libkryoptic_pkcs11.so` (Linux) or `libkryoptic_pkcs11.dylib` (macOS).
2. `KRYOPTIC_CONF`: Path to the Kryoptic configuration TOML file pointing to the token SQLite database.

## Testing

Kryoptic 1.5.2 pins `rusqlite = 0.38.0`, which conflicts with the workspace's `libsqlite3-sys` dependency graph. Therefore, its cdylib is built out-of-tree by the test harness.

To build the cdylib, provision a test token, and run the complete Kryoptic test suite:

```shell
mise run test:hsm:kryoptic
```
