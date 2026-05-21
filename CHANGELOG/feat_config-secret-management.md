## Features

- Add secret management for KMS config files: `secrets_file` merge, `${VAR}` env-var interpolation, and phase-2 secret URI backends (`vault://`, `aws-ssm://`, `azure-kv://`) ([#932](https://github.com/Cosmian/kms/pull/932))
- Add `cosmian-kms://` secret URI backend: fetch `SecretData` or `OpaqueObject` from another Cosmian KMS server via KMIP 2.1; supports Bearer-token auth (`COSMIAN_KMS_TOKEN`) and optional TLS bypass (`COSMIAN_KMS_INSECURE_CERTS`) — no extra dependencies ([#932](https://github.com/Cosmian/kms/pull/932))

## Bug Fixes

- Fix `interpolate_env_vars` to skip TOML comment lines, preventing spurious "env var not set" errors when `pkg/kms.toml` contains illustrative `${VAR}` examples in comments ([#932](https://github.com/Cosmian/kms/pull/932))

## Build

- Update Nix vendor hashes for darwin CLI packages (`cli.vendor.static.darwin`, `cli.vendor.dynamic.darwin`) ([#932](https://github.com/Cosmian/kms/pull/932))
