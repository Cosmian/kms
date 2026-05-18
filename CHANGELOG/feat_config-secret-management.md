## Features

- Add secret management for KMS config files: `secrets_file` merge, `${VAR}` env-var interpolation, and phase-2 secret URI backends (`vault://`, `aws-ssm://`, `azure-kv://`) ([#932](https://github.com/Cosmian/kms/pull/932))

## Bug Fixes

- Fix `interpolate_env_vars` to skip TOML comment lines, preventing spurious "env var not set" errors when `pkg/kms.toml` contains illustrative `${VAR}` examples in comments ([#932](https://github.com/Cosmian/kms/pull/932))

## Build

- Update Nix vendor hashes for darwin CLI packages (`cli.vendor.static.darwin`, `cli.vendor.dynamic.darwin`) ([#932](https://github.com/Cosmian/kms/pull/932))
