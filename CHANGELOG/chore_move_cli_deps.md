# chore/move_cli_deps

## Refactor

- Move CLI crates to `crate/clients/` subdirectory; flatten `kms/` subdirectory under actions and tests; rename `cosmian_kms_cli` → `cosmian_kms_cli_actions`

## Bug Fixes

- Fix `include_bytes!` relative paths in `cosmian_kms_cli_actions` and `ckms` test files after directory flattening (one extra `..` removed)
- Fix `cargo test -p cosmian_kms_cli` → `-p cosmian_kms_cli_actions` in `test_hsm_utimaco.sh`
- Fix `RUST_LOG` filter `cosmian_kms_cli` → `cosmian_kms_cli_actions` in `common.sh`
