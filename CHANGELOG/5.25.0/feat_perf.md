## Performance

### Server / XKS

- Make the unwrapped-key LRU cache size configurable via `--unwrapped-cache-max-size` CLI
  flag (env: `KMS_UNWRAPPED_CACHE_MAX_SIZE`, default: **1000**).
  Previously hardcoded to 100, this caused continuous LRU thrashing on XKS deployments
  with ≥ 100 active keys, forcing a full KEK unwrap on every cache eviction.
  ([#1020](https://github.com/Cosmian/kms/pull/1020))

### PostgreSQL

- Use `prepare_cached` for the `list-uids-for-tags` query, reducing per-request
  statement-preparation overhead on PostgreSQL backends.
  ([#1020](https://github.com/Cosmian/kms/pull/1020))

## Bug Fixes

### WASM

- Fix WASM build broken by `tracing-appender 0.2.5` (which introduced a `symlink` crate
  dependency incompatible with `wasm32-unknown-unknown`). Resolved by upgrading to
  `cosmian_logger 0.7.2`, which gates `tracing-appender` behind
  `cfg(not(target_arch = "wasm32"))`. ([#1020](https://github.com/Cosmian/kms/pull/1020))

---

Closes #1020
