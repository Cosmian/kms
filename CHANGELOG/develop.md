# Changelog – develop branch

## Features

### CPU Scaling & Flamegraph Benchmarks

- Added `--server-workers N` / `KMS_SERVER_WORKERS` configuration option to pin the number of
  actix-web OS threads at runtime, making multi-CPU benchmarks deterministic.
- Added `crate/test_kms_server/benches/http_throughput.rs`: a Criterion async HTTP throughput
  benchmark that sweeps worker counts {1, 2, 4, 8} for AES-256-GCM encrypt, RSA-2048 OAEP
  decrypt, and ECDSA P-256 sign, running 16 concurrent tasks per iteration via `iter_custom +
  join_all`.
- Added `.github/workflows/flamegraph.yml`: CI job that runs the throughput bench on an 8-core
  Ubuntu runner and generates flamegraph SVGs (via `cargo-flamegraph` / Linux `perf`) per worker
  count, uploading both Criterion HTML reports and SVGs as GitHub Actions artifacts.
- Added `[profile.bench]` to `Cargo.toml` with `strip = "none"`, `debug = 1`, `lto = "thin"` so
  `cargo flamegraph` produces readable flamegraphs with resolved function names across all crates.

- Added `.github/scripts/benchmarks/bench_run_flamegraph.sh`: runs the `http_throughput`
  Criterion bench across all worker counts and generates per-worker flamegraph SVGs via
  `cargo-flamegraph` / Linux `perf`, then writes an updated `cpu_scaling.md` documentation page.

### Performance
- `[profile.bench]`: override `opt-level` from `"z"` (size) to `3` (speed) — release profile
  was silently costing 15–40% throughput in all benchmarks
- `.cargo/config.toml`: add `target-cpu=native` for x86_64 to enable AES-NI/AVX2/SHA-NI
  in non-crypto glue code; add `bench-native` alias for local benchmark runs
- SQLite: add `PRAGMA cache_size=-65536` (64 MiB page cache), `PRAGMA mmap_size=268435456`
  (256 MiB mmap window), and `PRAGMA temp_store=MEMORY` to reduce syscall overhead for
  read-heavy concurrent workloads
- `.cargo/config.toml`: add `-C force-frame-pointers=yes` to x86_64 rustflags so
  `cargo-flamegraph` / `perf` uses `--call-graph fp` instead of `--call-graph dwarf`;
  reduces `perf.data` size 50–100× and eliminates the multi-minute `perf script` parsing step
- `bench_run_flamegraph.sh`: reduce default perf sampling frequency from 997 Hz to 500 Hz
  (`PERF_FREQ` env), add `--no-inline` (eliminates slow inline-frame expansion in perf script),
  and force `--call-graph fp` via `-c` custom perf command to prevent DWARF fallback that
  was producing multi-GB perf.data files and multi-minute parse times
