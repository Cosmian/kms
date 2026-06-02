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
- Added `documentation/docs/certifications_and_compliance/cryptographic_algorithms/benchmarks/cpu_scaling.md`:
  documentation page explaining the methodology, how to reproduce locally, and how to interpret
  scaling charts and flamegraphs.
