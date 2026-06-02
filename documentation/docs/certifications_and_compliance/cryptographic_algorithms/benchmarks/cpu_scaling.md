# CPU Scaling & Flamegraph Analysis

This page documents the multi-CPU scaling characteristics of the Cosmian KMS and explains how to
reproduce the results and generate flamegraphs yourself.

## Why this matters

A KMS deployed in production must handle concurrent cryptographic requests from many clients at the
same time. To justify a multi-core deployment (and to rule out serialisation bottlenecks such as
global mutexes or single-threaded database queues), we measure:

1. **Throughput scaling** – how req/s grows as the number of actix-web worker threads increases
   from 1 → 2 → 4 → 8.
2. **CPU hotspot profile** – a flamegraph confirming that the dominant cost is the cryptographic
   operation itself, not infrastructure overhead (routing, serialisation, database, locks).

## Methodology

### Server worker count

The KMS exposes a `--server-workers N` / `KMS_SERVER_WORKERS` configuration option (new in this
version) that pins the number of actix-web OS threads. Setting it explicitly makes the bench
deterministic regardless of the host's logical CPU count.

```toml
# kms.toml  – leave unset to default to one thread per logical CPU
# server_workers = 8
```

### Benchmark design

The `http_throughput` Criterion bench (located at
`crate/test_kms_server/benches/http_throughput.rs`) exercises three representative KMIP operations:

| Operation | Why chosen |
|-----------|-----------|
| AES-256-GCM encrypt | Lightweight, high-frequency – reveals OS-thread dispatch overhead |
| RSA-2048 OAEP decrypt | CPU-heavy asymmetric – shows scaling of the OpenSSL thread pool |
| ECDSA P-256 sign | CPU-heavy, short messages – reveals lock contention on key material |

For each worker count in `{1, 2, 4, 8}`:

1. A fresh in-process KMS is started with `server_workers = N` and SQLite on `/dev/shm` (tmpfs).
2. Cryptographic keys are pre-created (not timed).
3. **16 concurrent** `reqwest` HTTP tasks are dispatched per Criterion iteration via
   `iter_custom + join_all`, so the server is always saturated.
4. Criterion reports wall-clock throughput in **elements/s** (= concurrent requests per second).

### Flamegraph generation

Flamegraphs are recorded with
[`cargo-flamegraph`](https://github.com/flamegraph-rs/flamegraph) (Linux `perf` back-end).
They are generated in CI for the most CPU-intensive operation (ECDSA P-256 sign) at 1, 4, and 8
workers, and uploaded as GitHub Actions artifacts.

To reproduce locally (Linux only, requires `perf`):

```bash
# Install cargo-flamegraph once
cargo install flamegraph --locked

# Allow perf for unprivileged processes (revert after benchmarking)
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
echo 0   | sudo tee /proc/sys/kernel/kptr_restrict

# Build and profile – SVG lands in flamegraph.svg
CARGO_PROFILE_BENCH_DEBUG=true \
cargo flamegraph \
  --bench http_throughput \
  -p test_kms_server \
  --output target/flamegraphs/ecdsa_sign_w8.svg \
  -- \
  --bench \
  "ECDSA P-256 sign/8 workers" \
  --profile-time 15
```

## Running the throughput benchmark

```bash
# FIPS mode (default)
cargo bench --bench http_throughput -p test_kms_server

# Non-FIPS mode
cargo bench --bench http_throughput -p test_kms_server --features non-fips
```

Criterion writes an HTML report to `target/criterion/KMS CPU Scaling/`.

## Interpreting the results

### What near-linear scaling looks like

If the KMS scales well, throughput doubles when the worker count doubles:

| Workers | Expected throughput (relative) |
|---------|-------------------------------|
| 1       | 1× baseline                    |
| 2       | ~1.9×                          |
| 4       | ~3.6×                          |
| 8       | ~6–7× (NUMA / HT effects)      |

Sub-linear but monotonically increasing throughput is normal and expected:

- HTTP keep-alive and connection pooling overhead does not scale perfectly.
- SQLite WAL mode serialises writes but allows concurrent reads.
- OpenSSL's FIPS provider has per-context locking.

Flat or decreasing throughput would indicate a bottleneck worth investigating.

### Reading a flamegraph

A flamegraph shows where CPU time is spent, stacked by call depth.

- **Wide frames at the top** = the dominant cost; you want to see `openssl` / `ring` /
  `cosmian_kms_crypto` here.
- **Wide frames in the middle** = infrastructure cost; `actix-rt`, `tokio`, `serde_json`,
  `sqlx` are expected but should be narrow compared to crypto.
- **Wide frames at the bottom** = system calls; `syscall`, `epoll_wait` width grows with
  I/O wait (not CPU saturation).

If `std::sync::Mutex` or `parking_lot::Mutex` frames appear wide, that signals lock contention
and is a regression signal worth investigating.

## CI integration

The `flamegraph.yml` GitHub Actions workflow runs:

- **On demand** via `workflow_dispatch` (configurable worker counts and profile time).
- **Weekly** (Monday 03:00 UTC) against the default branch.
- **On pull requests** that touch `http_config.rs`, `start_kms_server.rs`, or the bench itself.

Artifacts uploaded per run:

| Artifact | Contents |
|----------|----------|
| `criterion-http-throughput-<run_id>` | Criterion HTML report with throughput charts |
| `flamegraph-svgs-<run_id>` | SVG flamegraphs per worker count |
| `http-throughput-output-<run_id>` | Raw bench output (bencher format) |
